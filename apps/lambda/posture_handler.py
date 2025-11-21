# posture_handler.py
import os
import json
import logging
import time
from datetime import datetime, timezone, timedelta

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").lower()

AWS_CONFIG = Config(connect_timeout=2, read_timeout=3, retries={"max_attempts": 2})
DDB = boto3.resource("dynamodb")
PROFILES_TABLE_NAME = os.environ.get("PROFILES_TABLE_NAME")
PROFILES_TABLE = DDB.Table(PROFILES_TABLE_NAME) if PROFILES_TABLE_NAME else None


REGION = os.environ.get("AWS_REGION", "us-east-1")
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
PORTAL_BUCKET_NAME = os.environ.get("PORTAL_BUCKET_NAME")
PROFILES_TABLE_NAME = os.environ.get("PROFILES_TABLE_NAME")
WAF_WEBACL_ARN = os.environ.get("WAF_WEBACL_ARN")
WAF_SAMPLE_RULE = os.environ.get("WAF_SAMPLE_RULE", "Default_Action")

cloudtrail = boto3.client("cloudtrail", config=AWS_CONFIG)
guardduty = boto3.client("guardduty", config=AWS_CONFIG)
securityhub = boto3.client("securityhub", region_name=os.environ.get("SECURITY_HUB_REGION", REGION), config=AWS_CONFIG)
config_svc = boto3.client("config", config=AWS_CONFIG)
waf = boto3.client("wafv2", config=AWS_CONFIG)
s3 = boto3.client("s3", config=AWS_CONFIG)
dynamodb = boto3.client("dynamodb", config=AWS_CONFIG)


# ---------- helpers ----------

def _resp(status, body):
    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
        "Access-Control-Allow-Credentials": "true",
    }
    return {"statusCode": status, "headers": headers, "body": json.dumps(body)}


def _claims(event):
    jwt = event.get("requestContext", {}).get("authorizer", {}).get("jwt", {})
    return jwt.get("claims") or {}


def _is_admin(claims):
    sub = claims.get("sub")
    role = _get_profile_role(sub)
    logger.info("Auth check for sub=%s profile_role=%s", sub, role)
    return role == "admin"


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------- individual checks ----------

def check_cloudtrail():
    try:
        resp = cloudtrail.describe_trails()
        trails = resp.get("trailList", [])
        enabled_trails = [t for t in trails if t.get("HomeRegion")]
        multi_region = any(t.get("IsMultiRegionTrail") for t in enabled_trails)
        return {
            "ok": bool(enabled_trails),
            "multi_region": bool(multi_region),
            "details": {"trail_count": len(trails)},
        }
    except ClientError as e:
        logger.error("CloudTrail error: %s", e, exc_info=True)
        return {"ok": False, "error": "cloudtrail_error"}


def check_guardduty():
    try:
        detectors = guardduty.list_detectors().get("DetectorIds", [])
        if not detectors:
            return {"ok": False, "enabled": False}
        # sample first detector
        det = guardduty.get_detector(DetectorId=detectors[0])
        enabled = det.get("Status") == "ENABLED"
        return {"ok": enabled, "enabled": enabled}
    except ClientError as e:
        logger.error("GuardDuty error: %s", e, exc_info=True)
        return {"ok": False, "error": "guardduty_error"}


def check_security_hub():
    try:
        hub = securityhub.describe_hub()
        enabled = True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("InvalidAccessException", "ResourceNotFoundException"):
            return {"ok": False, "enabled": False}
        logger.error("Security Hub describe_hub error: %s", e, exc_info=True)
        return {"ok": False, "error": "securityhub_error"}

    # very small sampled count, just for visualisation
    severities = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    try:
        resp = securityhub.get_findings(MaxResults=50)
        for f in resp.get("Findings", []):
            sev = (f.get("Severity", {}).get("Label") or "").upper()
            if sev in severities:
                severities[sev] += 1
    except ClientError as e:
        logger.warning("Security Hub get_findings error: %s", e)

    return {"ok": enabled, "enabled": enabled, "severity_counts": severities}


def check_config():
    try:
        resp = config_svc.get_compliance_summary_by_config_rule()
        summary = resp.get("ComplianceSummary", {})
        return {
            "ok": True,
            "compliant": summary.get("CompliantResourceCount", {}).get("CappedCount", 0),
            "non_compliant": summary.get("NonCompliantResourceCount", {}).get("CappedCount", 0),
        }
    except ClientError as e:
        logger.error("Config error: %s", e, exc_info=True)
        return {"ok": False, "error": "config_error"}


def check_waf():
    if not WAF_WEBACL_ARN:
        return {"ok": False, "error": "no_webacl_arn"}

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=24)
    try:
        resp = waf.get_sampled_requests(
            WebAclArn=WAF_WEBACL_ARN,
            RuleMetricName=WAF_SAMPLE_RULE,
            Scope="CLOUDFRONT",
            TimeWindow={"StartTime": start, "EndTime": end},
            MaxItems=1000,
        )
        sampled = resp.get("SampledRequests", [])
        blocked = sum(1 for r in sampled if r.get("Action") == "BLOCK")
        allowed = sum(1 for r in sampled if r.get("Action") == "ALLOW")
        return {"ok": True, "blocked_24h_sample": blocked, "allowed_24h_sample": allowed}
    except ClientError as e:
        logger.error("WAF error: %s", e, exc_info=True)
        return {"ok": False, "error": "waf_error"}


def check_encryption():
    bucket = {"sse": False, "public_blocked": False}
    table = {"cmk_encrypted": False}

    # S3 bucket SSE + block public
    if PORTAL_BUCKET_NAME:
        try:
            enc = s3.get_bucket_encryption(Bucket=PORTAL_BUCKET_NAME)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            bucket["sse"] = bool(rules)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code != "ServerSideEncryptionConfigurationNotFoundError":
                logger.error("S3 encryption error: %s", e, exc_info=True)

        try:
            pab = s3.get_public_access_block(Bucket=PORTAL_BUCKET_NAME)
            cfg = pab.get("PublicAccessBlockConfiguration", {})
            bucket["public_blocked"] = all(cfg.get(k, False) for k in (
                "BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"
            ))
        except ClientError as e:
            logger.error("S3 PAB error: %s", e, exc_info=True)

    # DynamoDB CMK encryption
    if PROFILES_TABLE_NAME:
        try:
            desc = dynamodb.describe_table(TableName=PROFILES_TABLE_NAME)
            sse = desc.get("Table", {}).get("SSEDescription", {})
            key_type = sse.get("SSEType")
            kms_master = sse.get("KMSMasterKeyArn")
            table["cmk_encrypted"] = key_type == "KMS" and bool(kms_master)
        except ClientError as e:
            logger.error("DynamoDB describe error: %s", e, exc_info=True)

    return {"ok": bucket["sse"] and bucket["public_blocked"] and table["cmk_encrypted"],
            "bucket": bucket,
            "profiles_table": table}

def _get_profile_role(sub: str | None) -> str | None:
    if not sub or not PROFILES_TABLE:
        logger.info("No sub or profiles table configured; treating as non-admin")
        return None

    try:
        resp = PROFILES_TABLE.get_item(Key={"id": sub})
    except ClientError as e:
        logger.error("profiles get_item failed for sub %s: %s", sub, e, exc_info=True)
        return None

    item = resp.get("Item")
    if not item:
        logger.info("No profile row for sub %s; treating as non-admin", sub)
        return None

    return (item.get("role") or "").lower()

# ---------- handler ----------

def handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    raw_path = event.get("rawPath", "/")

    if method == "OPTIONS":
        return _resp(200, {"ok": True})

    claims = _claims(event)
    logger.info(
        "Posture auth check claims.email=%s ADMIN_EMAIL=%s sub=%s",
        claims.get("email"),
        ADMIN_EMAIL,
        claims.get("sub"),
    )
    if not _is_admin(claims):
        return _resp(403, {"message": "Admins only"})

    if method == "GET" and raw_path.endswith("/security/posture"):
        logger.info("Running posture checks for admin %s", claims.get("sub"))

        posture = {
            "timestamp": _now_iso(),
            "cloudtrail": check_cloudtrail(),
            "guardduty": check_guardduty(),
            "securityhub": check_security_hub(),
            "config": check_config(),
            "waf": check_waf(),
            "encryption": check_encryption(),
        }
        return _resp(200, {"ok": True, "posture": posture})

    return _resp(404, {"message": "Not found"})
