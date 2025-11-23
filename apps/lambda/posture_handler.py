import json
import os
import logging
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

log = logging.getLogger()
log.setLevel(logging.INFO)

# Short timeouts so calls to public AWS APIs fail fast instead of hanging
AWS_CFG = Config(connect_timeout=0.5, read_timeout=1, retries={"max_attempts": 1})

session = boto3.Session()

ct_client = session.client("cloudtrail", config=AWS_CFG)
gd_client = session.client("guardduty", config=AWS_CFG)
sh_client = session.client("securityhub", config=AWS_CFG)
cfg_client = session.client("config", config=AWS_CFG)
waf_client = session.client("wafv2", config=AWS_CFG)
s3_client = session.client("s3", config=AWS_CFG)
ddb_client = session.client("dynamodb", config=AWS_CFG)

dynamodb = boto3.resource("dynamodb")
PROFILES_TABLE = dynamodb.Table(os.environ["PROFILES_TABLE_NAME"])

PORTAL_BUCKET_NAME = os.environ.get("PORTAL_BUCKET_NAME")
WAF_WEBACL_ARN = os.environ.get("WAF_WEBACL_ARN")
WAF_SAMPLE_RULE = os.environ.get("WAF_SAMPLE_RULE", "Default_Action")


def resp(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Authorization,Content-Type",
        },
        "body": json.dumps(body),
    }


def get_claims(event):
    rc = event.get("requestContext", {})
    auth = rc.get("authorizer", {})

    # HTTP API + JWT authorizer
    if "jwt" in auth:
        return auth["jwt"].get("claims", {}) or {}

    # Fallback for REST API style
    return auth.get("claims", {}) or {}


# -----------------------------
# Posture helpers
# -----------------------------

def cloudtrail_status():
    log.info("Checking CloudTrail posture")
    try:
        trails = ct_client.describe_trails().get("trailList", []) or []
        trail_count = len(trails)
        multi_region = any(t.get("IsMultiRegionTrail") for t in trails)
        return {
            "ok": trail_count > 0,
            "trail_count": trail_count,
            "multi_region": multi_region,
        }
    except Exception as e:
        log.exception("CloudTrail check failed")
        return {"ok": False, "error": str(e)}


def guardduty_status():
    log.info("Checking GuardDuty posture")
    try:
        det_ids = gd_client.list_detectors().get("DetectorIds", []) or []
        if not det_ids:
            return {"enabled": False}

        det = gd_client.get_detector(DetectorId=det_ids[0])
        status = det.get("Status", "UNKNOWN")
        return {
            "enabled": status.upper() == "ENABLED",
            "status": status,
        }
    except Exception as e:
        log.exception("GuardDuty check failed")
        return {"enabled": False, "error": str(e)}


def securityhub_status():
    log.info("Checking Security Hub posture")
    try:
        hub = sh_client.describe_hub()
        enabled = bool(hub)

        findings = sh_client.get_findings(
            MaxResults=50,
            Filters={
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            },
        )
        counts = {}
        for f in findings.get("Findings", []):
            sev = (f.get("Severity", {}) or {}).get("Label", "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1

        return {"enabled": enabled, "severity_counts": counts}
    except Exception as e:
        log.exception("Security Hub check failed")
        return {"enabled": False, "error": str(e)}


def config_status():
    log.info("Checking AWS Config posture")
    try:
        summary = cfg_client.get_compliance_summary_by_config_rule()
        comp = summary.get("ComplianceSummary", {}) or {}
        return {
            "ok": True,
            "compliant": comp.get("CompliantResourceCount", {}).get("CappedCount", 0),
            "non_compliant": comp.get("NonCompliantResourceCount", {}).get("CappedCount", 0),
        }
    except Exception as e:
        log.exception("Config check failed")
        return {"ok": False, "error": str(e)}


def waf_status():
    log.info("Checking WAF posture")
    if not (WAF_WEBACL_ARN and WAF_SAMPLE_RULE):
        # Frontend will just show "0 / gray"
        return {"ok": False, "error": "WAF env vars not set"}

    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=24)
        resp_waf = waf_client.get_sampled_requests(
            WebAclArn=WAF_WEBACL_ARN,
            RuleMetricName=WAF_SAMPLE_RULE,
            Scope="CLOUDFRONT",
            TimeWindow={"StartTime": start, "EndTime": end},
            MaxItems=100,
        )
        sampled = resp_waf.get("SampledRequests", []) or []
        allowed = sum(1 for r in sampled if r.get("Action") == "ALLOW")
        blocked = sum(1 for r in sampled if r.get("Action") == "BLOCK")

        return {
            "ok": True,
            "allowed_24h_sample": allowed,
            "blocked_24h_sample": blocked,
        }
    except Exception as e:
        log.exception("WAF check failed")
        return {"ok": False, "error": str(e)}


def portal_bucket_encryption_status():
    """Check S3 encryption + public access on the portal bucket."""
    if not PORTAL_BUCKET_NAME:
        return {
            "sse": False,
            "public_blocked": False,
            "encryption_error": "PORTAL_BUCKET_NAME env var not set",
            "public_access_error": None,
        }

    sse = False
    public_blocked = False
    enc_error = None
    pab_error = None

    # --- SSE on bucket ---
    try:
        enc = s3_client.get_bucket_encryption(Bucket=PORTAL_BUCKET_NAME)
        cfg = enc.get("ServerSideEncryptionConfiguration", {}) or {}
        rules = cfg.get("Rules", []) or []
        sse = len(rules) > 0
    except ClientError as e:
        # No config at all = just "off", not necessarily an error
        if e.response.get("Error", {}).get("Code") != "ServerSideEncryptionConfigurationNotFoundError":
            log.exception("Bucket encryption check failed")
            enc_error = str(e)
    except Exception as e:
        log.exception("Bucket encryption check failed")
        enc_error = str(e)

    # --- Public access block on bucket ---
    try:
        pab = s3_client.get_public_access_block(Bucket=PORTAL_BUCKET_NAME)
        cfg = pab.get("PublicAccessBlockConfiguration", {}) or {}
        public_blocked = all(bool(cfg.get(k)) for k in [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ])
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NoSuchPublicAccessBlockConfiguration":
            log.exception("Bucket public access block check failed")
            pab_error = str(e)
    except Exception as e:
        log.exception("Bucket public access block check failed")
        pab_error = str(e)

    return {
        "sse": sse,
        "public_blocked": public_blocked,
        "encryption_error": enc_error,
        "public_access_error": pab_error,
    }


def profiles_table_encryption_status():
    log.info("Checking DynamoDB profiles table encryption")
    cmk_encrypted = False
    error = None

    try:
        desc = ddb_client.describe_table(
            TableName=os.environ["PROFILES_TABLE_NAME"]
        )
        sse = (desc.get("Table", {}) or {}).get("SSEDescription", {}) or {}
        key_arn = sse.get("KMSMasterKeyArn")
        cmk_encrypted = bool(key_arn)
    except Exception as e:
        log.exception("Profiles table encryption check failed")
        error = str(e)

    return {
        "cmk_encrypted": cmk_encrypted,
        "error": error,
    }


# -----------------------------
# Main Lambda handler
# -----------------------------

def handler(event, context):
    log.info("EVENT: %s", json.dumps(event))

    # 1. Extract sub from JWT claims
    claims = get_claims(event)
    sub = claims.get("sub")
    email = claims.get("email")

    if not sub:
        log.warning("No sub in claims: %s", claims)
        return resp(401, {"message": "Unauthorized (missing sub claim)"})

    # 2. Load profile from DynamoDB
    try:
        ddb_resp = PROFILES_TABLE.get_item(Key={"id": sub})
        profile = ddb_resp.get("Item") or {}
        log.info("Loaded profile for %s: %s", sub, profile)
    except Exception as e:
        log.exception("Error reading profile from DynamoDB")
        return resp(
            500,
            {
                "message": "Failed to load profile",
                "error": str(e),
                "error_type": type(e).__name__,
            },
        )

    role = profile.get("role", "student")
    log.info("Posture request from %s (%s) role=%s", email, sub, role)

    # 3. Enforce admin-only access
    if role != "admin":
        return resp(403, {"message": "Admin access required"})

    # 4. Collect posture data (each helper handles its own errors)
    try:
        ct_status = cloudtrail_status()
        gd_status = guardduty_status()
        sh_status = securityhub_status()
        cfg_status = config_status()
        waf_status_obj = waf_status()
        bucket_status = portal_bucket_encryption_status()
        profiles_status = profiles_table_encryption_status()

        posture = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cloudtrail": ct_status,
            "guardduty": gd_status,
            "securityhub": sh_status,
            "config": cfg_status,
            "waf": waf_status_obj,
            "encryption": {
                "ok": bool(
                    bucket_status.get("sse")
                    and bucket_status.get("public_blocked")
                    and profiles_status.get("cmk_encrypted")
                ),
                "bucket": bucket_status,
                "profiles_table": profiles_status,
            },
        }

        log.info("Posture snapshot built: %s", json.dumps(posture))
        return resp(200, {"ok": True, "posture": posture})

    except Exception as e:
        log.exception("Posture handler failed with unexpected error")
        return resp(
            500,
            {
                "message": "Internal Server Error",
                "error": str(e),
                "error_type": type(e).__name__,
            },
        )
