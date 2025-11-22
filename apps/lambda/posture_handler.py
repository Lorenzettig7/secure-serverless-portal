import json
import os
import boto3
import logging
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError

log = logging.getLogger()
log.setLevel(logging.INFO)

# DynamoDB for profiles
dynamodb_res = boto3.resource("dynamodb")
PROFILES_TABLE_NAME = os.environ["PROFILES_TABLE_NAME"]
PROFILES_TABLE = dynamodb_res.Table(PROFILES_TABLE_NAME)

# Other AWS clients
ct_client = boto3.client("cloudtrail")
gd_client = boto3.client("guardduty")
sh_client = boto3.client("securityhub")
cfg_client = boto3.client("config")
waf_client = boto3.client("wafv2")
s3_client = boto3.client("s3")
ddb_client = boto3.client("dynamodb")

WAF_WEBACL_ARN = os.environ.get("WAF_WEBACL_ARN", "")
WAF_SAMPLE_RULE = os.environ.get("WAF_SAMPLE_RULE", "Default_Action")
PORTAL_BUCKET_NAME = os.environ.get("PORTAL_BUCKET_NAME", "")
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")


def resp(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
            "Access-Control-Allow-Headers": "Authorization,Content-Type",
        },
        "body": json.dumps(body),
    }


def get_claims(event):
    rc = event.get("requestContext", {})
    auth = rc.get("authorizer", {})

    # HTTP API + JWT
    if "jwt" in auth:
        return auth["jwt"].get("claims", {}) or {}

    # REST API fallback
    return auth.get("claims", {}) or {}


# -------- posture helpers -------- #

def cloudtrail_status():
    try:
        trails = ct_client.describe_trails().get("trailList", [])
        trail_count = len(trails)
        multi_region = any(t.get("IsMultiRegionTrail") for t in trails)
        ok = trail_count > 0 and multi_region
        return {
            "ok": ok,
            "trail_count": trail_count,
            "multi_region": multi_region,
        }
    except Exception as e:
        log.exception("CloudTrail check failed")
        return {
            "ok": False,
            "trail_count": 0,
            "multi_region": False,
            "error": str(e),
        }


def guardduty_status():
    try:
        detectors = gd_client.list_detectors().get("DetectorIds", [])
        if not detectors:
            return {"enabled": False}
        det_id = detectors[0]
        det = gd_client.get_detector(DetectorId=det_id)
        enabled = det.get("Status") == "ENABLED"
        return {"enabled": enabled}
    except Exception as e:
        log.exception("GuardDuty check failed")
        return {"enabled": False, "error": str(e)}


def securityhub_status():
    enabled = False
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    # Is Security Hub enabled?
    try:
        sh_client.describe_hub()
        enabled = True
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidAccessException", "AccessDeniedException"):
            # Not enabled → just show disabled
            return {"enabled": False, "severity_counts": severity_counts}
        log.exception("Security Hub describe failed")
        return {
            "enabled": False,
            "severity_counts": severity_counts,
            "error": str(e),
        }
    except Exception as e:
        log.exception("Security Hub describe failed")
        return {
            "enabled": False,
            "severity_counts": severity_counts,
            "error": str(e),
        }

    # If enabled, sample some ACTIVE findings
    try:
        paginator = sh_client.get_paginator("get_findings")
        for page in paginator.paginate(
            Filters={
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            },
            PaginationConfig={"PageSize": 25},
        ):
            for f in page.get("Findings", []):
                label = (f.get("Severity", {}).get("Label") or "").upper()
                if label in severity_counts:
                    severity_counts[label] += 1
    except Exception as e:
        log.exception("Security Hub findings failed")
        return {
            "enabled": enabled,
            "severity_counts": severity_counts,
            "error": str(e),
        }

    return {"enabled": enabled, "severity_counts": severity_counts}


def config_status():
    try:
        summary = cfg_client.get_compliance_summary_by_config_rule().get(
            "ComplianceSummary", {}
        )
        compliant = summary.get("CompliantResourceCount", {}).get("CappedCount", 0)
        non_compliant = summary.get("NonCompliantResourceCount", {}).get(
            "CappedCount", 0
        )
        return {
            "ok": True,
            "compliant": compliant,
            "non_compliant": non_compliant,
        }
    except Exception as e:
        log.exception("Config summary failed")
        return {
            "ok": False,
            "compliant": 0,
            "non_compliant": 0,
            "error": str(e),
        }


def waf_status():
    if not WAF_WEBACL_ARN:
        return {
            "ok": False,
            "allowed_24h_sample": 0,
            "blocked_24h_sample": 0,
            "error": "WAF_WEBACL_ARN not set",
        }

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=24)

    try:
        resp = waf_client.get_sampled_requests(
            WebAclArn=WAF_WEBACL_ARN,
            RuleMetricName=WAF_SAMPLE_RULE,
            Scope="CLOUDFRONT",  # your ACL ARN is 'global'
            TimeWindow={"StartTime": start, "EndTime": end},
            MaxItems=100,
        )
        sampled = resp.get("SampledRequests", [])
        allowed = sum(1 for r in sampled if r.get("Action") == "ALLOW")
        blocked = sum(1 for r in sampled if r.get("Action") == "BLOCK")
        return {
            "ok": True,
            "allowed_24h_sample": allowed,
            "blocked_24h_sample": blocked,
        }
    except Exception as e:
        log.exception("WAF check failed")
        return {
            "ok": False,
            "allowed_24h_sample": 0,
            "blocked_24h_sample": 0,
            "error": str(e),
        }


def portal_bucket_status():
    sse = False
    public_blocked = False
    enc_error = pab_error = None

    if not PORTAL_BUCKET_NAME:
        return {
            "sse": False,
            "public_blocked": False,
            "encryption_error": "PORTAL_BUCKET_NAME not set",
            "public_access_error": None,
        }

    # SSE
    try:
        enc = s3_client.get_bucket_encryption(Bucket=PORTAL_BUCKET_NAME)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        sse = len(rules) > 0
    except ClientError as e:
        if (
            e.response["Error"]["Code"]
            != "ServerSideEncryptionConfigurationNotFoundError"
        ):
            log.exception("Bucket encryption check failed")
            enc_error = str(e)
    except Exception as e:
        log.exception("Bucket encryption check failed")
        enc_error = str(e)

    # Public access block
    try:
        pab = s3_client.get_bucket_public_access_block(Bucket=PORTAL_BUCKET_NAME)
        cfg_pab = pab.get("PublicAccessBlockConfiguration", {})
        public_blocked = all(
            cfg_pab.get(k, False)
            for k in [
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            ]
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
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
    cmk_encrypted = False
    error = None
    try:
        desc = ddb_client.describe_table(TableName=PROFILES_TABLE_NAME)
        sse = desc.get("Table", {}).get("SSEDescription", {})
        key_arn = sse.get("KMSMasterKeyArn")
        if key_arn:
            cmk_encrypted = True
    except Exception as e:
        log.exception("Profiles table encryption check failed")
        error = str(e)

    return {"cmk_encrypted": cmk_encrypted, "error": error}


# -------- Lambda handler -------- #

def handler(event, context):
    log.info("EVENT: %s", json.dumps(event))

    try:
        # 1. Auth & claims
        claims = get_claims(event)
        sub = claims.get("sub")
        email = claims.get("email")

        if not sub:
            log.warning("No sub in claims: %s", claims)
            return resp(401, {"message": "Unauthorized (missing sub claim)"})

        # 2. Load profile
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

        if role != "admin":
            return resp(403, {"message": "Admin access required"})

        # 3. Build posture
        ct_status = cloudtrail_status()
        gd_status = guardduty_status()
        sh_status = securityhub_status()
        cfg_status = config_status()
        waf_status_obj = waf_status()
        bucket_status = portal_bucket_status()
        profiles_enc = profiles_table_encryption_status()

        enc_ok = (
            bucket_status.get("sse", False)
            and bucket_status.get("public_blocked", False)
            and profiles_enc.get("cmk_encrypted", False)
        )

        posture = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cloudtrail": ct_status,
            "guardduty": gd_status,
            "securityhub": sh_status,
            "config": cfg_status,
            "waf": waf_status_obj,
            "encryption": {
                "ok": enc_ok,
                "bucket": bucket_status,
                "profiles_table": profiles_enc,
            },
        }

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
