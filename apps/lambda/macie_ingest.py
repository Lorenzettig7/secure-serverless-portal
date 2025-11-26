import os
import json
import logging
import uuid
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DDB = boto3.resource("dynamodb")
TABLE = DDB.Table(os.environ["FINDINGS_TABLE_NAME"])
S3 = boto3.client("s3")

RAW_BUCKET = os.environ["PROFILE_RAW_BUCKET"]  # ssp-profiles-raw
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


def _extract_bucket_and_key(finding: dict):
    """Best-effort extraction of bucket + key from a Macie finding."""
    resources = finding.get("resourcesAffected", {}) or {}

    s3_object = resources.get("s3Object") or {}
    s3_bucket = resources.get("s3Bucket") or {}

    bucket_name = (
        s3_object.get("bucketName")
        or s3_bucket.get("name")
        or s3_bucket.get("bucketName")
    )
    key = s3_object.get("key")

    return bucket_name, key


def _lookup_email_from_s3(bucket_name: str, key: str):
    """
    Look up the profile email from the raw S3 snapshot.

    The profile snapshot is JSON that looks like:
      { "sub": "...", "email": "...", "bio": "..." }
    """
    if not bucket_name or not key:
        return None

    try:
        obj = S3.get_object(Bucket=bucket_name, Key=key)
        body = obj["Body"].read()
        data = json.loads(body)
        return data.get("email")
    except Exception as e:  # best-effort; don't break on failure
        logger.warning(
            "Failed to fetch/parse S3 object %s/%s for Macie finding: %s",
            bucket_name,
            key,
            e,
        )
        return None

def handler(event, context):
    """
    Lambda entrypoint for Macie findings from EventBridge.

    Macie normally sends one finding per event in `detail`. Some
    older examples show `detail.findings[]`, so we support both.
    """
    logger.info("Received event: %s", json.dumps(event))

    detail = event.get("detail") or {}

    # Support multiple possible shapes:
    # 1) detail.findings[] (list)
    # 2) detail.findings (single object)
    # 3) detail itself is the finding (Macie Finding event)
    raw_findings = detail.get("findings")

    if isinstance(raw_findings, list) and raw_findings:
        findings = raw_findings
    elif raw_findings:
        findings = [raw_findings]
    elif detail.get("id") and detail.get("type"):
        findings = [detail]
    else:
        logger.info("No findings in event detail; nothing to do.")
        return {"status": "ok", "processed": 0}

    processed = 0

    for finding in findings:
        macie_finding_id = finding.get("id") or str(uuid.uuid4())
        finding_type = finding.get("type", "UNKNOWN")
        title = finding.get("title") or finding_type
        description = finding.get("description") or ""

        severity_info = finding.get("severity") or {}
        severity = (severity_info.get("description") or "LOW").upper()

        created_at_raw = finding.get("createdAt") or finding.get("updatedAt")
        if created_at_raw:
            try:
                created_at = datetime.fromisoformat(
                    created_at_raw.replace("Z", "+00:00")
                ).isoformat()
            except Exception:
                created_at = datetime.now(timezone.utc).isoformat()
        else:
            created_at = datetime.now(timezone.utc).isoformat()

        resources = finding.get("resourcesAffected") or {}
        s3_bucket_info = resources.get("s3Bucket") or {}
        bucket_name = s3_bucket_info.get("name")

        object_path = None
        user_id = None

        s3_object_info = resources.get("s3Object") or {}
        key = s3_object_info.get("key")
        if key:
            object_path = key
            # Expected key format: "profiles/<sub>.json"
            filename = key.split("/")[-1]
            if filename.endswith(".json"):
                user_id = filename.rsplit(".", 1)[0]

        classification = finding.get("classificationDetails") or {}
        macie_job_id = classification.get("jobId")
        macie_job_arn = classification.get("jobArn")

        console_url = finding.get("consoleUrl") or finding.get("url")

        # Your UI expects at least an email field; if you don't have one,
        # you can use a placeholder or derive it from the finding if present.
        email = (finding.get("sample") or {}).get("email") if isinstance(
            finding.get("sample"), dict
        ) else "unknown@example.com"

        item = {
            "id": str(uuid.uuid4()),
            "user_id": user_id or "unknown",
            "created_at": created_at,
            "email": email,
            "severity": severity,
            "status": "OPEN",
            "source": "macie",
            "type": "MACIE_SENSITIVE_DATA",
            "details": {
                "macie_finding_id": macie_finding_id,
                "title": title,
                "description": description,
                "finding_type": finding_type,
                "bucket": bucket_name,
                "object_path": object_path,
                "console_url": console_url,
                "macie_job_id": macie_job_id,
                "macie_job_arn": macie_job_arn,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            },
        }


        logger.info("Writing Macie finding to DynamoDB: %s", item)
        TABLE.put_item(Item=item)
        processed += 1

    return {"status": "ok", "processed": processed}
#update
