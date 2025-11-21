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

    Expected shape (simplified):

      {
        "detail": {
          "findings": [
            {
              "id": "...",
              "category": "...",
              "description": "...",
              "severity": { "description": "LOW|MEDIUM|HIGH|..." },
              "createdAt": "2025-11-20T18:00:00Z",
              "resourcesAffected": {
                "s3Object": { "bucketName": "...", "key": "..." },
                "s3Bucket": { "name": "..." }
              }
            }
          ]
        }
      }
    """
    logger.info("Received event: %s", json.dumps(event))

    detail = event.get("detail") or {}
    findings = detail.get("findings") or []

    if not findings:
        logger.info("No findings in event detail; nothing to do.")
        return {"status": "ok", "processed": 0}

    processed = 0

    for finding in findings:
        macie_finding_id = finding.get("id") or str(uuid.uuid4())
        category = finding.get("category")
        description = finding.get("description")
        severity_info = finding.get("severity") or {}
        severity = severity_info.get("description") or "LOW"
        classification_details = finding.get("classificationDetails") or {}
        macie_job_id = classification_details.get("jobId")
        macie_job_arn = classification_details.get("jobArn")
        updated_at = finding.get("updatedAt")

        created_at = finding.get("createdAt")
        if created_at is None:
            created_at = datetime.now(timezone.utc).isoformat()

        bucket_name, key = _extract_bucket_and_key(finding)

        # Try to pull the email from the raw profile snapshot in S3
        email = None
        if bucket_name and bucket_name == RAW_BUCKET:
            email = _lookup_email_from_s3(bucket_name, key)

        console_url = (
            "https://console.aws.amazon.com/macie/home"
            f"?region={AWS_REGION}#/findings"
        )

        item = {
        "id": str(uuid.uuid4()),
        "email": email,  # can be None; UI should handle that
        "type": "MACIE_SENSITIVE_DATA",
        "source": "macie",
        "severity": severity,
        "summary": description or "Amazon Macie detected sensitive data.",
        "status": "OPEN",
        "created_at": created_at,
        "details": {
            "description": description,
            "category": category,
            "bucket": bucket_name,
            "object_key": key,
            "macie_finding_id": macie_finding_id,
            "console_url": console_url,
            # NEW: Macie job context
            "macie_job_id": macie_job_id,
            "macie_job_arn": macie_job_arn,
            "updated_at": updated_at,
        },
    }

        logger.info("Writing Macie finding to DynamoDB: %s", item)
        TABLE.put_item(Item=item)
        processed += 1

    return {"status": "ok", "processed": processed}

