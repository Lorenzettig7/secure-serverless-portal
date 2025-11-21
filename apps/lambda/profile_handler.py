# profile_handler.py
import os
import json
import logging
import base64
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DDB = boto3.resource("dynamodb")
TABLE_NAME = os.environ.get("TABLE_NAME")
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")

TABLE = DDB.Table(TABLE_NAME)

PK_NAME = os.environ.get("PK_NAME", "id")

def _resp(status, body_obj):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        },
        "body": json.dumps(body_obj),
    }

def _claims(event):
    return (
        event.get("requestContext", {})
             .get("authorizer", {})
             .get("jwt", {})
             .get("claims", {})
    )

def _sub_email(event):
    c = _claims(event)
    return c.get("sub"), c.get("email")

def _parse_body(event):
    body = event.get("body")
    if not body:
        return {}
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8", "ignore")
    try:
        return json.loads(body)
    except Exception:
        return {}

def _log_event(name, sub, extra=None):
    payload = {"event": name, "sub": sub, "ts": datetime.now(timezone.utc).isoformat()}
    if extra:
        payload.update(extra)
    # IMPORTANT: JSON line so Logs Insights can parse
    logger.info(json.dumps(payload))

def _get_profile(sub, email_hint=None):
    try:
        r = TABLE.get_item(Key={PK_NAME: sub})
        item = r.get("Item")
        if item:
            return item, "Loaded from DynamoDB"
        # default view if nothing stored yet
        return {
            PK_NAME: sub,
            "email": email_hint or "",
            "bio": "",
            "role": "student",
        }, "New profile (not yet saved)"
    except ClientError as e:
        logger.error("DynamoDB get_item failed: %s", e, exc_info=True)
        raise

def _put_profile(sub, email, bio,role):
    item = {
        PK_NAME: sub,
        "email": email or "",
        "bio": bio or "",
        "role": role,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    TABLE.put_item(Item=item)
    return item

def handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    sub, email = _sub_email(event)
    if not sub:
        return _resp(401, {"message": "Unauthorized: missing sub"})

    if method == "GET":
        profile, note = _get_profile(sub, email)
        _log_event("PROFILE_READ", sub, {"table": TABLE_NAME})
        return _resp(200, {
            **profile,
            "note": note
        })
    
    if method == "POST":
        body = _parse_body(event)
        bio = (body.get("bio") or "").strip()
        role = (body.get("role") or "student").strip().lower()
        if role == "administrator":
            role = "admin"


        try:
            # Save profile to DynamoDB
            saved = _put_profile(sub, email, bio, role)

            # NEW: write raw profile to S3 for Macie scanning and future use
            s3 = boto3.client("s3")
            bucket = os.environ.get("PROFILE_RAW_BUCKET")
            if bucket:
                key = f"profiles/{sub}.json"
                s3.put_object(
                    Bucket=bucket,
                    Key=key,
                    Body=json.dumps({"sub": sub, "email": email, "bio": bio}),
                    ServerSideEncryption="aws:kms",
                )

            _log_event("PROFILE_UPDATE", sub, {"table": TABLE_NAME})
            return _resp(200, {"ok": True, **saved})

        except ClientError as e:
            logger.error("DynamoDB put_item failed: %s", e, exc_info=True)
            return _resp(500, {"message": "Failed to save profile"})

    # other methods not used
    return _resp(405, {"message": "Method not allowed"})
