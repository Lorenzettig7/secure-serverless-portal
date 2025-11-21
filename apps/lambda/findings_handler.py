# findings_handler.py
import os
import json
import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DDB = boto3.resource("dynamodb")
TABLE_NAME = os.environ.get("FINDINGS_TABLE_NAME")
ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "*")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").lower()


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
    jwt = event.get("requestContext", {}).get("authorizer", {}).get("jwt", {})
    return jwt.get("claims") or {}


def _is_admin(claims):
    email = (claims.get("email") or "").lower()
    if not ADMIN_EMAIL:
        # If env var not set, fall back to custom:role (for flexibility later)
        return (claims.get("custom:role") or "").lower() == "admin"
    return email == ADMIN_EMAIL


def _user_id(claims):
    return claims.get("sub")


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    raw_path = event.get("rawPath", "/")

    claims = _claims(event)
    user_id = _user_id(claims)

    table = DDB.Table(TABLE_NAME)

    try:
        # ---------------- GET /findings ----------------
        if method == "GET" and raw_path.endswith("/findings"):
            if not user_id:
                return _resp(403, {"message": "No user"})

            qsp = event.get("queryStringParameters") or {}

            # Admin can see all (scan, capped)
            if _is_admin(claims) and qsp.get("scope") == "all":
                scan = table.scan(Limit=50)
                items = scan.get("Items", [])

            else:
                # Normal user – try GSI first, fall back to scan
                try:
                    qs = table.query(
                        IndexName="by_user",
                        KeyConditionExpression=Key("user_id").eq(user_id),
                        ScanIndexForward=False,
                        Limit=25,
                    )
                    items = qs.get("Items", [])
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code")
                    # e.g. index doesn't exist yet, etc.
                    if code == "ValidationException":
                        logger.warning(
                            "GSI by_user not available, falling back to scan: %s", e
                        )
                        scan = table.scan(
                            FilterExpression=Attr("user_id").eq(user_id),
                            Limit=25,
                        )
                        items = scan.get("Items", [])
                    else:
                        raise

            return _resp(200, {"items": items})

        # ---------------- POST /findings/resolve ----------------
        if method == "POST" and raw_path.endswith("/findings/resolve"):
            body = json.loads(event.get("body") or "{}")
            fid = body.get("id")
            if not fid:
                return _resp(400, {"message": "Missing id"})

            # In a real system you'd also check user_id or admin rights more strictly
            res = table.update_item(
                Key={"id": fid},
                UpdateExpression="SET #s = :s, resolved_at = :t",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":s": "RESOLVED",
                    ":t": _now_iso(),
                },
                ReturnValues="ALL_NEW",
            )
            return _resp(200, {"ok": True, "item": res.get("Attributes")})

        # ---------------- Fallback: 404 ----------------
        return _resp(404, {"message": "Not found"})

    except ClientError as e:
        logger.error("DDB error: %s", e, exc_info=True)
        return _resp(500, {"message": "Server error"})
