import os, json, logging
from datetime import datetime, timedelta
import boto3
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "https://portal.secureschoolcloud.org")
MAX_EVENTS = int(os.environ.get("MAX_EVENTS", "20"))

cloudtrail = boto3.client(
    "cloudtrail",
    config=Config(connect_timeout=2, read_timeout=3, retries={"max_attempts": 2})
)

def _resp(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        },
        "body": json.dumps(body),
    }

def handler(event, context):
    claims = (event.get("requestContext", {})
                  .get("authorizer", {})
                  .get("jwt", {})
                  .get("claims", {}) or {})
    sub = claims.get("sub")
    email = claims.get("email")
    if not sub:
        return _resp(400, {"error": "Missing user identity"})

    logger.info("TELEMETRY_READ for %s (%s)", sub, email)

    body = {"events": []}
    try:
        end = datetime.utcnow()
        start = end - timedelta(minutes=15)
        out = cloudtrail.lookup_events(StartTime=start, EndTime=end, MaxResults=MAX_EVENTS)
        for e in out.get("Events", []):
            body["events"].append({
                "time": e.get("EventTime").isoformat() if e.get("EventTime") else None,
                "name": e.get("EventName"),
                "source": e.get("EventSource"),
                "username": e.get("Username"),
            })
    except Exception as exc:
        logger.error("CloudTrail lookup failed: %s", exc, exc_info=True)
        body["warning"] = "CloudTrail temporarily unavailable"

    return _resp(200, body)
