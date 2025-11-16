import os, json, logging, time
from datetime import datetime, timedelta, timezone
import boto3
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "https://portal.secureschoolcloud.org")
MAX_EVENTS = int(os.environ.get("MAX_EVENTS", "20"))
WINDOW_MINUTES = int(os.environ.get("WINDOW_MINUTES", "15"))
LOG_GROUP = os.environ.get("LOG_GROUP")  # /aws/lambda/<your-profile-fn>

cloudtrail = boto3.client(
    "cloudtrail",
    config=Config(connect_timeout=2, read_timeout=3, retries={"max_attempts": 2})
)
logs = boto3.client("logs")

# add near imports
def _json_from_log_message(msg: str):
    # best-effort: handle "INFO\t{...}" or any prefix before the first '{'
    try:
        return json.loads(msg)
    except Exception:
        i = msg.find("{")
        if i != -1:
            try:
                return json.loads(msg[i:])
            except Exception:
                pass
    return {"raw": msg}

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

def _jwt_sub(event):
    return (
        event.get("requestContext", {})
             .get("authorizer", {})
             .get("jwt", {})
             .get("claims", {})
             .get("sub")
    )

def _profile_events_from_logs(sub):
    if not (LOG_GROUP and sub):
        return []

    # Query recent PROFILE_* events for this user
    query = f"""
      fields @timestamp, @message
      | filter event like /PROFILE_/ and sub = "{sub}"
      | sort @timestamp desc
      | limit {MAX_EVENTS}
    """
    end = int(time.time())
    start = end - WINDOW_MINUTES * 60
    qid = logs.start_query(
        logGroupName=LOG_GROUP,
        startTime=start,
        endTime=end,
        queryString=query
    )["queryId"]

    status = "Running"
    while status in ("Running", "Scheduled"):
        time.sleep(1)
        out = logs.get_query_results(queryId=qid)
        status = out["status"]

    results = []
    for row in out.get("results", []):
        ts  = next((f["value"] for f in row if f["field"] == "@timestamp"), "")
        msg = next((f["value"] for f in row if f["field"] == "@message"), "{}")
        data = _json_from_log_message(msg)
        data["@timestamp"] = ts
        results.append(data)
    return results



def handler(event, context):
    body = {"events": []}  # <-- keep existing field for current UI
    try:
        # 1) CloudTrail (existing)
        now = datetime.now(timezone.utc)
        start = now - timedelta(minutes=WINDOW_MINUTES)
        out = cloudtrail.lookup_events(StartTime=start, EndTime=now, MaxResults=MAX_EVENTS)
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

    # 2) New: Logs Insights for user’s PROFILE_* events
    try:
        sub = _jwt_sub(event)
        body["profileEvents"] = _profile_events_from_logs(sub) if sub else []
    except Exception as exc:
        logger.error("Logs Insights query failed: %s", exc, exc_info=True)
        body["profileEvents"] = []

    # 3) New: also expose trailEvents (alias) for future UI
    body["trailEvents"] = body["events"]

    return _resp(200, body)
