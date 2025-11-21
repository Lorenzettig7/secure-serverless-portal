# pii_scanner.py
import os
import json
import logging
import re
from datetime import datetime, timezone
import uuid

import boto3
from boto3.dynamodb.types import TypeDeserializer

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DESERIALIZER = TypeDeserializer()
DDB = boto3.resource("dynamodb")

FINDINGS_TABLE = os.environ.get("FINDINGS_TABLE_NAME")

# simple patterns - good enough for demo
DOB_RE = re.compile(r"\b(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b")
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,16}\b")  # very rough

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _deserialize_image(new_image):
    return {k: DESERIALIZER.deserialize(v) for k, v in new_image.items()}

def _check_pii(text: str):
    text = text or ""
    matched = []
    if DOB_RE.search(text):
        matched.append("dob")
    if SSN_RE.search(text):
        matched.append("ssn")
    if CC_RE.search(text):
        matched.append("card")
    return matched

def handler(event, context):
    table = DDB.Table(FINDINGS_TABLE)
    logger.info("Received %d records", len(event.get("Records", [])))

    for rec in event.get("Records", []):
        if rec.get("eventName") not in ("INSERT", "MODIFY"):
            continue

        new_image = rec.get("dynamodb", {}).get("NewImage")
        if not new_image:
            continue

        profile = _deserialize_image(new_image)
        bio = (profile.get("bio") or "").strip()
        if not bio:
            continue

        matched = _check_pii(bio)
        if not matched:
            continue

        user_id = profile.get("sub") or profile.get("id") or "unknown"
        email = profile.get("email")

        finding_id = str(uuid.uuid4())
        created_at = _now_iso()

        item = {
            "id": finding_id,
            "user_id": user_id,
            "email": email,
            "type": "PII_IN_PROFILE",
            "source": "local-scan",
            "severity": "HIGH" if "ssn" in matched or "card" in matched else "MEDIUM",
            "summary": f"Possible {', '.join(matched)} in profile bio.",
            "status": "OPEN",
            "created_at": created_at,
            "details": {
                "matched_types": matched,
                # don't store full bio in a real system; okay here for demo
                "sample": bio[:200]
            },
        }

        logger.info("Writing finding: %s", item)
        table.put_item(Item=item)

    return {"status": "ok"}
