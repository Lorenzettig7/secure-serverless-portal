import json
import os
import logging

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["TABLE_NAME"])

ALLOWED_ORIGIN = os.environ.get("ALLOWED_ORIGIN", "https://portal.secureschoolcloud.org")



def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        },
        "body": json.dumps(body),
    }


def handler(event, context):
    """
    Entry point for API Gateway HTTP API (JWT authorizer in front).
    Supports:
      - GET  /profile  -> read profile from DynamoDB
      - POST /profile  -> update profile (bio) in DynamoDB
    """
    logger.info("EVENT: %s", json.dumps(event))

    http = event.get("requestContext", {}).get("http", {})
    method = http.get("method")

    claims = (
        event.get("requestContext", {})
        .get("authorizer", {})
        .get("jwt", {})
        .get("claims", {})
    )

    user_id = claims.get("sub")
    email = claims.get("email")

    if not user_id:
        return _response(400, {"error": "Missing user ID in token"})

    if method == "GET":
        # Read profile from DynamoDB
        logger.info("PROFILE_READ for %s", user_id)
        try:
            resp = table.get_item(Key={"id": user_id})
            item = resp.get("Item", {})
        except Exception as e:
            logger.error("Error reading profile from DynamoDB: %s", e)
            return _response(500, {"error": "Failed to read profile"})

        profile = {
            "user_id": user_id,
            "email": email,
            "bio": item.get("bio", ""),
            "note": "Loaded from DynamoDB",
        }
        return _response(200, profile)

    if method == "POST":
        # Update profile in DynamoDB
        try:
            raw_body = event.get("body") or "{}"
            body = json.loads(raw_body)
        except json.JSONDecodeError:
            return _response(400, {"error": "Invalid JSON body"})

        bio = body.get("bio", "")

        try:
            table.put_item(
                Item={
                    "id": user_id,
                    "email": email,
                    "bio": bio,
                }
            )
            logger.info("PROFILE_UPDATE for %s", user_id)
        except Exception as e:
            logger.error("Error updating profile in DynamoDB: %s", e)
            return _response(500, {"error": "Failed to update profile"})

        return _response(200, {"message": "Profile updated"})

    return _response(405, {"error": "Method not allowed"})
