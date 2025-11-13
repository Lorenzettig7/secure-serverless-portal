import json, os

def lambda_handler(event, context):
    method = event.get("requestContext", {}).get("http", {}).get("method", "")
    # In a real app you'd read/write DynamoDB using TABLE_NAME
    if method == "POST":
        return {
            "statusCode": 200,
            "headers": {"content-type":"application/json"},
            "body": json.dumps({"ok": True, "action": "update_profile"})
        }
    return {
        "statusCode": 200,
        "headers": {"content-type":"application/json"},
        "body": json.dumps({"ok": True, "action": "get_profile"})
    }
