import json

def lambda_handler(event, context):
    # In a real app you'd query CloudWatch Logs/CloudTrail here
    return {
        "statusCode": 200,
        "headers": {"content-type":"application/json"},
        "body": json.dumps({"events":[{"type":"PROFILE_READ","count":1}]})
    }
