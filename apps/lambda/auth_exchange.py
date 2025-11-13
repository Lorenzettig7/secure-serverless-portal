import json, os, urllib.parse, urllib.request, base64

TOKEN_URL = f"https://{os.environ['COGNITO_DOMAIN']}/oauth2/token"
CLIENT_ID = os.environ["CLIENT_ID"]
REDIRECT  = os.environ["REDIRECT_URI"]

def lambda_handler(event, context):
    qs = event.get("queryStringParameters") or {}
    code = qs.get("code")
    if not code:
        return {"statusCode": 400, "headers": {"content-type":"application/json"},
                "body": json.dumps({"error":"missing code"})}

    data = urllib.parse.urlencode({
        "grant_type":"authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "redirect_uri": REDIRECT
    }).encode()

    req = urllib.request.Request(TOKEN_URL, data=data,
                                 headers={"Content-Type":"application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req) as r:
        tok = json.loads(r.read().decode())

    # httpOnly cookies (id/access), 1h, secure, same-site
    headers = {
      "Set-Cookie": (
        f"id_token={tok['id_token']}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600"
      ),
      "Location": "/",
      "Cache-Control": "no-store"
    }
    return {"statusCode": 302, "headers": headers, "body": ""}  # redirect home
