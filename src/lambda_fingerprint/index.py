import json
import requests
from urllib.parse import urlparse

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,POST",
    "Access-Control-Allow-Headers": (
        "Content-Type,X-Amz-Date,Authorization,X-Api-Key,"
        "X-Amz-Security-Token,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,Sec-Ch-Ua-Platform,Dnt"
    ),
    "Access-Control-Max-Age": "3600",
    "Content-Type": "application/json",
}


def respond(status_code, body):
    return {
        "statusCode": status_code,
        "headers": CORS_HEADERS,
        "body": json.dumps(body),
    }


def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return respond(200, {"message": "CORS preflight OK"})

    try:
        try:
            body = json.loads(event.get("body") or "{}")
        except json.JSONDecodeError:
            return respond(400, {"error": "Invalid JSON request body."})

        url = body.get("url")
        if not url:
            return respond(400, {"error": "Missing URL in request body."})

        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = "https://" + url
        if not parsed_url.netloc and parsed_url.path:
            url = "https://" + parsed_url.path

        try:
            response = requests.get(url, timeout=5, allow_redirects=False)
            headers = {k.lower(): v for k, v in response.headers.items()}
            content = response.text
        except requests.exceptions.Timeout:
            return respond(200, {"results": {"error": "Request timed out."}})
        except requests.exceptions.RequestException as e:
            return respond(
                200, {"results": {"error": f"Failed to fetch URL: {str(e)}"}}
            )

        results = {}
        server_header = headers.get("server")
        results["Server"] = (
            {
                "status": "FAILED",
                "value": server_header,
                "notes": "Server header exposes backend info.",
            }
            if server_header
            else {
                "status": "PASSED",
                "value": "Suppressed",
                "notes": "Server header not exposed (recommended).",
            }
        )
        powered_by = headers.get("x-powered-by")
        results["X_Powered_By"] = (
            {
                "status": "FAILED",
                "value": powered_by,
                "notes": "X-Powered-By header exposes framework/tech info.",
            }
            if powered_by
            else {
                "status": "PASSED",
                "value": "Suppressed",
                "notes": "X-Powered-By header not exposed (recommended).",
            }
        )
        markers = [
            "wp-content",
            "joomla",
            "drupal",
            "next.js",
            "react-dom",
            "analytics.js",
        ]
        detected = [m for m in markers if m.lower() in content.lower()]
        results["Technology_Stack"] = (
            {
                "status": "WARNING",
                "value": " | ".join(detected),
                "notes": "Frameworks detected — monitor for CVEs.",
            }
            if detected
            else {
                "status": "PASSED",
                "value": "None detected",
                "notes": "No major framework fingerprints found.",
            }
        )

        return respond(200, {"results": results})

    except Exception as e:
        return respond(500, {"error": f"Internal server error: {str(e)}"})
