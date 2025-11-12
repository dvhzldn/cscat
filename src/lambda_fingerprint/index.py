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
        body = json.loads(event.get("body") or "{}")
        url = body.get("url")
        if not url:
            return respond(400, {"error": "Missing URL in request body."})

        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = "https://" + url
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            return respond(400, {"error": f"Invalid URL: {url}"})

        try:
            response = requests.get(url, timeout=10, allow_redirects=False)
            headers = {k.lower(): v for k, v in response.headers.items()}
            content = response.text
        except requests.exceptions.RequestException as e:
            return respond(
                200, {"results": {"error": f"Failed to fetch URL: {str(e)}"}}
            )
        except Exception as e:
            return respond(200, {"results": {"error": f"Unexpected error: {str(e)}"}})

        # --- security/fingerprint logic ---
        results = {}
        server_header = headers.get("server")
        results["Server"] = {
            "status": "FAILED" if server_header else "PASSED",
            "value": server_header or "Suppressed",
            "notes": "Server header info." if server_header else "Header suppressed.",
        }

        powered_by = headers.get("x-powered-by")
        results["X_Powered_By"] = {
            "status": "FAILED" if powered_by else "PASSED",
            "value": powered_by or "Suppressed",
            "notes": "X-Powered-By exposed." if powered_by else "Header suppressed.",
        }

        # Detect frameworks
        markers = [
            "wp-content",
            "joomla",
            "drupal",
            "next.js",
            "react-dom",
            "analytics.js",
        ]
        detected = [m for m in markers if m.lower() in content.lower()]
        results["Technology_Stack"] = {
            "status": "WARNING" if detected else "PASSED",
            "value": " | ".join(detected) if detected else "None detected",
            "notes": "Frameworks detected" if detected else "No major fingerprints.",
        }

        return respond(200, {"results": results})

    except Exception as e:
        return respond(200, {"results": {"error": f"Internal error: {str(e)}"}})
