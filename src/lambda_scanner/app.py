import json
import requests
from urllib.parse import urlparse


def scan_url(url, checks):
    """
    Performs security checks on the target URL.
    """
    results = []

    # 1. Standardize URL and perform initial connection check
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    status_code = None
    error_message = None
    headers = {}
    http_status = "FAILED"

    try:
        # Use a timeout for resilience
        response = requests.get(url, timeout=10)
        status_code = response.status_code
        headers = response.headers

        if 200 <= status_code < 400:
            http_status = "PASSED"
        elif 400 <= status_code < 500:
            http_status = "WARNING"
        else:
            http_status = "FAILED"  # 5xx or other non-client errors

    except requests.exceptions.RequestException as e:
        error_message = str(e)
        http_status = "FAILED"
        # Return early if connection fails
        return {
            "url": url,
            "status_code": status_code if status_code else 0,
            "http_status": http_status,
            "error_message": error_message,
            "security_findings": {},
        }

    # 2. Perform Security Checks
    security_findings = {}

    if "Strict-Transport-Security" in checks:
        hsts_value = headers.get("Strict-Transport-Security")
        if hsts_value:
            # Check for max-age and includeSubDomains
            if "max-age=" in hsts_value and "includeSubDomains" in hsts_value:
                hsts_status = "PASSED"
                hsts_notes = "HSTS header is present and correctly includes max-age and includeSubDomains."
            else:
                hsts_status = "WARNING"
                hsts_notes = "HSTS header is present but may be missing max-age or includeSubDomains."

            security_findings["hsts_status"] = hsts_status
            security_findings["hsts_value"] = hsts_value
            security_findings["hsts_notes"] = hsts_notes
        else:
            security_findings["hsts_status"] = "FAILED"
            security_findings["hsts_notes"] = (
                "Strict-Transport-Security (HSTS) header is missing."
            )

    if "X-Frame-Options" in checks:
        xfo_value = headers.get("X-Frame-Options")
        if xfo_value:
            xfo_value = xfo_value.upper()
            if xfo_value in ["DENY", "SAMEORIGIN"]:
                xfo_status = "PASSED"
                xfo_notes = f"X-Frame-Options is set to {xfo_value}."
            else:
                xfo_status = "WARNING"
                xfo_notes = f"X-Frame-Options is present but set to an unusual value: {xfo_value}."

            security_findings["xfo_status"] = xfo_status
            security_findings["xfo_value"] = xfo_value
            security_findings["xfo_notes"] = xfo_notes
        else:
            security_findings["xfo_status"] = "FAILED"
            security_findings["xfo_notes"] = "X-Frame-Options (XFO) header is missing."

    # 3. Compile the single result object
    results.append(
        {
            "url": url,
            "status_code": status_code if status_code else 0,
            "http_status": http_status,
            "error_message": error_message,
            "security_findings": security_findings,
        }
    )

    return results


def lambda_handler(event, context):
    """
    Handles the API Gateway request.
    """

    # 1. Parse the request body (comes as a JSON string in the event body)
    try:
        body = json.loads(event.get("body", "{}"))
        target_url = body.get("url", "").strip()
        checks_list = body.get("checks", [])

        if not target_url:
            return {
                "statusCode": 400,
                # CRITICAL: Adding CORS headers to error response
                "headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Content-Type": "application/json",
                },
                "body": json.dumps({"error": "Missing target URL in request body."}),
            }

    except json.JSONDecodeError:
        return {
            "statusCode": 400,
            # CRITICAL: Adding CORS headers to error response
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Content-Type": "application/json",
            },
            "body": json.dumps({"error": "Invalid JSON format in request body."}),
        }

    # 2. Run the scan
    scan_results = scan_url(target_url, checks_list)

    # 3. Construct the final response with required CORS headers
    return {
        "statusCode": 200,
        # CRITICAL: Adding CORS headers to the successful response
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Content-Type": "application/json",
        },
        "body": json.dumps({"results": scan_results}),
    }
