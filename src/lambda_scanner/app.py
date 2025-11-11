import requests
import boto3
import json
import os
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize S3 client (boto3 automatically handles credentials from the IAM role)
s3_client = boto3.client("s3")

# --- CONFIGURATION ---
SCAN_TARGETS = [
    {"name": "Google", "url": "https://www.google.com"},
    # Good target that likely has security headers
    {"name": "GitHub", "url": "https://github.com"},
    # Example target that might be missing some headers
    {"name": "Example Domain", "url": "http://example.com"},
    {
        "name": "Broken Link Test",
        "url": "https://this-will-definitely-fail-404-332.com",
    },
]
S3_BUCKET_NAME = os.environ.get("REPORT_BUCKET_NAME")

# Headers to specifically check for
SECURITY_HEADERS = ["Strict-Transport-Security", "X-Frame-Options"]
# --- END CONFIGURATION ---


def analyze_security_headers(headers):
    """
    Checks for the presence and basic validity of critical security headers.
    Returns a dictionary of findings.
    """
    findings = {}
    normalized_headers = {k.lower(): v for k, v in headers.items()}

    # 1. Strict-Transport-Security (HSTS) Check
    hsts_header = normalized_headers.get("strict-transport-security")
    if hsts_header:
        findings["hsts_status"] = "PASSED"
        findings["hsts_value"] = hsts_header
    else:
        findings["hsts_status"] = "FAILED"
        findings["hsts_notes"] = "Missing Strict-Transport-Security (HSTS) header."

    # 2. X-Frame-Options Check (for Clickjacking prevention)
    xfo_header = normalized_headers.get("x-frame-options")
    if xfo_header:
        # Check if the value is one of the secure options
        xfo_value = xfo_header.upper().strip()
        if xfo_value in ["DENY", "SAMEORIGIN"]:
            findings["xfo_status"] = "PASSED"
        else:
            findings["xfo_status"] = "WARNING"
        findings["xfo_value"] = xfo_header
    else:
        findings["xfo_status"] = "FAILED"
        findings["xfo_notes"] = (
            "Missing X-Frame-Options header (Vulnerable to Clickjacking)."
        )

    return findings


def perform_check(target):
    """
    Performs a single check (HTTP HEAD request) on a target URL and runs header analysis.
    """
    url = target["url"]
    name = target["name"]

    result = {
        "target_name": name,
        "url": url,
        "http_status": "FAILED",
        "status_code": None,
        "security_findings": {},
        "error_message": None,
        "check_time": datetime.now().isoformat(),
    }

    try:
        # Use a HEAD request (lightweight) and follow redirects
        response = requests.head(url, timeout=5, allow_redirects=True)

        result["status_code"] = response.status_code

        if 200 <= response.status_code < 400:
            result["http_status"] = "PASSED"

            # --- NEW: Run Security Header Analysis ---
            result["security_findings"] = analyze_security_headers(response.headers)
            # ----------------------------------------

        elif 400 <= response.status_code < 600:
            result["http_status"] = "WARNING"
            result["error_message"] = f"HTTP Error {response.status_code}"
        else:
            result["http_status"] = "UNKNOWN"
            result["error_message"] = "Non-standard HTTP status code"

    except requests.exceptions.RequestException as e:
        result["error_message"] = str(e)

    logger.info(f"Check result for {name}: HTTP Status={result['http_status']}")
    return result


def generate_report(results):
    """
    Compiles the scan results into a structured report dictionary.
    """
    report = {
        "scan_timestamp": datetime.now().isoformat(),
        "total_targets": len(SCAN_TARGETS),
        "results": results,
    }
    return report


def upload_to_s3(report_content):
    """
    Uploads the JSON report content to the S3 report bucket.
    """
    if not S3_BUCKET_NAME:
        logger.error(
            "S3_BUCKET_NAME environment variable is not set. Cannot upload report."
        )
        return False

    # Define the S3 key (file path) using the timestamp
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    s3_key = f"scan-reports/report-{timestamp}.json"

    try:
        json_report = json.dumps(report_content, indent=2)

        s3_client.put_object(
            Bucket=S3_BUCKET_NAME,
            Key=s3_key,
            Body=json_report,
            ContentType="application/json",
        )
        logger.info(f"Successfully uploaded report to s3://{S3_BUCKET_NAME}/{s3_key}")
        return True
    except Exception as e:
        logger.error(f"Failed to upload report to S3: {e}")
        return False


# --- Lambda Handler Function ---


def lambda_handler(event, context):
    """
    The main entry point for the AWS Lambda function.
    """
    logger.info("Starting scheduled security scan.")

    # 1. Perform all checks
    all_results = [perform_check(target) for target in SCAN_TARGETS]

    # 2. Generate the final report
    final_report = generate_report(all_results)

    # 3. Upload the report to S3
    upload_success = upload_to_s3(final_report)

    # Return a summary of the execution
    return {
        "statusCode": 200,
        "body": {
            "message": "Security scan completed with header checks.",
            "total_checks": len(all_results),
            "s3_upload_status": "Success" if upload_success else "Failure",
            "bucket": S3_BUCKET_NAME,
        },
    }
