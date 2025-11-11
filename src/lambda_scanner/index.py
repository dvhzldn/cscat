import json
import requests
from urllib.parse import urlparse, urlunparse
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

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


def scan_url(url: str, checks: list[str]) -> list[dict]:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        return [
            {"url": url, "error_message": "Invalid domain", "security_findings": {}}
        ]

    cleaned = urlunparse(
        ("https", parsed.netloc.split(":")[0], parsed.path or "/", "", "", "")
    )

    try:
        resp = requests.get(cleaned, timeout=10)
    except requests.exceptions.RequestException as e:
        return [{"url": cleaned, "error_message": str(e), "security_findings": {}}]

    headers = resp.headers
    findings = {}

    def check_header(name, condition, pass_note, fail_note):
        value = headers.get(name)
        if not value:
            return {"status": "FAILED", "value": None, "notes": fail_note}
        return {
            "status": "PASSED" if condition(value) else "WARNING",
            "value": value,
            "notes": pass_note,
        }

    for header_name, condition, pass_note, fail_note in [
        (
            "Strict-Transport-Security",
            lambda v: "max-age" in v and "includeSubDomains" in v,
            "HSTS configured properly.",
            "Missing or incomplete HSTS header.",
        ),
        (
            "X-Frame-Options",
            lambda v: v.upper() in ["DENY", "SAMEORIGIN"],
            "Proper X-Frame-Options value.",
            "Missing or unsafe X-Frame-Options.",
        ),
        (
            "X-Content-Type-Options",
            lambda v: v.lower() == "nosniff",
            "Prevents MIME-type sniffing.",
            "Missing or invalid X-Content-Type-Options.",
        ),
        (
            "Content-Security-Policy",
            lambda v: bool(v.strip()),
            "CSP present.",
            "Missing Content-Security-Policy.",
        ),
        (
            "Referrer-Policy",
            lambda v: v
            in [
                "no-referrer",
                "same-origin",
                "strict-origin",
                "strict-origin-when-cross-origin",
            ],
            "Valid Referrer-Policy.",
            "Missing or weak Referrer-Policy.",
        ),
        (
            "Permissions-Policy",
            lambda v: bool(v.strip()),
            "Permissions-Policy header present.",
            "Missing Permissions-Policy.",
        ),
    ]:
        if header_name in checks:
            findings[header_name] = check_header(
                header_name, condition, pass_note, fail_note
            )

    for header, expected in {
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
    }.items():
        if header in checks:
            findings[header] = check_header(
                header,
                lambda v: v.lower() == expected,
                f"{header} correctly set.",
                f"Missing or incorrect {header}.",
            )

    return [
        {
            "url": cleaned,
            "status_code": resp.status_code,
            "security_findings": findings,
            "full_headers": dict(headers),
        }
    ]


def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return respond(200, {"message": "CORS preflight OK"})

    try:
        try:
            body = json.loads(event.get("body") or "{}")
        except json.JSONDecodeError:
            return respond(400, {"error": "Invalid JSON in request body"})

        url = body.get("url")
        checks = body.get("checks", [])

        if not url:
            return respond(400, {"error": "Missing URL in request body"})

        try:
            results = scan_url(url, checks)
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            results = [
                {
                    "url": url,
                    "error_message": f"Scan failed: {str(e)}",
                    "security_findings": {},
                }
            ]

        return respond(200, {"results": results})

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return respond(500, {"error": f"Internal server error: {str(e)}"})
