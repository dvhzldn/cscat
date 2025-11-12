import json
import requests
import re
from urllib.parse import urlparse, urlunparse

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


def _check_hsts_security(hsts_value: str) -> bool:
    """Checks HSTS header for max-age >= 1 year and includeSubDomains."""
    if not hsts_value:
        return False

    value_lower = hsts_value.lower()

    if "includesubdomains" not in value_lower:
        return False

    match = re.search(r"max-age=(\d+)", value_lower)

    if match:
        try:
            max_age = int(match.group(1))
            return max_age >= 31536000
        except ValueError:
            return False

    return False


HTTP_HEADERS_TO_CHECK = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Set-Cookie",
]


def _check_csp(csp_value: str) -> dict:
    """Performs an in-depth check of Content-Security-Policy directives."""
    findings = []

    if not csp_value:
        return {"status": "FAILED", "notes": "Missing Content-Security-Policy."}

    critical_directives = {
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
    }

    if "'unsafe-inline'" in csp_value.lower():
        findings.append(
            "WARNING: CSP allows 'unsafe-inline'. This weakens XSS protection."
        )
    if "'unsafe-eval'" in csp_value.lower():
        findings.append(
            "WARNING: CSP allows 'unsafe-eval'. This weakens XSS protection."
        )

    for directive, safe_values in critical_directives.items():
        match = re.search(rf"\b{directive}\s+([^;]+)", csp_value, re.IGNORECASE)

        if not match:
            findings.append(f"WARNING: Missing restrictive '{directive}' directive.")
        else:
            value = match.group(1).strip()
            if not any(sv in value.lower() for sv in safe_values):
                findings.append(f"WARNING: Unsafe value for '{directive}': {value}")

    if not findings:
        return {"status": "PASSED", "notes": "CSP is present and appears robust."}
    elif len(findings) < 2:
        return {"status": "WARNING", "notes": "; ".join(findings)}
    else:
        return {
            "status": "FAILED",
            "notes": "Multiple critical CSP weaknesses found: " + "; ".join(findings),
        }


def _check_cookie_security(set_cookie_headers: list) -> dict:
    """Checks 'Set-Cookie' headers for Secure, HttpOnly, and SameSite flags."""
    if not set_cookie_headers:
        return {"status": "INFO", "notes": "No 'Set-Cookie' headers found."}

    vulnerable_cookies = []

    for cookie_string in set_cookie_headers:
        name_match = re.match(r"([^=]+)=", cookie_string)
        cookie_name = name_match.group(1) if name_match else "Unnamed Cookie"

        if "secure" not in cookie_string.lower():
            vulnerable_cookies.append(
                f"'{cookie_name}' is missing the 'Secure' flag (Critical)."
            )
        if "httponly" not in cookie_string.lower():
            vulnerable_cookies.append(
                f"'{cookie_name}' is missing the 'HttpOnly' flag (High)."
            )

        samesite_match = re.search(
            r"SameSite=(Strict|Lax|None)", cookie_string, re.IGNORECASE
        )
        if not samesite_match:
            vulnerable_cookies.append(
                f"'{cookie_name}' is missing the 'SameSite' flag (High)."
            )
        elif (
            samesite_match.group(1).lower() == "none"
            and "secure" not in cookie_string.lower()
        ):
            vulnerable_cookies.append(
                f"'{cookie_name}' has SameSite=None but lacks 'Secure' (Critical)."
            )

    if not vulnerable_cookies:
        return {"status": "PASSED", "notes": "All 'Set-Cookie' headers appear secure."}

    return {
        "status": "FAILED",
        "notes": "Vulnerable Cookies Found: " + " | ".join(vulnerable_cookies),
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
            "notes": pass_note if condition(value) else fail_note,
        }

    for header_name, condition, pass_note, fail_note in [
        (
            "Strict-Transport-Security",
            _check_hsts_security,
            "HSTS configured properly with long max-age and includeSubDomains.",
            "Missing HSTS or max-age is too short or missing includeSubDomains.",
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

    if "Content-Security-Policy" in checks:
        csp_header = headers.get("Content-Security-Policy")
        findings["Content-Security-Policy"] = _check_csp(csp_header or "")

    if "Set-Cookie" in checks:
        try:
            set_cookie_headers = resp.raw.headers.getlist("Set-Cookie")
        except AttributeError:
            set_cookie_headers = resp.headers.get("Set-Cookie", "").split(",")

        findings["Cookie-Security"] = _check_cookie_security(set_cookie_headers)

    for info_header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
        if headers.get(info_header):
            findings[info_header] = {
                "status": "INFO",
                "value": headers[info_header],
                "notes": f"Server information disclosed via '{info_header}' header. Consider suppression.",
            }

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
        body = json.loads(event.get("body") or "{}")
        url = body.get("url")
        checks = body.get("checks") or HTTP_HEADERS_TO_CHECK

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
            headers = {k: v for k, v in response.headers.items()}
        except requests.exceptions.RequestException as e:
            return respond(
                200, {"results": {"error": f"Failed to fetch URL: {str(e)}"}}
            )
        except Exception as e:
            return respond(200, {"results": {"error": f"Unexpected error: {str(e)}"}})

        results = {}
        for header in checks:
            value = headers.get(header)
            results[header] = {
                "status": "PASSED" if value else "FAILED",
                "value": value or "Not set",
                "notes": f"{header} is {'present' if value else 'missing'}.",
            }

        return respond(200, {"results": results, "full_headers": headers})

    except Exception as e:
        return respond(200, {"results": {"error": f"Internal error: {str(e)}"}})
