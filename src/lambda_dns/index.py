import dns.resolver
import json
from collections import defaultdict
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
            return respond(400, {"error": "Invalid JSON in request body"})

        target_input = body.get("url") or body.get("domain")
        if not target_input:
            return respond(400, {"error": "Missing domain or URL in request body"})

        domain = urlparse(target_input).netloc or target_input
        domain = domain.split(":")[0].strip()
        if not domain:
            return respond(400, {"error": "Could not extract a valid domain"})

        try:
            results = perform_dns_security_scan(domain)
        except Exception as e:
            results = {"error": f"DNS scan failed: {str(e)}"}

        return respond(200, {"domain": domain, "results": results})

    except Exception as e:
        return respond(500, {"error": f"Internal server error: {str(e)}"})


def perform_dns_security_scan(domain):
    scan_results = defaultdict(dict)

    try:
        spf_answers = dns.resolver.resolve(domain, "TXT")
        spf_records = [
            r.to_text() for r in spf_answers if r.to_text().startswith('"v=spf1')
        ]
        scan_results["SPF"]["records_found"] = spf_records
        scan_results["SPF"]["record_count"] = len(spf_records)
        if len(spf_records) > 1:
            scan_results["SPF"]["error"] = "Multiple SPF records found (RFC violation)."
        elif len(spf_records) == 1 and not (
            "-all" in spf_records[0] or "~all" in spf_records[0]
        ):
            scan_results["SPF"]["warning"] = "Missing or improper SPF fail mechanism."
    except dns.resolver.NoAnswer:
        scan_results["SPF"]["status"] = "No SPF TXT record found."
    except Exception as e:
        scan_results["SPF"]["error"] = str(e)

    try:
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_answers = dns.resolver.resolve(dmarc_domain, "TXT")
        dmarc_records = [
            r.to_text() for r in dmarc_answers if r.to_text().startswith('"v=DMARC1')
        ]
        scan_results["DMARC"]["records_found"] = dmarc_records
        if dmarc_records:
            record = dmarc_records[0]
            if "p=reject" in record:
                scan_results["DMARC"]["policy_strength"] = "reject (strongest)"
            elif "p=quarantine" in record:
                scan_results["DMARC"]["policy_strength"] = "quarantine (medium)"
            elif "p=none" in record:
                scan_results["DMARC"]["policy_strength"] = "none (monitoring only)"
    except dns.resolver.NoAnswer:
        scan_results["DMARC"]["status"] = "No DMARC TXT record found."
    except Exception as e:
        scan_results["DMARC"]["error"] = str(e)

    try:
        selector = f"default._domainkey.{domain}"
        dkim_answers = dns.resolver.resolve(selector, "TXT")
        record = dkim_answers[0].to_text()
        key_length = len(record.split("p=")[1].strip('"')) * 8
        scan_results["DKIM"]["status"] = "Common selector found."
        scan_results["DKIM"]["estimated_key_length"] = f"{key_length} bits (approx.)"
    except dns.resolver.NoAnswer:
        scan_results["DKIM"]["status"] = "Common DKIM selector 'default' not found."
    except Exception as e:
        scan_results["DKIM"]["error"] = str(e)

    try:
        dnssec_answers = dns.resolver.resolve(domain, "DS")
        scan_results["DNSSEC"]["status"] = "DS record found (DNSSEC likely enabled)."
        scan_results["DNSSEC"]["records"] = [r.to_text() for r in dnssec_answers]
    except dns.resolver.NoAnswer:
        scan_results["DNSSEC"][
            "status"
        ] = "No DS record found (DNSSEC likely disabled)."
    except Exception as e:
        scan_results["DNSSEC"]["error"] = str(e)

    return dict(scan_results)
