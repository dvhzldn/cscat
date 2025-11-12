import json
import dns.resolver

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


DNS_CHECKS = ["SPF", "DMARC", "DKIM", "DNSSEC"]


def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return respond(200, {"message": "CORS preflight OK"})

    try:
        body = json.loads(event.get("body") or "{}")
        domain = body.get("domain")
        if not domain:
            return respond(400, {"error": "Missing domain in request body."})

        results = {}

        # SPF
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            spf_records = [
                r.to_text().strip('"')
                for r in answers
                if r.to_text().startswith('"v=spf')
            ]
            if not spf_records:
                results["SPF"] = {
                    "status": "FAILED",
                    "records_found": [],
                    "notes": "No SPF record found.",
                }
            else:
                results["SPF"] = {
                    "status": "PASSED",
                    "records_found": spf_records,
                    "notes": "SPF record present.",
                }
        except Exception as e:
            results["SPF"] = {"status": "ERROR", "notes": str(e)}

        # DMARC
        try:
            dmarc_domain = "_dmarc." + domain
            answers = dns.resolver.resolve(dmarc_domain, "TXT")
            dmarc_records = [
                r.to_text().strip('"')
                for r in answers
                if r.to_text().startswith('"v=DMARC')
            ]
            if not dmarc_records:
                results["DMARC"] = {
                    "status": "FAILED",
                    "records_found": [],
                    "notes": "No DMARC record found.",
                }
            else:
                results["DMARC"] = {
                    "status": "PASSED",
                    "records_found": dmarc_records,
                    "notes": "DMARC record present.",
                }
        except Exception as e:
            results["DMARC"] = {"status": "ERROR", "notes": str(e)}

        # DKIM (common selector)
        try:
            selector = "default"
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, "TXT")
            dkim_records = [r.to_text().strip('"') for r in answers]
            if not dkim_records:
                results["DKIM"] = {
                    "status": "FAILED",
                    "records_found": [],
                    "notes": "No DKIM record found.",
                }
            else:
                results["DKIM"] = {
                    "status": "PASSED",
                    "records_found": dkim_records,
                    "notes": "DKIM record present.",
                }
        except Exception as e:
            results["DKIM"] = {"status": "ERROR", "notes": str(e)}

        # DNSSEC (check for DS record)
        try:
            answers = dns.resolver.resolve(domain, "DS")
            results["DNSSEC"] = {
                "status": "PASSED",
                "records_found": [r.to_text() for r in answers],
                "notes": "DNSSEC DS record found.",
            }
        except dns.resolver.NoAnswer:
            results["DNSSEC"] = {
                "status": "FAILED",
                "records_found": [],
                "notes": "No DS record found; DNSSEC not enabled.",
            }
        except Exception as e:
            results["DNSSEC"] = {"status": "ERROR", "notes": str(e)}

        return respond(200, {"results": results})

    except Exception as e:
        return respond(200, {"results": {"error": f"Internal error: {str(e)}"}})
