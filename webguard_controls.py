"""Passive HTTP evidence and scoring based on explicitly evaluated controls."""
import re
from urllib.parse import urlsplit

CONTROLS = {
    "HTTPS": (25, {"HTTP_ONLY"}),
    "HSTS": (15, {"HSTS_INVALID", "HSTS_MISSING"}),
    "CSP": (20, {"CSP_MISSING", "CSP_UNSAFE_EVAL"}),
    "Framing restrictions": (15, {"FRAME_POLICY_MISSING"}),
    "MIME sniffing protection": (15, {"NOSNIFF_MISSING"}),
    "Referrer policy": (10, {"REFERRER_POLICY_MISSING"}),
}

SAFE_HEADERS = {
    "content-type", "content-encoding", "x-content-type-options", "referrer-policy",
    "strict-transport-security", "content-security-policy", "content-security-policy-report-only",
    "x-frame-options", "set-cookie", "access-control-allow-origin",
    "access-control-allow-credentials", "allow", "www-authenticate", "server", "x-powered-by",
}


def capture_http(headers):
    evidence = {}
    for name in sorted(SAFE_HEADERS):
        values = headers.get_all(name, [])
        if not values:
            continue
        if name == "x-content-type-options":
            evidence[name] = "nosniff" if len(values) == 1 and values[0].strip().lower() == "nosniff" else "Present"
        elif name == "allow":
            methods = {method.strip() for value in values for method in value.split(",")}
            known = methods & {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}
            evidence[name] = ", ".join(sorted(known)) or "Present"
        elif name == "content-type":
            media = values[0].partition(";")[0].strip().lower()
            evidence[name] = media if re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", media) else "Present"
        else:
            evidence[name] = "Present"
    return evidence


def configuration_score(report):
    if report["response_kind"] != "response" or not 200 <= report["status"] < 300:
        return None
    secure = urlsplit(report["url"]).scheme == "https"
    page = report["html_status"] != "not_applicable"
    skipped = set()
    if not secure:
        skipped.add("HSTS")
    if not page:
        skipped.update({"CSP", "Framing restrictions", "Referrer policy"})
    ids = {item["id"] for item in report["findings"]}
    checks = []
    for name, (weight, failures) in CONTROLS.items():
        if name not in skipped:
            failed = sorted(ids & failures)
            checks.append({"name": name, "weight": weight, "earned": 0 if failed else weight, "reasons": failed})
    total = sum(check["weight"] for check in checks)
    return {"value": round(100 * sum(check["earned"] for check in checks) / total),
            "checks": checks, "possible": total}


def control_coverage(report):
    """Describe the observation scope without treating absent evidence as a pass."""
    success = report["response_kind"] == "response" and 200 <= report["status"] < 300
    html = report["html_status"]
    limited = report.get("body_truncated") or html == "partial"
    status = {
        "Transport URL": "observed",
        "TLS certificate and negotiated protocol": "observed" if report.get("tls") else "not_applicable",
        "Response headers and observed cookies": "observed" if success else "response_only",
        "HTML forms and resource references": (
            "partial" if limited and html in {"analyzed", "partial"} else
            "observed" if html == "analyzed" else
            "not_applicable" if html == "not_applicable" else "unavailable"
        ),
        "Authentication and authorization workflows": "outside_scope",
        "Active injection and exploit verification": "outside_scope",
    }
    return status
