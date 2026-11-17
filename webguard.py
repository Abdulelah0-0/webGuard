#!/usr/bin/env python3
"""WebGuard: a low-impact, single-page website security configuration checker.

Requires Python 3.10+ and only the standard library. Use on sites you own or
have explicit permission to assess. This is not a penetration-testing tool.
"""

from __future__ import annotations

import argparse
import json
import math
import multiprocessing as mp
import time
import re
import socket
import unicodedata
import ssl
import sys
from collections import Counter
from datetime import datetime, timezone
from http.client import HTTPException, HTTPSConnection
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlsplit, urlunsplit
from webguard_controls import capture_http, configuration_score, control_coverage
from webguard_english import LIMITATIONS
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


VERSION = "2.2.0"
MAX_BYTES = 1_000_000
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
SEVERITY_AR = {"high": "مرتفع", "medium": "متوسط", "low": "منخفض", "info": "معلومة"}


class NoRedirect(HTTPRedirectHandler):
    """Do not silently send requests to a host outside the authorized URL."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class PageInspector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.base = None
        self.resources = []
        self.title_parts = []
        self.in_title = False
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        properties = dict(attrs)
        if tag == "title":
            self.in_title = True
        if tag == "base" and self.base is None and properties.get("href") is not None:
            self.base = properties["href"]
        if tag == "form":
            self.current_form = {
                "method": (properties.get("method") or "get").lower(),
                "action": properties.get("action") or "",
                "password": False,
            }
            self.forms.append(self.current_form)
        elif tag == "input" and self.current_form is not None:
            if (properties.get("type") or "").lower() == "password":
                self.current_form["password"] = True
        if tag in ("script", "iframe", "img", "audio", "video", "source"):
            src = properties.get("src")
            if src:
                self.resources.append((tag, src))
        if tag in ("img", "source") and properties.get("srcset"):
            self.resources.extend((tag, ref) for ref in srcset_urls(properties["srcset"]))
        if tag == "link" and set((properties.get("rel") or "").lower().split()) & {
            "stylesheet", "preload", "modulepreload"
        }:
            href = properties.get("href")
            if href:
                self.resources.append((tag, href))

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        elif tag == "form":
            self.current_form = None

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)


def srcset_urls(value: str):
    """Read candidate URLs, preserving commas inside URLs such as data URLs."""
    while value := value.lstrip(" ,\t\r\n\f"):
        match = re.match(r"[^\s]+", value)
        if not match:
            break
        url = match.group()
        yield url.rstrip(",")
        value = value[match.end():]
        if not url.endswith(","):
            descriptor = re.match(r"(?:[^,(]|\([^)]*\))*", value)
            value = value[descriptor.end():]


def clean_text(value: str, limit: int = 200) -> str:
    return "".join(ch for ch in value
                   if ch.isprintable() and unicodedata.category(ch) != "Cf")[:limit]


def public_url(url: str, hide_path: bool = False) -> str:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    netloc = host + (f":{parts.port}" if parts.port is not None else "")
    return clean_text(urlunsplit((parts.scheme, netloc, "/" if hide_path else parts.path or "/", "", "")), 2048)


def normalize_url(value: str) -> str:
    value = value.strip()
    if value and "://" not in value:
        value = "https://" + value
    if any(ch.isspace() or not ch.isprintable() for ch in value) or "\\" in value:
        raise ValueError("الرابط يحتوي على محارف غير صالحة.")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise ValueError("عنوان الموقع أو المنفذ غير صالح.") from None
    if parts.scheme not in ("http", "https") or not parts.hostname or port == 0:
        raise ValueError("أدخل رابط HTTP أو HTTPS بمنفذ صالح.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("لا تضع بيانات دخول ضمن الرابط.")
    try:
        host = parts.hostname.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("اسم الموقع غير صالح.") from None
    if ":" in host:
        host = f"[{host}]"
    elif not re.fullmatch(r"[a-zA-Z0-9_.-]+", host):
        raise ValueError("اسم الموقع غير صالح.")
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="/?%:@!$&'()*+,;=-._~")
    return urlunsplit((parts.scheme, host + (f":{port}" if port else ""), path, query, ""))


def finding(level: str, key: str, message: str, fix: str, evidence: str = "", **details) -> dict:
    return {
        "severity": level, "id": key, "message": message, "details": details,
        "recommendation": fix, "evidence": evidence or EVIDENCE.get(key, key),
        "severity_reason": SEVERITY_REASONS.get(key, SEVERITY_DEFAULTS[level]),
    }


SEVERITY_DEFAULTS = {
    "high": "قد يؤثر مباشرةً على سرية الاتصال أو البيانات.",
    "medium": "قد يقلل الحماية المتوفرة للصفحة بحسب إعداد التطبيق.",
    "low": "فرصة لتحسين الإعدادات وتقليل التعرض.",
    "info": "معلومة لتفسير الاستجابة أو حدود الفحص.",
}
EVIDENCE = {
    "HTTP_ONLY": "مخطط الرابط HTTP",
    "REFERRER_POLICY_MISSING": "ترويسة Referrer-Policy غائبة",
    "NOSNIFF_MISSING": "قيمة nosniff غير موجودة في X-Content-Type-Options",
    "BANNER_SERVER": "ترويسة Server موجودة",
    "BANNER_X_POWERED_BY": "ترويسة X-Powered-By موجودة",
    "COOKIE_NO_SECURE": "السمة Secure غائبة من Set-Cookie",
    "COOKIE_NO_HTTPONLY": "السمة HttpOnly غائبة من كوكي جلسة محتمل بحسب الاسم",
    "COOKIE_NO_SAMESITE": "السمة SameSite غائبة من كوكي جلسة محتمل بحسب الاسم",
    "PASSWORD_FORM_INSECURE": "رُصد حقل كلمة مرور في نموذج يعتمد على HTTP",
    "MIXED_CONTENT": "يشير HTML إلى موارد HTTP داخل صفحة HTTPS",
    "REDIRECT_NOT_FOLLOWED": "رد HTTP للتحويل يحمل ترويسة Location",
}

SEVERITY_REASONS = {
    "TLS_CERT_EXPIRING": "انتهاء الشهادة قريبًا قد يقطع وصول المستخدمين.",
    "HSTS_MISSING": "المتصفح لا يتلقى سياسة تلزمه باستخدام HTTPS في الزيارات التالية.",
    "HSTS_INVALID": "السياسة الحالية لا تفرض استخدام HTTPS في الزيارات التالية.",
    "FRAME_POLICY_MISSING": "قد يكون تضمين الصفحة متاحًا دون قيود مناسبة.",
}


def analyze(url: str, status: int, headers, body: bytes, *, truncated=False, hide_path=False) -> dict:
    """Pure analysis; it never sends an HTTP request."""
    result = {
        "url": public_url(url, hide_path),
        "schema_version": 3,
        "app_version": VERSION,
        "response_kind": ("redirect" if status in (301, 302, 303, 307, 308) else
                          "error" if status >= 400 else "response"),
        "html_status": "not_applicable",
        "body_truncated": truncated,
        "body_bytes_analyzed": len(body),
        "status": status,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "title": "",
        "findings": [],
        "limitations_en": [],
        "limitations": [
            "فحص الصفحة المطلوبة فقط، دون تتبع الروابط أو إعادة التوجيه.",
            "النتائج مؤشرات إعدادات أمنية، وليست إثباتًا لاستغلال ثغرة.",
            "لا يشمل اختبار SQL Injection أو XSS أو صلاحيات الحسابات.",
        ],
    }
    result["limitations_en"] = [LIMITATIONS[key] for key in ("scope", "interpretation", "coverage")]
    issues = result["findings"]
    secure = urlsplit(url).scheme == "https"
    content_type = (headers.get("Content-Type") or "").lower()
    is_html = "text/html" in content_type or "application/xhtml+xml" in content_type

    if truncated:
        result["limitations"].append("توقف تحليل الرد عند الحد الأقصى لحجم المحتوى.")
        result["limitations_en"].append(LIMITATIONS["body_limit"])
    if status >= 400:
        result["limitations"].append("النتائج تخص استجابة الخطأ التي أرجعها الخادم.")
        result["limitations_en"].append(LIMITATIONS["error_response"])
    if not secure:
        issues.append(finding("high", "HTTP_ONLY", "الصفحة تستخدم HTTP غير المشفّر.",
                              "فعّل HTTPS وأعد توجيه HTTP إلى HTTPS."))
    else:
        values = headers.get_all("Strict-Transport-Security", [])
        max_age = [part.partition("=")[2].strip().strip('"') for part in
                   (values[0].split(";") if values else [])
                   if part.partition("=")[0].strip().lower() == "max-age"]
        valid = (len(max_age) == 1 and bool(re.fullmatch(r"[0-9]+", max_age[0]))
                 and bool(max_age[0].lstrip("0")))
        if not valid:
            issues.append(finding(
                "medium", "HSTS_INVALID" if values else "HSTS_MISSING",
                "ترويسة HSTS غير موجودة أو لا تحتوي على max-age موجبة وصالحة.",
                "اضبط max-age بعد التأكد من جاهزية HTTPS.",
                "Strict-Transport-Security: " + ("max-age معطلة أو غير صالحة" if values else "غائبة"),
            ))

    if is_html:
        policies = []
        for value in headers.get_all("Content-Security-Policy", []):
            for policy in value.split(","):
                directives = {}
                for directive in policy.split(";"):
                    tokens = directive.split()
                    if tokens:
                        directives.setdefault(tokens[0].lower(), tokens[1:])
                if directives:
                    policies.append(directives)
        if not policies:
            report_only = bool(headers.get("Content-Security-Policy-Report-Only"))
            issues.append(finding("medium", "CSP_MISSING", "لا توجد سياسة Content-Security-Policy مفروضة.",
                                  "ضع CSP مناسبة واختبرها قبل فرضها على الإنتاج.",
                                  "توجد سياسة Report-Only" if report_only else "ترويسة CSP المفروضة غائبة",
                                  report_only="yes" if report_only else "no"))
        if policies and all(
            "'unsafe-eval'" in [source.lower() for source in
                                policy.get("script-src", policy.get("default-src", []))]
            for policy in policies
        ):
            issues.append(finding("medium", "CSP_UNSAFE_EVAL", "سياسة CSP تسمح بتنفيذ نصوص كسكربت.",
                                  "استبدل تنفيذ النصوص ككود، واختبر السياسة قبل إزالة unsafe-eval.",
                                  "تحتوي سياسات CSP المفروضة على unsafe-eval ضمن script-src أو default-src."))
        frame_values = {
            token.strip().upper() for value in headers.get_all("X-Frame-Options", [])
            for token in value.split(",")
        }
        frame_sources = [policy.get("frame-ancestors", []) for policy in policies]
        csp_frame = any(
            sources and ("*" not in sources) and any(
                token.lower() in {"'none'", "'self'"} or re.fullmatch(
                    r"(?:https?://)?(?:\*\.)?[a-z0-9.-]+(?::[0-9]+)?(?:/[^\s]*)?",
                    token, re.I
                )
                for token in sources
            ) for sources in frame_sources
        )
        if not csp_frame and frame_values not in ({"DENY"}, {"SAMEORIGIN"}):
            issues.append(finding("medium", "FRAME_POLICY_MISSING",
                                  "لم تُرصد سياسة تقييد تضمين الصفحة بقيمة معروفة.",
                                  "استخدم CSP frame-ancestors أو X-Frame-Options بحسب الحاجة.",
                                  "لم يُرصد توجيه مقيّد أو DENY أو SAMEORIGIN متسقة"))
        if not headers.get("Referrer-Policy"):
            issues.append(finding("low", "REFERRER_POLICY_MISSING", "ترويسة Referrer-Policy غير موجودة.",
                                  "حدّد سياسة إحالة مناسبة، مثل strict-origin-when-cross-origin."))

    if (headers.get("X-Content-Type-Options") or "").lower().strip() != "nosniff":
        issues.append(finding("low", "NOSNIFF_MISSING", "لا توجد X-Content-Type-Options: nosniff.",
                              "أضف الترويسة مع أنواع محتوى صحيحة."))

    for header in ("Server", "X-Powered-By"):
        if headers.get(header):
            issues.append(finding("info", f"BANNER_{header.upper().replace('-', '_')}",
                                  f"الخادم يعلن ترويسة {header} التي قد تكشف تفاصيل تقنية.",
                                  "قلّل الإفصاح عن تفاصيل النسخ والتقنيات إن أمكن."))

    origins = headers.get_all("Access-Control-Allow-Origin", [])
    credentials = headers.get_all("Access-Control-Allow-Credentials", [])
    if [value.strip() for value in origins] == ["null"] and [value.strip() for value in credentials] == ["true"]:
        issues.append(finding("medium", "CORS_NULL_CREDENTIALS",
                              "إعداد CORS يسمح بالأصل null مع بيانات الاعتماد.",
                              "احذف الأصل null وحدّد قائمة بأصول HTTPS المطلوبة لهذا المسار.",
                              "Access-Control-Allow-Origin: null + Access-Control-Allow-Credentials: true"))
    cookies = headers.get_all("Set-Cookie", []) or []
    if len(cookies) > 200:
        result["limitations"].append("اقتصر فحص الكوكيز على أول 200 ترويسة Set-Cookie.")
        result["limitations_en"].append(LIMITATIONS["cookie_limit"])
    for raw in cookies[:200]:
        pair, *attributes = raw.split(";")
        name, separator, _ = pair.partition("=")
        name = name.strip()
        if not separator or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", name):
            continue
        # Never retain or print values from Set-Cookie.
        flags = {}
        for attribute in attributes:
            key, _, value = attribute.strip().partition("=")
            flags[key.strip().lower()] = value.strip().lower()
        same_site = flags.get("samesite")
        if same_site is not None and same_site not in {"lax", "strict", "none"}:
            issues.append(finding("low", "COOKIE_SAMESITE_INVALID",
                                  f"Cookie باسم {name!r} يحدد SameSite بقيمة غير معروفة.",
                                  "اختر Lax أو Strict أو None حسب آلية التطبيق.",
                                  "SameSite موجودة وقيمتها غير معروفة", cookie=name))
        if same_site == "none" and "secure" not in flags:
            issues.append(finding("medium", "COOKIE_NONE_REQUIRES_SECURE",
                                  f"Cookie باسم {name!r} يستخدم SameSite=None بدون Secure.",
                                  "أضف Secure أو اختر سياسة SameSite مناسبة.",
                                  "SameSite=None مع غياب Secure", cookie=name))
        sensitive = bool(re.search(r"session|sessid|auth|token|jwt|sid$", name, re.I))
        level = "medium" if sensitive else "low"
        if secure and "secure" not in flags:
            issues.append(finding(level, "COOKIE_NO_SECURE",
                                  f"Cookie باسم {name!r} لا يحدد Secure.",
                                  "استخدم Secure للكوكيز المرسلة عبر HTTPS.", cookie=name,
                                  session_like="yes" if sensitive else "no"))
        if sensitive and "httponly" not in flags:
            issues.append(finding("medium", "COOKIE_NO_HTTPONLY",
                                  f"Cookie جلسة محتمل باسم {name!r} لا يحدد HttpOnly.",
                                  "أضف HttpOnly لكوكيز الجلسات التي لا تحتاج JavaScript.", cookie=name))
        if sensitive and "samesite" not in flags:
            issues.append(finding("low", "COOKIE_NO_SAMESITE",
                                  f"Cookie جلسة محتمل باسم {name!r} لا يحدد SameSite صراحة.",
                                  "اختر Lax أو Strict حسب آلية التطبيق.", cookie=name))

    if status in (301, 302, 303, 307, 308):
        location = headers.get("Location")
        if location:
            try:
                target = urljoin(url, location)
                dest = public_url(target, hide_path) if urlsplit(target).scheme in {"http", "https"} else ""
            except ValueError:
                dest = ""
            display_destination = dest
            dest = dest or "وجهة غير قابلة للعرض"
            issues.append(finding("info", "REDIRECT_NOT_FOLLOWED",
                                  f"الاستجابة تحوّل إلى {dest} (لم نتبع التحويل).",
                                  "افحص الرابط النهائي بشكل مستقل بعد التأكد من التفويض.",
                                  destination=display_destination or "Unavailable"))

    if is_html and not body:
        result["html_status"] = "empty"
    if is_html and body:
        page = PageInspector()
        charset = headers.get_content_charset() or "utf-8"
        try:
            page.feed(body.decode(charset, errors="replace"))
            page.close()
            result["html_status"] = "partial" if truncated else "analyzed"
            base = urljoin(url, page.base or "")
            if not hide_path:
                result["title"] = clean_text(" ".join(" ".join(page.title_parts).split()), 140)
            if len(page.forms) > 200:
                result["limitations"].append("اقتصر فحص النماذج على أول 200 نموذج HTML.")
                result["limitations_en"].append(LIMITATIONS["form_limit"])
                result["html_status"] = "partial"
            for i, form in enumerate(page.forms[:200], start=1):
                action = urljoin(base, form["action"]) if form["action"] else url
                if form["password"] and form["method"].strip().lower() not in {"post", "dialog"}:
                    issues.append(finding("medium", "PASSWORD_FORM_GET",
                                          f"نموذج كلمة المرور رقم {i} يستخدم GET بحسب HTML.",
                                          "استخدم POST عبر HTTPS وتحقق من سلوك أزرار الإرسال.",
                                          f"نموذج كلمة المرور رقم {i} لا يصرّح باستخدام POST.", form=i))
                if form["password"] and (not secure or urlsplit(action).scheme == "http"):
                    issues.append(finding("high", "PASSWORD_FORM_INSECURE",
                                          f"نموذج كلمة المرور رقم {i} قد يرسل البيانات عبر اتصال غير مشفّر.",
                                          "تأكد أن الصفحة ووجهة إرسال النموذج تستخدمان HTTPS.", form=i))
            if secure:
                mixed = [(tag, ref) for tag, ref in page.resources
                         if urlsplit(urljoin(base, ref)).scheme == "http"]
                if mixed:
                    names = ", ".join(tag for tag, _ in mixed[:5])
                    issues.append(finding("medium", "MIXED_CONTENT",
                                          f"اكتُشف {len(mixed)} موردًا يشير إلى HTTP داخل صفحة HTTPS (مثل: {names}).",
                                          "استخدم HTTPS لكل الموارد، وراجع سياسة المتصفح تجاه المحتوى المختلط.",
                                          count=len(mixed), elements=names))
        except (LookupError, ValueError) as exc:
            result["html_status"] = "failed"
            result["limitations_en"].append(LIMITATIONS["html_error"].format(error=type(exc).__name__))
            result["limitations"].append(f"تعذر تحليل HTML بالكامل: {type(exc).__name__}.")

    issues.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], item["id"]))
    return result


class CertificateHandler(HTTPSHandler):
    """Collect the certificate from the same verified connection as the HTTP request."""

    def __init__(self):
        super().__init__(context=ssl.create_default_context())
        self.certificate = None
        self.protocol = None

    def https_open(self, request):
        handler = self

        class VerifiedConnection(HTTPSConnection):
            def connect(self):
                super().connect()
                handler.certificate = self.sock.getpeercert()
                handler.protocol = self.sock.version()

        return self.do_open(VerifiedConnection, request, context=self._context)


def certificate_findings(certificate: dict | None) -> list[dict]:
    expires = (certificate or {}).get("notAfter")
    if not expires:
        return []
    expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(expires), timezone.utc)
    remaining = expiry - datetime.now(timezone.utc)
    if remaining.total_seconds() < 15 * 86400:
        return [finding("medium", "TLS_CERT_EXPIRING",
                        f"تنتهي صلاحية شهادة TLS بتاريخ {expiry:%Y-%m-%d %H:%M} UTC.",
                        "جدّد الشهادة قبل انتهاء صلاحيتها.", f"notAfter: {expiry.isoformat()}", expires=expiry.isoformat())]
    return []


class ScanError(ValueError):
    pass


def network_error(error: Exception) -> tuple[str, str]:
    reason = error.reason if isinstance(error, URLError) else error
    if isinstance(reason, ssl.SSLCertVerificationError):
        labels = {
            9: "شهادة TLS غير سارية بعد.",
            10: "انتهت صلاحية شهادة TLS.",
            18: "الشهادة موقّعة ذاتيًا ولا يثق بها النظام.",
            19: "تحتوي سلسلة الشهادات على شهادة موقّعة ذاتيًا وغير موثوقة.",
            20: "لم يتمكن النظام من التحقق من جهة إصدار الشهادة.",
            21: "تعذر التحقق من سلسلة ثقة الشهادة.",
            62: "اسم الموقع لا يطابق شهادة TLS.",
            64: "عنوان IP لا يطابق شهادة TLS.",
        }
        return ("tls_certificate", labels.get(reason.verify_code,
                f"تعذر التحقق من شهادة TLS. رمز التحقق {reason.verify_code}."))
    if isinstance(reason, ssl.SSLError):
        return "tls_connection", "تعذر إنشاء اتصال TLS."
    if isinstance(reason, socket.gaierror):
        return "dns", "تعذر العثور على عنوان الموقع عبر DNS."
    if isinstance(reason, PermissionError):
        return "network_permission", "النظام منع الاتصال بالشبكة."
    if isinstance(reason, TimeoutError):
        return "timeout", "انتهت مهلة الفحص."
    return "connection", "تعذر قراءة استجابة الموقع. تحقق من الرابط والاتصال."


def _scan_response(url: str, timeout: float, hide_path: bool) -> dict:
    request = Request(url, headers={
        "User-Agent": f"WebGuard/{VERSION} (authorized security configuration check)",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
        "Accept-Encoding": "identity",
    })
    tls = CertificateHandler() if urlsplit(url).scheme == "https" else None
    opener = build_opener(NoRedirect, *([tls] if tls else []))
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        encoding = (response.headers.get("Content-Encoding") or "identity").strip().lower()
        body = response.read(MAX_BYTES + 1) if encoding == "identity" else b""
        result = analyze(url, response.status or response.code, response.headers,
                         body[:MAX_BYTES], truncated=len(body) > MAX_BYTES, hide_path=hide_path)
        if encoding != "identity":
            result["limitations_en"].append(LIMITATIONS["encoding"])
            if result["html_status"] != "not_applicable":
                result["html_status"] = "failed"
            result["limitations"].append("تم تحليل الترويسات فقط لأن ترميز محتوى الرد غير مدعوم.")
    result["http"] = {"method": "GET", "user_agent": request.get_header("User-agent"),
                      "response_headers": capture_http(response.headers)}
    result["scan_mode"] = "quick"
    result["scope_redacted"] = hide_path or bool(urlsplit(url).query)

    if tls:
        expiry = (tls.certificate or {}).get("notAfter")
        result["tls"] = {
            "protocol": tls.protocol or "Unavailable",
            "expires": (datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry), timezone.utc)
                        .isoformat() if expiry else None),
        }
        result["findings"].extend(certificate_findings(tls.certificate))
    result["findings"].sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], item["id"]))
    result["control_coverage"] = control_coverage(result)
    result["configuration_score"] = configuration_score(result)
    return result


def _scan_worker(channel, url: str, timeout: float, hide_path: bool):
    try:
        with channel:
            try:
                result = _scan_response(url, timeout, hide_path)
            except (OSError, ValueError, HTTPException) as error:
                channel.send(("error", network_error(error)))
            else:
                channel.send(("success", result))
    except (BrokenPipeError, EOFError):
        return


def scan(url: str, timeout: float, *, hide_path=False, cancel=None) -> dict:
    url = normalize_url(url)
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("المهلة يجب أن تكون أكبر من صفر وحتى 60 ثانية.")
    context = mp.get_context("spawn")
    incoming, outgoing = context.Pipe(duplex=False)
    process = context.Process(target=_scan_worker, args=(outgoing, url, timeout, hide_path), daemon=True)
    deadline = time.monotonic() + timeout
    with incoming, outgoing:
        process.start()
        outgoing.close()
        try:
            while True:
                if cancel is not None and cancel.is_set():
                    raise ScanError("أُلغي الفحص.")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ScanError("انتهت مهلة الفحص.")
                if incoming.poll(min(remaining, 0.05)):
                    try:
                        kind, payload = incoming.recv()
                    except EOFError:
                        raise ScanError("توقف الفحص قبل استلام نتيجة.") from None
                    if kind == "error":
                        raise ScanError(payload[1])
                    return payload
        finally:
            if process.is_alive():
                process.terminate()
            process.join()
            process.close()


def print_report(result: dict):
    print(f"\nWebGuard | {result['url']} | HTTP {result['status']}")
    if result["title"]:
        print(f"عنوان الصفحة: {result['title']}")
    counts = Counter(item["severity"] for item in result["findings"])
    print("النتائج: " + " | ".join(f"{SEVERITY_AR[level]}: {counts[level]}"
                                     for level in SEVERITY_ORDER))
    if not result["findings"]:
        print("لم تظهر ملاحظات في الفحوصات المحدودة الحالية.")
    for index, item in enumerate(result["findings"], start=1):
        print(f"\n{index}. [{SEVERITY_AR[item['severity']]}] {item['message']}")
        print(f"   الدليل: {item['evidence']}")
        print(f"   الإجراء المقترح: {item['recommendation']}")
    for limitation in result["limitations"]:
        print(f"  • {limitation}")
    print("\nتنبيه: هذا فحص محدود ولا يثبت أن الموقع آمن أو قابل للاختراق.")


def main() -> int:
    parser = argparse.ArgumentParser(description="فحص أمني منخفض التأثير لصفحة ويب مصرح لك بفحصها")
    parser.add_argument("url", help="رابط كامل مثل https://example.com")
    parser.add_argument("--hide-path", action="store_true", help="إخفاء المسار من التقرير")
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--json", metavar="FILE", help="حفظ التقرير بصيغة JSON")
    parser.add_argument("--pdf", metavar="FILE", help="حفظ تقرير PDF بالإنجليزية")
    parser.add_argument("--html", metavar="FILE", help="حفظ تقرير HTML محلي")
    parser.add_argument("--timeout", type=float, default=8.0, help="مهلة الطلب بالثواني (الافتراضي 8)")
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 60:
        parser.error("--timeout يجب أن تكون بين 0 و60 ثانية")
    try:
        result = scan(args.url, args.timeout, hide_path=args.hide_path)
        print_report(result)
        if args.json:
            destination = Path(args.json)
            destination.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"\nحُفظ التقرير في: {destination.resolve()}")
        if args.html:
            from webguard_reports import html_report
            destination = Path(args.html)
            destination.write_text(html_report(result), encoding="utf-8")
            print(f"\nحُفظ تقرير HTML في: {destination.resolve()}")
        if args.pdf:
            from webguard_pdf import pdf_report
            pdf_report(result, Path(args.pdf))
        return 0
    except (ValueError, URLError, OSError, ssl.SSLError, ImportError) as exc:
        print(f"خطأ: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    mp.freeze_support()
    raise SystemExit(main())
