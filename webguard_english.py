"""English finding descriptions used by the desktop UI and PDF reports."""

# Each entry contains a finding, its evidence, its impact, and a remediation.
FINDINGS = {
    "HTTP_ONLY": ("Unencrypted HTTP response", "The requested URL uses HTTP.", "Traffic can be observed or modified in transit.", "Serve this endpoint over HTTPS and redirect HTTP traffic to HTTPS."),
    "HSTS_MISSING": ("HSTS header missing", "No Strict-Transport-Security header was received.", "Browsers may initiate later visits over HTTP.", "Verify HTTPS readiness, then enable HSTS with a positive max-age. Roll out cautiously before expanding to subdomains."),
    "HSTS_INVALID": ("HSTS disabled or invalid", "Strict-Transport-Security has no valid positive max-age.", "The response does not establish an effective HSTS policy.", "Set one valid positive max-age after confirming HTTPS readiness."),
    "CSP_MISSING": ("Enforced Content Security Policy missing", "No enforced CSP was found. Report-Only present: {report_only}.", "The browser lacks a CSP enforcement layer for this response.", "Define a site-specific policy, test it in Report-Only, then deploy the enforced policy."),
    "FRAME_POLICY_MISSING": ("Effective framing restriction not observed", "No recognized restrictive frame-ancestors directive or consistent DENY/SAMEORIGIN header was found.", "Unwanted framing may be possible.", "Set an appropriate CSP frame-ancestors policy. Use X-Frame-Options DENY or SAMEORIGIN where appropriate for older clients."),
    "REFERRER_POLICY_MISSING": ("Referrer-Policy header missing", "No explicit Referrer-Policy header was received.", "Referrer handling depends on client defaults.", "Set a policy appropriate to the application, such as strict-origin-when-cross-origin."),
    "NOSNIFF_MISSING": ("MIME sniffing protection missing", "X-Content-Type-Options is absent or does not specify nosniff.", "Some resources may be interpreted differently from their declared type.", "Serve accurate Content-Type values and set X-Content-Type-Options: nosniff."),
    "BANNER_SERVER": ("Server header is exposed", "The Server header is present. Its value is omitted.", "The header can reveal server implementation details.", "Minimize unnecessary product and version details at the server or reverse proxy."),
    "BANNER_X_POWERED_BY": ("X-Powered-By header is exposed", "The X-Powered-By header is present. Its value is omitted.", "The header can reveal framework details.", "Disable framework or proxy headers that disclose implementation details unnecessarily."),
    "COOKIE_NO_SECURE": ("Cookie is missing Secure", "Cookie {cookie} was set over HTTPS without Secure. Session-like name: {session_like}.", "The cookie may be sent over HTTP where the client permits it.", "Add Secure and serve the cookie only over HTTPS."),
    "COOKIE_NO_HTTPONLY": ("Session-like cookie is missing HttpOnly", "Cookie {cookie} has a session-like name and omits HttpOnly.", "Client-side script may be able to read it.", "Add HttpOnly to session cookies that do not require JavaScript access."),
    "COOKIE_NO_SAMESITE": ("Session-like cookie is missing SameSite", "Cookie {cookie} has a session-like name and omits SameSite.", "Cross-site behavior depends on browser defaults.", "Choose and set an explicit SameSite policy for the application's sign-in and navigation flows."),
    "COOKIE_SAMESITE_INVALID": ("Cookie has an unrecognized SameSite value", "Cookie {cookie} has a SameSite value outside Lax, Strict, and None.", "Browsers may apply default SameSite behavior.", "Use Lax, Strict, or None as appropriate. Pair None with Secure."),
    "COOKIE_NONE_REQUIRES_SECURE": ("SameSite=None cookie is missing Secure", "Cookie {cookie} sets SameSite=None without Secure.", "Browsers can reject this cookie.", "Add Secure on HTTPS, or select Lax or Strict if the workflow permits."),
    "REDIRECT_NOT_FOLLOWED": ("Redirect response observed", "Location destination: {destination}. The destination was not requested.", "The findings describe the redirect response.", "Review the destination and assess it independently if authorized."),
    "PASSWORD_FORM_INSECURE": ("Password form may use unencrypted transport", "Password form #{form} appears on HTTP or has an HTTP action.", "Passwords may be exposed in transit.", "Serve the page and form destination over HTTPS."),
    "MIXED_CONTENT": ("HTTP resources referenced by HTTPS HTML", "{count} HTTP resource reference(s). Example element types: {elements}.", "Some browsers may block or upgrade these requests, and unprotected resources can undermine transport security.", "Replace HTTP resource references with HTTPS URLs and test the page in supported browsers."),
    "TLS_CERT_EXPIRING": ("TLS certificate expires soon", "Verified leaf certificate expiry: {expires}.", "Expiry can interrupt HTTPS access.", "Renew the certificate and validate automated renewal before the expiry date."),
    "CORS_NULL_CREDENTIALS": ("Credentialed CORS trusts the null origin", "Access-Control-Allow-Origin: null and Access-Control-Allow-Credentials: true were both observed.", "Depending on the endpoint and browser context, an untrusted opaque origin may be permitted to read a credentialed response.", "Remove trust for null origins. Allowlist explicit HTTPS origins only where required, and enable credentials only for those routes."),
    "CSP_UNSAFE_EVAL": ("Content Security Policy permits string evaluation", "The effective script-src or default-src directive in every enforced policy contains 'unsafe-eval'.", "Permitting string-to-code evaluation weakens CSP's mitigation of script injection.", "Replace string-to-code evaluation and update dependencies that require it. Test in Report-Only before removing 'unsafe-eval'."),
    "PASSWORD_FORM_GET": ("Password form declares GET", "Password form #{form} has an effective form method of GET in HTML.", "If submitted as declared, password fields may enter the URL, browser history, and request logs.", "Use POST over HTTPS and verify that form submit controls and client-side code preserve that behavior."),
}

LIMITATIONS = {
    "scope": "One HTTP GET to the requested URL. Redirects, linked resources, and JavaScript were not executed.",
    "interpretation": "Findings are response-based indicators. Review impact in the context of the application.",
    "coverage": "Authentication, authorization, injection, and application workflows were outside this review.",
    "body_limit": "HTML analysis was limited to the first 1,000,000 bytes of the response.",
    "error_response": "The findings describe the HTTP error response returned by the server.",
    "cookie_limit": "Only the first 200 Set-Cookie headers were analyzed.",
    "form_limit": "Only the first 200 HTML forms were analyzed.",
    "html_error": "HTML parsing could not be completed ({error}).",
    "encoding": "Only headers were analyzed because the response content encoding is unsupported.",
}

HTML_STATUS_EN = {
    "not_applicable": "HTML analysis not applicable",
    "empty": "Empty HTML response",
    "analyzed": "HTML analyzed",
    "partial": "HTML partially analyzed",
    "failed": "HTML analysis unavailable",
}

RESPONSE_EN = {"response": "Response", "redirect": "Redirect", "error": "HTTP error response"}
SEVERITY_EN = {"high": "High", "medium": "Medium", "low": "Low", "info": "Informational"}

ERRORS = {
    "أُلغي الفحص.": "The scan was cancelled.",
    "انتهت مهلة الفحص.": "The scan timed out.",
    "توقف الفحص قبل استلام نتيجة.": "The scan ended before a result was received.",
    "أدخل رابط HTTP أو HTTPS بمنفذ صالح.": "Enter an HTTP or HTTPS URL with a valid port.",
    "عنوان الموقع أو المنفذ غير صالح.": "The address or port is invalid.",
    "الرابط يحتوي على محارف غير صالحة.": "The URL contains invalid characters.",
    "لا تضع بيانات دخول ضمن الرابط.": "Remove credentials from the URL.",
    "اسم الموقع غير صالح.": "The hostname is invalid.",
    "شهادة TLS غير سارية بعد.": "The TLS certificate is not yet valid.",
    "انتهت صلاحية شهادة TLS.": "The TLS certificate has expired.",
    "الشهادة موقّعة ذاتيًا ولا يثق بها النظام.": "The TLS certificate is self-signed and untrusted.",
    "تحتوي سلسلة الشهادات على شهادة موقّعة ذاتيًا وغير موثوقة.": "The certificate chain contains an untrusted self-signed certificate.",
    "لم يتمكن النظام من التحقق من جهة إصدار الشهادة.": "The certificate issuer could not be verified.",
    "تعذر التحقق من سلسلة ثقة الشهادة.": "The certificate chain could not be verified.",
    "اسم الموقع لا يطابق شهادة TLS.": "The hostname does not match the TLS certificate.",
    "عنوان IP لا يطابق شهادة TLS.": "The IP address does not match the TLS certificate.",
    "تعذر إنشاء اتصال TLS.": "A TLS connection could not be established.",
    "تعذر العثور على عنوان الموقع عبر DNS.": "The hostname could not be resolved.",
    "النظام منع الاتصال بالشبكة.": "The system denied network access.",
    "تعذر قراءة استجابة الموقع. تحقق من الرابط والاتصال.": "The response could not be read. Check the URL and connection.",
}


def english_finding(item: dict) -> dict:
    title, evidence, impact, fix = FINDINGS[item["id"]]
    return {
        **item, "message": title, "evidence": evidence.format(**item.get("details", {})),
        "severity_reason": impact, "recommendation": fix,
    }
