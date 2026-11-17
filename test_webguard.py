import threading
import unittest
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
import ssl
import time

from webguard import MAX_BYTES, ScanError, analyze, network_error, normalize_url, scan
from webguard_english import english_finding
from webguard_reports import html_report


class LocalSite(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.requests.append(self.path)
        if self.path.startswith("/slow"):
            time.sleep(2)
        code = 302 if self.path.startswith("/redirect") else 403 if self.path == "/denied" else 200
        self.send_response(code)
        if code == 302:
            self.send_header("Location", "/final/private-token?key=secret")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        body = b"<title>Demo</title>" + (b" " * MAX_BYTES if self.path == "/large" else b"")
        try:
            self.wfile.write(body)
        except OSError:
            pass


class AnalysisTests(unittest.TestCase):
    def analyze(self, body=b"<title>Demo</title>", **fields):
        headers = Message()
        headers["Content-Type"] = "text/html"
        for key, value in fields.items():
            for entry in value if isinstance(value, list) else [value]:
                headers[key.replace("_", "-")] = entry
        return analyze("https://example.test/page", 200, headers, body)

    def test_header_values(self):
        findings = self.analyze(Strict_Transport_Security="max-age=0", X_Frame_Options="ALLOWALL",
                                Content_Security_Policy_Report_Only="frame-ancestors 'none'")["findings"]
        ids = {item["id"] for item in findings}
        self.assertTrue({"HSTS_INVALID", "CSP_MISSING", "FRAME_POLICY_MISSING"} <= ids)

    def test_valid_headers_and_multiple_cookies(self):
        result = self.analyze(Strict_Transport_Security="max-age=31536000",
                              Content_Security_Policy=["default-src 'self'", "frame-ancestors 'none'"],
                              Set_Cookie=["session=secret; SameSite=None", "prefs=secret; SameSite=nope; Secure"])
        ids = {item["id"] for item in result["findings"]}
        self.assertFalse({"HSTS_INVALID", "HSTS_MISSING", "FRAME_POLICY_MISSING"} & ids)
        self.assertTrue({"COOKIE_NONE_REQUIRES_SECURE", "COOKIE_SAMESITE_INVALID"} <= ids)
        self.assertNotIn("secret", str(result))

    def test_base_and_srcset(self):
        result = self.analyze(b'<base href="http://example.test/assets/"><img srcset="pic.png 1x, data:image/png,abc 2x">'
                              b'<form action="submit"><input type="password"></form>')
        self.assertTrue({"MIXED_CONTENT", "PASSWORD_FORM_INSECURE"} <= {item["id"] for item in result["findings"]})

    def test_additional_response_indicators_and_english_details(self):
        result = self.analyze(
            b'<form><input type="password"></form>',
            Access_Control_Allow_Origin="null", Access_Control_Allow_Credentials="true",
            Content_Security_Policy="script-src 'self' 'unsafe-eval'",
            Set_Cookie="session=secret; SameSite=None",
        )
        by_id = {item["id"]: english_finding(item) for item in result["findings"]}
        self.assertTrue({"CORS_NULL_CREDENTIALS", "CSP_UNSAFE_EVAL", "PASSWORD_FORM_GET"} <= by_id.keys())
        self.assertIn("form #1", by_id["PASSWORD_FORM_GET"]["evidence"])
        self.assertIn("session", by_id["COOKIE_NO_SECURE"]["evidence"])
        self.assertNotIn("secret", str(by_id))
        self.assertIn('lang="en"', html_report(result, english=True))

    def test_additional_indicators_respect_policy_and_post(self):
        result = self.analyze(
            b'<form method="post"><input type="password"></form>',
            Access_Control_Allow_Origin="*", Access_Control_Allow_Credentials="true",
            Content_Security_Policy=["script-src 'unsafe-eval'", "default-src 'self'"],
        )
        ids = {item["id"] for item in result["findings"]}
        self.assertFalse({"CORS_NULL_CREDENTIALS", "CSP_UNSAFE_EVAL", "PASSWORD_FORM_GET"} & ids)

    def test_url_validation(self):
        self.assertEqual(normalize_url("example.test/path#frag"), "https://example.test/path")
        for value in ("https://example.test:0", "http://@example.test", "https://exa mple.test"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_url(value)

    def test_export_escapes_untrusted_text(self):
        result = self.analyze()
        result["findings"][0]["evidence"] = "<script>alert(1)</script>"
        document = html_report(result)
        self.assertNotIn("<script>", document)
        self.assertIn("&lt;script&gt;", document)

    def test_tls_error_uses_code_instead_of_raw_message(self):
        class VerificationError(ssl.SSLCertVerificationError):
            verify_code = 10

        kind, message = network_error(VerificationError("do not expose"))
        self.assertEqual(kind, "tls_certificate")
        self.assertNotIn("do not expose", message)
        self.assertIn("TLS", message)


class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LocalSite)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_redirect_is_not_followed_and_path_is_redacted(self):
        result = scan(self.url + "/redirect?key=secret", 5, hide_path=True)
        self.assertEqual(result["response_kind"], "redirect")
        self.assertEqual(result["url"], self.url + "/")
        self.assertNotIn("private-token", str(result))
        self.assertNotIn("key=secret", str(result))
        self.assertFalse(any(path.startswith("/final") for path in LocalSite.requests))

    def test_coverage(self):
        self.assertEqual(scan(self.url + "/denied", 5)["response_kind"], "error")
        result = scan(self.url + "/large", 5)
        self.assertTrue(result["body_truncated"])
        self.assertEqual(result["html_status"], "partial")

    def test_timeout_and_cancel(self):
        start = time.monotonic()
        with self.assertRaises(ScanError):
            scan(self.url + "/slow", 0.4)
        self.assertLess(time.monotonic() - start, 1.5)
        event = threading.Event()
        timer = threading.Timer(0.15, event.set)
        timer.start()
        try:
            with self.assertRaises(ScanError):
                scan(self.url + "/slow", 5, cancel=event)
        finally:
            timer.join()


if __name__ == "__main__":
    unittest.main()
