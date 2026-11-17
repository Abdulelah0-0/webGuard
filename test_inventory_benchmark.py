"""Labeled HTTP cases covering expected findings and expected absences."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest

from webguard import scan
from webguard_inventory import batch_rows, import_inventory


DEFAULT = {"Content-Type": "text/html", "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
           "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"}
CASES = {
    "baseline": ({}, set()),
    "missing-csp": ({"Content-Security-Policy": None}, {"CSP_MISSING", "FRAME_POLICY_MISSING"}),
    "missing-referrer": ({"Referrer-Policy": None}, {"REFERRER_POLICY_MISSING"}),
    "invalid-nosniff": ({"X-Content-Type-Options": "off"}, {"NOSNIFF_MISSING"}),
    "xfo": ({"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY"}, set()),
    "cors": ({"Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true"},
             {"CORS_NULL_CREDENTIALS"}),
    "wildcard": ({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}, set()),
    "unsafe-eval": ({"Content-Security-Policy": "script-src 'unsafe-eval'; frame-ancestors 'none'"},
                    {"CSP_UNSAFE_EVAL"}),
    "cookie": ({"Set-Cookie": "session=benchmark-secret; SameSite=None"}, {"COOKIE_NONE_REQUIRES_SECURE"}),
}
CHECKS = set().union(*(expected for _, expected in CASES.values()))


class Cases(BaseHTTPRequestHandler):
    def do_GET(self):
        overrides, _ = CASES[self.path[1:]]
        self.send_response(200)
        for name, value in (DEFAULT | overrides).items():
            if value is not None:
                self.send_header(name, value)
        self.end_headers()
        self.wfile.write(b"<title>Benchmark page</title>")

    def log_message(self, *_):
        pass


class InventoryAndBenchmarkTests(unittest.TestCase):
    def test_inventory_combines_sources_and_filters_scope(self):
        with TemporaryDirectory() as scratch:
            xml = Path(scratch) / "sitemap.xml"
            xml.write_text('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                           '<url><loc>https://example.test/docs</loc></url>'
                           '<url><loc>https://other.test/</loc></url></urlset>', encoding="utf-8")
            spec = Path(scratch) / "api.json"
            spec.write_text('{"openapi":"3.1.0","servers":[{"url":"/v1"}],"paths":{'
                            '"/users":{"get":{}}, "/users/{id}":{"get":{}}, "/write":{"post":{}}}}',
                            encoding="utf-8")
            self.assertEqual(import_inventory("https://example.test/", [xml, spec]),
                             (["https://example.test/docs", "https://example.test/v1/users"], 1))

    def test_states_include_partial_errors_and_unattempted(self):
        self.assertEqual(batch_rows(["a", "b", "c", "d", "e", "f"], [
            ("a", {"status": 200}), ("b", {"status": 200, "body_truncated": True}),
            ("c", {"status": 302}), ("d", {"status": 404}), ("e", None),
        ]), [("a", "complete", 200), ("b", "limited", 200), ("c", "redirect", 302),
             ("d", "http_error", 404), ("e", "failed", None), ("f", "not_attempted", None)])

    def test_labeled_cases_over_real_http(self):
        false_positive = false_negative = true_positive = 0
        with ThreadingHTTPServer(("127.0.0.1", 0), Cases) as server:
            Thread(target=server.serve_forever, daemon=True).start()
            try:
                for name, (_, expected) in CASES.items():
                    report = scan(f"http://127.0.0.1:{server.server_port}/{name}", 8)
                    actual = {item["id"] for item in report["findings"]} & CHECKS
                    false_positive += len(actual - expected)
                    false_negative += len(expected - actual)
                    true_positive += len(actual & expected)
                    self.assertNotIn("benchmark-secret", str(report))
                    with self.subTest(case=name):
                        self.assertEqual(actual, expected)
            finally:
                server.shutdown()
        self.assertEqual((true_positive, false_positive, false_negative), (7, 0, 0))
