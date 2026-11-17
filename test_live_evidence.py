from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest

from webguard import scan
from webguard_openapi import inspect_spec


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "session=private-test-value")
        if self.path == "/fixed":
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(b"<title>Local regression fixture</title>")

    def log_message(self, *_):
        pass


class LiveEvidenceTests(unittest.TestCase):
    def test_live_header_change_changes_finding(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), Fixture) as server:
            Thread(target=server.serve_forever, daemon=True).start()
            try:
                base = f"http://127.0.0.1:{server.server_port}"
                original = scan(base + "/original", 8)
                fixed = scan(base + "/fixed", 8)
                self.assertIn("CSP_MISSING", {item["id"] for item in original["findings"]})
                self.assertNotIn("CSP_MISSING", {item["id"] for item in fixed["findings"]})
                self.assertEqual(fixed["http"]["response_headers"]["content-security-policy"], "Present")
                self.assertNotIn("private-test-value", str(fixed))
            finally:
                server.shutdown()

    def test_openapi_security_inheritance_and_override(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "api.json"
            path.write_text('{"openapi":"3.1.0","security":[{"auth":[]}],"paths":{'
                            '"/items":{"get":{},"post":{"security":[]}},'
                            '"/external":{"$ref":"https://example.test/spec.json"},'
                            '"/optional":{"get":{"security":[{},{"auth":[]}]}}}}', encoding="utf-8")
            self.assertEqual(inspect_spec(path), [
                ("", "/external", "reference"), ("GET", "/items", "required"),
                ("POST", "/items", "none"), ("GET", "/optional", "optional")
            ])
