from email.message import Message
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from webguard import analyze
from webguard_controls import capture_http, configuration_score
from webguard_history import compare_scans, read_scan, recent_scans, save_scan
from webguard_scope import audit_urls, scope_urls


class AuditTests(TestCase):
    def test_scope(self):
        root = "https://example.test/"
        self.assertEqual(scope_urls(root, [root, root + "docs"]), [root, root + "docs"])
        for url in ("http://example.test/", "https://example.test:444/", "https://else.test/",
                    root + "?action=test"):
            with self.assertRaises(ValueError):
                scope_urls(root, [url])
        with self.assertRaises(ValueError):
            scope_urls(root, [root + str(i) for i in range(50)])

    def test_batch_respects_exhausted_budget(self):
        with patch("webguard_scope.monotonic", side_effect=[0, 2]), patch("webguard_scope.scan") as scan:
            self.assertEqual(audit_urls(["https://example.test/"], 1), [])
            scan.assert_not_called()

    def test_http_evidence_and_score(self):
        headers = Message()
        headers["Set-Cookie"] = "session=secret"
        headers["Content-Type"] = "text/html"
        headers["X-Content-Type-Options"] = "nosniff"
        self.assertEqual(capture_http(headers)["set-cookie"], "Present")
        self.assertNotIn("secret", str(capture_http(headers)))
        good = analyze("https://example.test/", 200, headers, b"<title>Page</title>")
        score = configuration_score(good)
        self.assertTrue(0 < score["value"] < 100)
        self.assertIn("CSP_MISSING", str(score))
        good["status"] = 403
        self.assertIsNone(configuration_score(good))

    def test_history_and_comparison(self):
        report = analyze("https://example.test/", 200, Message(), b"")
        with TemporaryDirectory() as directory:
            path = Path(directory) / "history.sqlite3"
            scan_id = save_scan(path, report)
            self.assertEqual(read_scan(path, scan_id), report)
            self.assertEqual(len(recent_scans(path)), 1)
        newer = {**report, "findings": []}
        self.assertTrue(compare_scans(report, newer)["comparable"])
        self.assertFalse(compare_scans(report, {**newer, "status": 404})["comparable"])
        with self.assertRaises(ValueError):
            compare_scans(report, {**newer, "scope_redacted": True})

    def test_local_inventory_does_not_return_external_or_query_urls(self):
        from webguard_scope import discover_saved_html

        with TemporaryDirectory() as directory:
            path = Path(directory) / "page.html"
            path.write_text('<a href="/docs">Docs</a><a href="/docs#top">Top</a>'
                            '<a href="/?id=1">Query</a><a href="//else.test">External</a>',
                            encoding="utf-8")
            self.assertEqual(discover_saved_html("https://example.test/", path), ["https://example.test/docs"])

    def test_coverage_distinguishes_error_and_partial_html(self):
        from webguard_controls import control_coverage

        report = {"response_kind": "error", "status": 503, "html_status": "partial",
                  "body_truncated": True}
        coverage = control_coverage(report)
        self.assertEqual(coverage["Response headers and observed cookies"], "response_only")
        self.assertEqual(coverage["HTML forms and resource references"], "partial")
        self.assertEqual(coverage["Active injection and exploit verification"], "outside_scope")
        self.assertIsNone(configuration_score(report))

    def test_comparison_rejects_incomplete_coverage_and_flags_changed_evidence(self):
        headers = Message()
        headers["Content-Type"] = "text/html"
        report = analyze("https://example.test/", 200, headers, b"<title>Example</title>")
        self.assertTrue(compare_scans(report, report)["comparable"])
        partial = {**report, "html_status": "partial"}
        error = {**report, "status": 403, "response_kind": "error"}
        self.assertFalse(compare_scans(partial, partial)["comparable"])
        self.assertFalse(compare_scans(error, error)["comparable"])
        first, *rest = report["findings"]
        updated = {**report, "findings": [{**first, "evidence": "Different evidence"}, *rest]}
        delta = compare_scans(report, updated)
        self.assertIn(first["id"], delta["changed_evidence"])
        self.assertIn((first["id"], 1, 1), delta["rows"])
