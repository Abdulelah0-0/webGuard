from email.message import Message
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from webguard import analyze
from webguard_source_review import review_source
from webguard_workspace import (
    compare_workspaces, import_findings, load_workspace, new_workspace,
    record_scan, register_asset, save_workspace,
)


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.workspace = new_workspace()
        self.asset = register_asset(self.workspace, "https://example.test/?token=secret")
        self.assertEqual(self.asset, "https://example.test/")

    def test_import_and_round_trip(self):
        self.assertEqual(import_findings(self.workspace, Path(__file__).with_name("example_findings.json")), 2)
        self.assertEqual({entry["kind"] for entry in self.workspace["external"].values()}, {"SQL_INJECTION", "XSS"})
        self.assertNotIn("token=secret", str(self.workspace))
        with TemporaryDirectory() as directory:
            path = Path(directory) / "workspace.json"
            save_workspace(self.workspace, path)
            self.assertEqual(load_workspace(path), self.workspace)

    def test_import_outside_scope_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside the registered scope"):
            import_findings(new_workspace(), Path(__file__).with_name("example_findings.json"))

    def test_comparison_does_not_claim_remediation(self):
        baseline = new_workspace()
        headers = Message()
        headers["Content-Type"] = "text/html"
        report = analyze(self.asset, 200, headers, b"<title>Local</title>")
        record_scan(baseline, report)
        changes = compare_workspaces(self.workspace, baseline)
        self.assertTrue(changes)
        self.assertTrue(all(item[-1] == "No current observation" for item in changes))

    def test_local_python_review_and_reassessment(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "audit.py"
            path.write_text(
                'def find(cursor, value):\n'
                '    cursor.execute(f"select id from items where id = {value}")\n'
                '    render_template_string("title: " + value)\n', encoding="utf-8")
            self.assertEqual(review_source(self.workspace, self.asset, path), 2)
            self.assertEqual({item["state"] for item in self.workspace["external"].values()}, {"needs_review"})
            self.assertNotIn("select id from items", str(self.workspace))
            path.write_text('def find(cursor, value):\n'
                            '    cursor.execute("select id from items where id = ?", (value,))\n',
                            encoding="utf-8")
            self.assertEqual(review_source(self.workspace, self.asset, path), 0)
            self.assertFalse(self.workspace["external"])


if __name__ == "__main__":
    unittest.main()
