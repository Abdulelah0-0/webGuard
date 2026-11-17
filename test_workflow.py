import csv
from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from webguard_imports import import_report
from webguard_workflow import finding_rows, remediation_plan, update_finding, update_incident
from webguard_workspace import compare_workspaces, import_entries, load_workspace, new_workspace, register_asset, save_workspace


def record(asset="https://example.test/", source="Team", id="R-01", **overrides):
    return {
        "asset": asset, "source": source, "id": id, "kind": "XSS", "title": "Output encoding",
        "severity": "medium", "evidence": "Manual source review reference IR-14.",
        "observed_at": "2026-11-12T06:00:00Z", "impact": "Untrusted text may reach HTML output.",
        **overrides,
    }


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workspace = new_workspace()
        register_asset(self.workspace, "https://example.test/")
        register_asset(self.workspace, "https://example.test/portal")

    def test_csv_merges_correlated_evidence_and_groups_actions(self):
        items = [
            record(correlation_id="case-14"),
            record(source="Independent review", id="Q-99", correlation_id="case-14", severity="high"),
            record(asset="https://example.test/portal", correlation_id="case-14"),
        ]
        with TemporaryDirectory() as scratch:
            path = Path(scratch) / "findings.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=items[0].keys())
                writer.writeheader()
                writer.writerows(items)
            self.assertEqual(import_report(self.workspace, path), 3)
            self.assertEqual(import_report(self.workspace, path), 3)
        rows = finding_rows(self.workspace)
        self.assertEqual(len(rows), 2)
        self.assertEqual({item["source"] for item in rows[0]["evidence"]}, {"Team", "Independent review"})
        plan = remediation_plan(self.workspace)
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["severity"], "high")
        self.assertEqual(len(plan[0]["assets"]), 2)

    def test_sarif_requires_scope_and_ignores_accepted_suppressions(self):
        fixture = {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "Static review", "rules": [{"id": "safe-output"}]}},
            "results": [
                {"ruleIndex": 0, "level": "warning", "message": {"text": "Review output handling"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/view.py?secret=1"},
                                                     "region": {"startLine": 18}}}]},
                {"ruleId": "suppressed", "message": {"text": "Skipped"}, "suppressions": [{"status": "accepted"}]},
            ],
        }]}
        with TemporaryDirectory() as scratch:
            path = Path(scratch) / "findings.sarif"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            with self.assertRaises(ValueError):
                import_report(self.workspace, path)
            self.assertEqual(import_report(self.workspace, path, "https://example.test/"), 1)
            self.assertEqual(import_report(self.workspace, path, "https://example.test/"), 1)
        row, = finding_rows(self.workspace)
        self.assertEqual(row["evidence"][0]["text"], "src/view.py:18 | Review output handling")

    def test_evidence_is_required_and_changed_observations_reenter_plan(self):
        import_entries(self.workspace, [record()])
        key = finding_rows(self.workspace)[0]["key"]
        baseline = deepcopy(self.workspace)
        update_finding(self.workspace, key, "working", "AppSec", "Assigned for review")
        with self.assertRaisesRegex(ValueError, "verification evidence"):
            update_finding(self.workspace, key, "verified", "AppSec", "")
        update_finding(self.workspace, key, "verified", "AppSec", "Regression check 5 passed.")
        self.assertFalse(remediation_plan(self.workspace))
        self.assertTrue(any("Team workflow update" in item[-1] for item in compare_workspaces(self.workspace, baseline)))
        import_entries(self.workspace, [record(evidence="New evidence after deployment.")])
        self.assertTrue(finding_rows(self.workspace)[0]["recheck"])
        self.assertTrue(remediation_plan(self.workspace))
        self.workspace["external"].clear()
        self.assertEqual(finding_rows(self.workspace)[0]["history"][-1]["note"], "Regression check 5 passed.")

    def test_workspace_migration_and_history_round_trip(self):
        with TemporaryDirectory() as scratch:
            path = Path(scratch) / "old.json"
            path.write_text('{"schema":"webguard-workspace/1","assets":{},"external":{}}', encoding="utf-8")
            self.assertEqual(load_workspace(path), new_workspace())
            import_entries(self.workspace, [record()])
            update_finding(self.workspace, finding_rows(self.workspace)[0]["key"], "working", "AppSec", "Follow up")
            update_incident(self.workspace, {"log_references": "IR-14"})
            save_workspace(self.workspace, path)
            reopened = load_workspace(path)
            self.assertEqual(finding_rows(reopened)[0]["owner"], "AppSec")
            self.assertEqual(reopened["incident"]["log_references"], "IR-14")
            self.assertEqual(len(remediation_plan(reopened)), 1)


if __name__ == "__main__":
    unittest.main()
