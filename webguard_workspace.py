"""Local assessment workspace, sanitized evidence intake, and baseline comparison."""
from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile

from webguard import VERSION, clean_text, normalize_url, public_url
from webguard_workflow import INCIDENT_FIELDS, STATUSES, finding_rows, remediation_plan
from webguard_english import HTML_STATUS_EN, english_finding

LEVELS = ("high", "medium", "low", "info")
STATES = ("needs_review", "confirmed", "remediated")
KINDS = {
    "SQL_INJECTION": (
        "Review database audit logs and application errors for the affected operation and time window. "
        "Restrict the affected operation where feasible and preserve relevant logs.",
        "Use parameterized queries for values and explicit allowlists for query identifiers. "
        "Remove string-built SQL and review the database account's privileges.",
        "Review the corrected query construction and run application regression tests that verify "
        "user input is treated as data.",
    ),
    "XSS": (
        "Identify affected rendering paths and preserve relevant request and application logs. "
        "Restrict publication or rendering of affected content while triaging.",
        "Use context-appropriate output encoding and safe rendering APIs. Sanitize HTML where rich "
        "content is required, and review CSP as a defense-in-depth control.",
        "Review the updated rendering code and run regression tests for the affected output contexts.",
    ),
    "OTHER": (
        "Preserve relevant logs and review access to the affected asset during the reported window.",
        "Review the imported evidence and apply a fix for the affected component.",
        "Reassess the same component and record the verification evidence.",
    ),
}


def new_workspace():
    return {"schema": "webguard-workspace/1", "assets": {}, "external": {}, "tracking": {}, "incident": {}}


def _text(value, field, maximum=2000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{field} must be non-empty text up to {maximum} characters.")
    cleaned = clean_text(" ".join(value.split()), maximum)
    if not cleaned:
        raise ValueError(f"{field} is empty after sanitization.")
    return cleaned


def _asset(value):
    return public_url(normalize_url(_text(value, "asset", 2048)))


def _read_json(path):
    with Path(path).open("rb") as stream:
        data = stream.read(12_000_001)
    if len(data) > 12_000_000:
        raise ValueError("JSON file exceeds 12 MB.")
    return json.loads(data.decode("utf-8-sig"))


def register_asset(workspace, url):
    asset = _asset(url)
    workspace["assets"].setdefault(asset, None)
    return asset


def record_scan(workspace, report):
    asset = register_asset(workspace, report["url"])
    observations = []
    for raw in report["findings"]:
        item = english_finding(raw)
        observations.append({key: item[key] for key in
                             ("id", "severity", "message", "evidence", "severity_reason", "recommendation")})
    workspace["assets"][asset] = {
        "checked_at": report["checked_at"], "status": report["status"],
        "coverage": HTML_STATUS_EN[report["html_status"]],
        "limitations": report["limitations_en"], "findings": observations,
        "body_truncated": report["body_truncated"],
        "control_coverage": report.get("control_coverage", {}),
    }


def import_findings(workspace, path):
    data = _read_json(path)
    if not isinstance(data, dict) or data.get("schema") != "webguard-findings/1":
        raise ValueError("Expected the webguard-findings/1 JSON format.")
    return import_entries(workspace, data.get("findings"))


def import_entries(workspace, entries):
    if not isinstance(entries, list) or not entries:
        raise ValueError("Findings must be a non-empty list.")
    staged = {}
    for index, item in enumerate(entries, 1):
        if not isinstance(item, dict):
            raise ValueError(f"Finding {index} must be an object.")
        asset = _asset(item.get("asset"))
        key = _text(item.get("id"), "id", 100)
        source = _text(item.get("source"), "source", 120)
        kind = item.get("kind")
        state = item.get("state", "needs_review")
        severity = item.get("severity")
        if not isinstance(kind, str) or kind not in KINDS or state not in STATES or severity not in LEVELS:
            raise ValueError(f"Finding {index} has an invalid kind, state, or severity.")
        evidence = _text(item.get("evidence"), "evidence")
        correlation = item.get("correlation_id")
        if correlation:
            correlation = _text(correlation, "correlation_id", 120)
        if asset not in workspace["assets"]:
            raise ValueError(f"Finding {index} is outside the registered scope: {asset}")
        identity = json.dumps([asset, source, key], ensure_ascii=False)
        if identity in staged:
            raise ValueError(f"Finding {index} repeats an asset, source, and ID.")
        containment, remedy, verification = KINDS[kind]
        staged[identity] = {
            "asset": asset, "id": key, "source": source, "kind": kind, "state": state,
            "severity": severity, "correlation_id": correlation or "", "title": _text(item.get("title"), "title", 200),
            "evidence": evidence, "observed_at": _text(item.get("observed_at"), "observed_at", 80),
            "impact": _text(item.get("impact"), "impact"),
            "containment": _text(item.get("containment", containment), "containment"),
            "remediation": _text(item.get("remediation", remedy), "remediation"),
            "verification": _text(item.get("verification", verification), "verification"),
        }
    workspace["external"].update(staged)
    return len(staged)


def save_workspace(workspace, path):
    path = Path(path)
    data = json.dumps(workspace, ensure_ascii=False, indent=2)
    temporary = None
    try:
        with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def load_workspace(path):
    data = _read_json(path)
    if not isinstance(data, dict) or data.get("schema") != "webguard-workspace/1":
        raise ValueError("Expected a WebGuard workspace file.")
    assets, external = data.get("assets"), data.get("external")
    if not isinstance(assets, dict) or not isinstance(external, dict):
        raise ValueError("Invalid workspace structure.")
    for asset, scan in assets.items():
        if asset != _asset(asset):
            raise ValueError("Workspace contains an invalid asset URL.")
        if scan is not None and (not isinstance(scan, dict) or not
                {"checked_at", "status", "coverage", "limitations", "findings", "body_truncated"} <= scan.keys()):
            raise ValueError("Workspace contains an invalid observation.")
        if scan and (not isinstance(scan["limitations"], list) or not isinstance(scan["findings"], list) or any(
            not isinstance(item, dict) or not {"id", "severity", "message", "evidence",
            "severity_reason", "recommendation"} <= item.keys() or item["severity"] not in LEVELS
            for item in scan["findings"]
        )):
            raise ValueError("Workspace contains invalid findings.")
    for item in external.values():
        if not isinstance(item, dict) or not {
            "asset", "id", "source", "kind", "state", "severity", "title", "evidence", "observed_at",
            "impact", "containment", "remediation", "verification"
        } <= item.keys() or item["asset"] not in assets or item["state"] not in STATES or item["severity"] not in LEVELS:
            raise ValueError("Workspace contains invalid imported evidence.")
    for field in ("tracking", "incident"):
        if not isinstance(data.setdefault(field, {}), dict):
            raise ValueError(f"Invalid workspace {field}.")
    for entry in data["tracking"].values():
        if not isinstance(entry, dict) or entry.get("status") not in STATUSES or not isinstance(entry.get("owner"), str):
            raise ValueError("Invalid finding tracking entry.")
        snapshot = entry.get("snapshot")
        history = entry.get("history")
        if (not isinstance(snapshot, dict) or not {"asset", "title", "severity", "actions", "evidence"} <= snapshot.keys()
                or snapshot["severity"] not in LEVELS or not isinstance(history, list)
                or any(not isinstance(event, dict) or not {"at", "status", "owner", "note"} <= event.keys()
                       or event["status"] not in STATUSES for event in history)
                or not isinstance(snapshot["actions"], list)
                or any(not isinstance(action, list) or len(action) != 2 or
                       not all(isinstance(value, str) for value in action) for action in snapshot["actions"])
                or not isinstance(snapshot["evidence"], list)
                or any(not isinstance(item, dict) or not {"source", "id", "text", "observed_at"} <= item.keys()
                       for item in snapshot["evidence"])):
            raise ValueError("Invalid finding tracking history.")
    if any(not isinstance(value, str) for value in data["incident"].values()):
        raise ValueError("Invalid incident notes.")
    batch = data.get("last_batch")
    if batch is not None and (not isinstance(batch, dict) or any(
        not isinstance(batch.get(key), int) for key in ("requested", "responses")
    ) or any(not isinstance(batch.get(key), list) or any(not isinstance(url, str) for url in batch[key])
             for key in ("errors", "not_attempted"))):
        raise ValueError("Invalid assessment coverage.")
    return data


def compare_workspaces(current, baseline):
    changes = []
    for asset in sorted(current["assets"].keys() | baseline["assets"].keys()):
        old, new = baseline["assets"].get(asset), current["assets"].get(asset)
        before = Counter(item["id"] for item in old["findings"]) if old else Counter()
        after = Counter(item["id"] for item in new["findings"]) if new else Counter()
        for key in sorted(before.keys() | after.keys()):
            difference = after[key] - before[key]
            if not new:
                status = "No current observation"
            elif not old:
                status = "First observation"
            elif (not old or not all(200 <= scan["status"] < 300 and not scan.get("body_truncated")
                                      for scan in (old, new)) or old["coverage"] != new["coverage"]
                  or old.get("control_coverage") != new.get("control_coverage")
                  or old["coverage"] not in {"HTML analyzed", "HTML analysis not applicable"}):
                status = "Coverage differs or is incomplete; verify before comparing"
            elif difference > 0:
                status = "More occurrences observed"
            elif difference < 0:
                status = "Fewer occurrences observed; verify coverage and remediation"
            else:
                status = "Same occurrence count"
            changes.append((asset, key, before[key], after[key], status))
    for identity, item in current["external"].items():
        previous = baseline["external"].get(identity)
        if previous is None or item["state"] != previous["state"]:
            changes.append((item["asset"], f"{item['source']} / {item['id']}",
                            previous["state"] if previous else "Unrecorded", item["state"],
                            "Imported status; attributed to its source"))
    for identity, item in baseline["external"].items():
        if identity not in current["external"]:
            changes.append((item["asset"], f"{item['source']} / {item['id']}",
                            item["state"], "Unrecorded",
                            "No matching current entry; verify before closure"))
    current_tracking = current.get("tracking", {})
    old_tracking = baseline.get("tracking", {})
    for key, entry in current_tracking.items():
        previous = old_tracking.get(key, {})
        if (previous.get("status"), previous.get("owner")) != (entry["status"], entry["owner"]):
            snapshot = entry["snapshot"]
            changes.append((snapshot["asset"], snapshot["title"],
                            STATUSES.get(previous.get("status"), "Untracked"), STATUSES[entry["status"]],
                            f"Team workflow update | Owner: {entry['owner'] or 'Unassigned'}"))
    return changes


def workspace_report(workspace, destination, baseline=None):
    from html import escape
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    ink, muted = colors.HexColor("#142238"), colors.HexColor("#41536A")
    title = ParagraphStyle("Title", fontName="Helvetica-Bold", fontSize=24, leading=29, textColor=ink)
    heading = ParagraphStyle("Heading", parent=title, fontSize=13, leading=17,
                             spaceBefore=14, spaceAfter=7, keepWithNext=True)
    body = ParagraphStyle("Body", fontName="Helvetica", fontSize=10, leading=14,
                          textColor=muted, spaceAfter=6, splitLongWords=True)
    doc = SimpleDocTemplate(str(destination), title="WebGuard | Assessment workspace",
                            author="WebGuard", topMargin=53, bottomMargin=52)
    story = [Paragraph("Web Security Assessment", title), Spacer(1, 8)]

    def safe(value):
        return escape(str(value).encode("cp1252", "backslashreplace").decode("cp1252"))

    def line(label, value):
        story.append(Paragraph(f"<b>{safe(label)}</b> {safe(value)}", body))

    line("Generated (UTC)", datetime.now(timezone.utc).isoformat(timespec="seconds"))
    line("Coverage", "Built-in observations are limited to individual HTTP responses. "
         "Imported evidence and status remain attributed to their sources.")
    line("Inventory", f"{len(workspace['assets'])} registered assets; "
         f"{sum(scan is not None for scan in workspace['assets'].values())} with recorded scans; "
         f"{len(workspace['external'])} imported findings.")
    batch = workspace.get("last_batch")
    if batch:
        line("Latest standard assessment", f"{batch['responses']} responses from {batch['requested']} listed URLs. "
             "Asset entries may retain earlier observations.")
        for url in batch["errors"]:
            line("No response recorded", url)
        for url in batch["not_attempted"]:
            line("Not attempted within the time budget", url)
    totals = Counter(item["severity"] for scan in workspace["assets"].values() if scan
                     for item in scan["findings"])
    totals.update(item["severity"] for item in workspace["external"].values())
    line("Severity totals", " | ".join(f"{level.title()}: {totals[level]}" for level in LEVELS))
    for asset, scan in sorted(workspace["assets"].items()):
        story.append(Paragraph(f"Asset: {safe(asset)}", heading))
        if scan is None:
            line("Coverage", "Registered; no WebGuard scan recorded.")
            continue
        line("Observed", f"{scan['checked_at']} | HTTP {scan['status']} | {scan['coverage']}")
        for limit in scan["limitations"]:
            line("Scope", limit)
        for item in scan["findings"]:
            line("Observation", f"{item['severity'].upper()} / {item['id']} / {item['message']}")
            line("Evidence", item["evidence"])
            line("Potential impact", item["severity_reason"])
            line("Remediation", item["recommendation"])
            line("Verification", "Repeat the same response-based check after deploying the remediation.")
    if workspace["external"]:
        story.append(Paragraph("Imported findings and response actions", heading))
        for item in sorted(workspace["external"].values(),
                           key=lambda item: (LEVELS.index(item["severity"]), item["asset"], item["id"])):
            line("Finding", f"{item['severity'].upper()} / {item['id']} / {item['title']}")
            line("Asset", item["asset"])
            line("Source and status", f"{item['source']} | {item['observed_at']} | {item['state']} (reported by source)")
            for label in ("Evidence", "Impact", "Containment", "Remediation", "Verification"):
                line(label, item[label.lower()])
    if baseline is not None:
        story.append(Paragraph("Comparison with saved baseline", heading))
        line("Interpretation", "A lower count or missing observation requires verification before closure.")
        for asset, key, old, new, state in compare_workspaces(workspace, baseline):
            line(key, f"{asset} | {old} -> {new} | {state}")

    incident = workspace.get("incident", {})
    if any(incident.values()):
        story.append(Paragraph("Incident response notes", heading))
        for key, label in INCIDENT_FIELDS.items():
            if incident.get(key):
                line(label, incident[key])
    rows = finding_rows(workspace)
    if rows:
        story.append(Paragraph("Finding tracking and evidence", heading))
        for row in rows:
            line(row["title"], f"{row['asset']} | {STATUSES[row['status']]} | "
                              f"Owner: {row['owner'] or 'Unassigned'}")
            if not row["current"]:
                line("Coverage", "No current matching observation. Review the retained evidence.")
            elif row["recheck"]:
                line("Review required", "The matching evidence changed after verification.")
            for evidence in row["evidence"]:
                line("Source", f"{evidence['source']} / {evidence['id']} / {evidence['observed_at']}")
                if not row["current"]:
                    line("Retained evidence", evidence["text"])
            for event in row["history"]:
                line("History", f"{event['at']} | {STATUSES[event['status']]} | "
                                f"{event['owner'] or 'Unassigned'} | {event['note'] or 'No note'}")
    story.append(Paragraph("Prioritized remediation plan", heading))
    tasks = remediation_plan(workspace)
    if not tasks:
        line("Plan", "No pending actions from the recorded findings.")
    for index, task in enumerate(tasks, 1):
        line(f"{index}. {task['severity'].upper()}", task["remediation"])
        line("Affected assets", " | ".join(sorted(task["assets"])))
        line("Related findings", " | ".join(sorted(task["findings"])))
        line("Owners", " | ".join(sorted(task["owners"])) or "Unassigned")
        line("Acceptance check", task["verification"])

    def footer(canvas, document):
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(muted)
        canvas.drawString(72, 32, f"WebGuard {VERSION}")
        canvas.drawRightString(document.pagesize[0] - 72, 32, f"Page {document.page}")

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
