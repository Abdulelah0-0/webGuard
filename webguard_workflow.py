"""Finding assignment, verification history, incident notes and remediation planning."""
import hashlib
import json
from datetime import datetime, timezone

STATUSES = {
    "review": "Needs review", "open": "Open", "working": "In progress",
    "verify": "Ready for verification", "verified": "Verified fixed",
}
LEVELS = ("high", "medium", "low", "info")
INCIDENT_FIELDS = {
    "observed_at": "Observed at / time window",
    "affected_assets": "Affected assets",
    "log_references": "Log and evidence references",
    "containment_taken": "Containment actions taken",
    "open_questions": "Open questions",
}


def _key(*parts):
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode("utf-8")).hexdigest()


def finding_groups(workspace):
    groups = {}

    def add(key, asset, title, level, remediation, verification, evidence):
        group = groups.setdefault(key, {"asset": asset, "title": title, "severity": level,
                                       "actions": [], "evidence": []})
        if LEVELS.index(level) < LEVELS.index(group["severity"]):
            group["severity"] = level
        action = (remediation, verification)
        if action not in group["actions"]:
            group["actions"].append(action)
        group["evidence"].append(evidence)

    for asset, scan in workspace["assets"].items():
        if scan:
            for item in scan["findings"]:
                add(_key("webguard", asset, item["id"], item["evidence"]), asset, item["message"],
                    item["severity"], item["recommendation"],
                    "Repeat the same response-based check after deployment.",
                    {"source": "WebGuard", "id": item["id"], "text": item["evidence"],
                     "observed_at": scan["checked_at"]})
    for identity, item in workspace["external"].items():
        correlation = item.get("correlation_id")
        key = _key("correlation", item["asset"], item["kind"], correlation) if correlation else _key("external", identity)
        add(key, item["asset"], item["title"], item["severity"], item["remediation"], item["verification"],
            {"source": item["source"], "id": item["id"], "text": item["evidence"],
             "observed_at": item["observed_at"]})
    return groups


def finding_rows(workspace):
    groups = finding_groups(workspace)
    tracked = workspace.get("tracking", {})
    rows = []
    for key in groups.keys() | tracked.keys():
        entry = tracked.get(key, {})
        current = groups.get(key)
        group = current or entry["snapshot"]
        recheck = bool(current and entry.get("status") == "verified" and
                       current["evidence"] != entry["snapshot"]["evidence"])
        rows.append({"key": key, **group, "current": current is not None, "recheck": recheck,
                     "status": entry.get("status", "review"), "owner": entry.get("owner", ""),
                     "history": entry.get("history", [])})
    return sorted(rows, key=lambda row: (LEVELS.index(row["severity"]), row["asset"], row["title"], row["key"]))


def update_finding(workspace, key, status, owner, note):
    row = next((row for row in finding_rows(workspace) if row["key"] == key), None)
    if row is None or status not in STATUSES:
        raise ValueError("Invalid finding or status.")
    owner, note = owner.strip(), note.strip()
    if len(owner) > 120 or len(note) > 4000:
        raise ValueError("Owner is limited to 120 characters and notes to 4,000.")
    if status == "verified" and not note and (row["status"] != "verified" or row["recheck"]):
        raise ValueError("Add verification evidence before marking this finding as verified fixed.")
    if status == row["status"] and owner == row["owner"] and not note:
        return
    event = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "status": status, "owner": owner, "note": note}
    snapshot = {field: row[field] for field in ("asset", "title", "severity", "actions", "evidence")}
    workspace.setdefault("tracking", {})[key] = {
        "status": status, "owner": owner, "snapshot": snapshot, "history": [*row["history"], event],
    }


def update_incident(workspace, values):
    notes = {key: values.get(key, "").strip() for key in INCIDENT_FIELDS}
    if any(len(value) > 4000 for value in notes.values()):
        raise ValueError("Incident fields are limited to 4,000 characters each.")
    workspace["incident"] = notes


def remediation_plan(workspace):
    tasks = {}
    for row in finding_rows(workspace):
        if row["status"] == "verified" and not row["recheck"]:
            continue
        for remediation, verification in row["actions"]:
            generic = remediation.startswith("Review the imported evidence and apply a fix")
            key = (remediation, verification, row["title"] if generic else "")
            task = tasks.setdefault(key, {"remediation": remediation, "verification": verification,
                                          "severity": row["severity"], "assets": set(), "owners": set(),
                                          "findings": set()})
            if LEVELS.index(row["severity"]) < LEVELS.index(task["severity"]):
                task["severity"] = row["severity"]
            task["assets"].add(row["asset"])
            if row["owner"]:
                task["owners"].add(row["owner"])
            task["findings"].add(row["title"])
    return sorted(tasks.values(), key=lambda task: (LEVELS.index(task["severity"]), task["remediation"]))
