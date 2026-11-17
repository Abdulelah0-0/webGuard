"""Local SQLite history. Callers pass the path so tests can isolate storage."""
from collections import Counter
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3


def history_path():
    return Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "WebGuard" / "scans.sqlite3"


def _connect(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    try:
        db.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY, target TEXT NOT NULL, observed TEXT NOT NULL,
            count INTEGER NOT NULL, report TEXT NOT NULL
        )""")
    except BaseException:
        db.close()
        raise
    return db


def save_scan(path, report):
    with closing(_connect(path)) as db, db:
        cursor = db.execute("INSERT INTO scans (target, observed, count, report) VALUES (?, ?, ?, ?)",
                            (report["url"], report["checked_at"], len(report["findings"]),
                             json.dumps(report, ensure_ascii=False)))
        return cursor.lastrowid


def recent_scans(path):
    with closing(_connect(path)) as db:
        return db.execute("SELECT id, target, observed, count FROM scans ORDER BY id DESC LIMIT 200").fetchall()


def read_scan(path, scan_id):
    with closing(_connect(path)) as db:
        row = db.execute("SELECT report FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise ValueError("The selected scan is unavailable.")
    return json.loads(row[0])


def compare_scans(before, after):
    if before["url"] != after["url"] or any(item.get("scope_redacted") for item in (before, after)):
        raise ValueError("Choose scans of the same URL and privacy scope.")
    counts = [Counter(item["id"] for item in report["findings"]) for report in (before, after)]
    previous, current = counts
    comparable = (
        all(report.get("response_kind") == "response" and 200 <= report["status"] < 300
            for report in (before, after)) and
        before.get("scan_mode") == after.get("scan_mode") and
        before["status"] == after["status"] and
        before.get("html_status") == after.get("html_status") and
        all(not report.get("body_truncated") and report.get("html_status") not in {"failed", "partial", "empty"}
            for report in (before, after))
    )
    def evidence(report):
        by_check = {}
        for item in report["findings"]:
            by_check.setdefault(item["id"], Counter())[
                (item.get("severity"), item.get("message"), item.get("evidence"))] += 1
        return by_check

    old_evidence, new_evidence = evidence(before), evidence(after)
    keys = sorted(previous.keys() | current.keys())
    return {"comparable": comparable, "rows": [
        (key, previous[key], current[key]) for key in keys
    ], "changed_evidence": [key for key in keys if old_evidence.get(key) != new_evidence.get(key)]}
