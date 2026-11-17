"""Import a documented CSV profile and local SARIF 2.1.0 reports."""
import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from webguard_workspace import _read_json, import_entries, import_findings

CSV_COLUMNS = {"asset", "id", "source", "kind", "severity", "title", "evidence", "observed_at", "impact"}
SARIF_LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def _csv_rows(path):
    with Path(path).open("rb") as stream:
        data = stream.read(12_000_001)
    if len(data) > 12_000_000:
        raise ValueError("CSV file exceeds 12 MB.")
    reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig"), newline=""), strict=True)
    fields = reader.fieldnames or []
    if not CSV_COLUMNS <= set(fields) or len(set(fields)) != len(fields):
        raise ValueError("CSV requires the documented header with no repeated columns.")
    rows = []
    try:
        for row in reader:
            if None in row or None in row.values():
                raise ValueError(f"Invalid column count on CSV line {reader.line_num}.")
            rows.append({key: value for key, value in row.items() if value.strip()})
    except csv.Error as error:
        raise ValueError(f"Invalid CSV near line {reader.line_num}: {error}") from None
    return rows


def _location(result, artifacts):
    labels, identifiers = [], []
    for location in result.get("locations", [])[:10]:
        physical = location.get("physicalLocation", {})
        artifact = physical.get("artifactLocation", {})
        index = artifact.get("index")
        default = artifacts[index].get("location", {}) if isinstance(index, int) and 0 <= index < len(artifacts) else {}
        parsed = urlsplit(artifact.get("uri") or default.get("uri", ""))
        region = physical.get("region", {})
        identifiers.append([artifact.get("uriBaseId", default.get("uriBaseId")), parsed.scheme,
                            parsed.hostname, parsed.path, region.get("startLine"), region.get("startColumn")])
        # Remove query, fragment and URL credentials. Do not open or resolve paths.
        path = parsed.path.replace("\\", "/")
        if path.startswith("/") or parsed.scheme:
            path = path.rsplit("/", 1)[-1]
        start = physical.get("region", {}).get("startLine")
        if path:
            labels.append(f"{path}:{start}" if isinstance(start, int) and start > 0 else path)
    return " | ".join(labels), identifiers


def _sarif_rows(data, asset):
    if not isinstance(data, dict) or data.get("version") != "2.1.0" or not isinstance(data.get("runs"), list):
        raise ValueError("Expected a SARIF 2.1.0 document.")
    rows = {}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for run in data["runs"]:
        driver = run.get("tool", {}).get("driver", {})
        tool = (driver.get("name") or "SARIF")[:112]
        rules = driver.get("rules", [])
        rules_by_id = {rule.get("id"): rule for rule in rules}
        for result in run.get("results") or []:
            if result.get("baselineState") == "absent" or any(
                item.get("status", "accepted") == "accepted" for item in result.get("suppressions", [])
            ):
                continue
            index = result.get("ruleIndex")
            rule_id = result.get("ruleId")
            if not rule_id and isinstance(index, int) and 0 <= index < len(rules):
                rule_id = rules[index].get("id")
            rule_id = rule_id or "Unspecified rule"
            rule = rules_by_id.get(rule_id, {})
            message = result.get("message", {})
            detail = message.get("text") or message.get("markdown") or message.get("id") or "No message supplied."
            location, identifiers = _location(result, run.get("artifacts", []))
            fingerprints = result.get("fingerprints")
            identity = [tool, rule_id, fingerprints] if fingerprints else [tool, rule_id, identifiers, detail]
            digest = hashlib.sha256(json.dumps(identity, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()[:24]
            key = f"{rule_id[:70]}-{digest}"
            level = result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
            help_text = rule.get("help", {}).get("text")
            title = rule.get("shortDescription", {}).get("text") or rule.get("name") or rule_id
            rows[(tool, key)] = {
                "asset": asset, "source": f"SARIF / {tool}", "id": key, "kind": "OTHER",
                "severity": SARIF_LEVELS.get(level, "info"), "title": title[:200], "observed_at": now,
                "evidence": (f"{location} | {detail}" if location else detail)[:2000],
                "impact": "Tool-reported result. Review the evidence and applicability to the selected asset.",
                **({"remediation": help_text[:2000]} if help_text else {}),
            }
    return list(rows.values())


def import_report(workspace, path, asset=None):
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        return import_entries(workspace, _csv_rows(path))
    if suffix not in {".json", ".sarif"}:
        raise ValueError("Choose a WebGuard JSON, CSV, or SARIF file.")
    data = _read_json(path)
    if isinstance(data, dict) and (data.get("version") == "2.1.0" or suffix == ".sarif"):
        if asset not in workspace["assets"]:
            raise ValueError("Select the registered asset that the SARIF results apply to.")
        try:
            rows = _sarif_rows(data, asset)
        except (AttributeError, KeyError, TypeError, IndexError):
            raise ValueError("The SARIF report contains an invalid run or result.") from None
        if not rows:
            return 0
        for row in rows:
            identity = json.dumps([asset, row["source"], row["id"]], ensure_ascii=False)
            if identity in workspace["external"]:
                row["observed_at"] = workspace["external"][identity]["observed_at"]
        return import_entries(workspace, rows)
    return import_findings(workspace, path)
