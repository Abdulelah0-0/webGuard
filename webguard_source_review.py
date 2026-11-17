"""Offline review of potentially unsafe construction in Python source."""
import ast
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from webguard_workspace import KINDS

MAX_SOURCE = 500_000


def _constructed(expression):
    if isinstance(expression, ast.JoinedStr):
        return any(isinstance(part, ast.FormattedValue) for part in expression.values)
    if isinstance(expression, ast.BinOp):
        return isinstance(expression.op, (ast.Add, ast.Mod)) and not (
            isinstance(expression.left, ast.Constant) and isinstance(expression.right, ast.Constant)
        )
    return (isinstance(expression, ast.Call) and isinstance(expression.func, ast.Attribute)
            and expression.func.attr in {"format", "format_map"})


def review_source(workspace, asset, path):
    if asset not in workspace["assets"]:
        raise ValueError("Register the corresponding asset first.")
    path = Path(path)
    if path.suffix.lower() != ".py":
        raise ValueError("Select a Python source file (.py).")
    with path.open("rb") as stream:
        data = stream.read(MAX_SOURCE + 1)
    if len(data) > MAX_SOURCE:
        raise ValueError("Source file exceeds 500 KB.")
    try:
        tree = ast.parse(data, filename=path.name)
    except (SyntaxError, ValueError, RecursionError):
        raise ValueError("Python source could not be parsed.") from None

    source = f"WebGuard offline review / {path.name}"
    digest = hashlib.sha256(data).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    observations = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args or not _constructed(node.args[0]):
            continue
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany", "executescript"}:
            kind = "SQL_INJECTION"
            title = "Review dynamically constructed database statement"
            impact = "If untrusted input reaches this construction, it could alter query meaning."
            api = node.func.attr
        elif ((isinstance(node.func, ast.Name) and node.func.id == "render_template_string") or
              (isinstance(node.func, ast.Attribute) and node.func.attr == "render_template_string")):
            kind = "OTHER"
            title = "Review dynamically constructed template source"
            impact = "If untrusted input reaches the template source, template injection or unsafe output may result."
            api = "render_template_string"
        else:
            continue
        key = f"PY-{api.upper()}-{node.lineno}-{node.col_offset}"
        identity = json.dumps([asset, source, key], ensure_ascii=False)
        containment, remedy, verification = KINDS[kind]
        if kind == "OTHER":
            remedy = "Keep the template source fixed and pass variable content as context data. Keep autoescaping enabled."
            verification = "Review template construction and test output encoding in each affected rendering context."
        observations[identity] = {
            "asset": asset, "id": key, "source": source, "kind": kind,
            "state": "needs_review", "severity": "medium", "title": title,
            "evidence": f"{api} receives constructed input at line {node.lineno}. Source SHA-256: {digest}.",
            "observed_at": timestamp, "impact": impact, "containment": containment,
            "remediation": remedy, "verification": verification,
        }
    workspace["external"] = {
        key: item for key, item in workspace["external"].items()
        if not (item.get("origin") == "local_static_review" and
                item["asset"] == asset and item["source"] == source)
    }
    for item in observations.values():
        item["origin"] = "local_static_review"
    workspace["external"].update(observations)
    return len(observations)
