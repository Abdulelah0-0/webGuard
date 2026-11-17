"""Inspect a local OpenAPI 3 JSON document without resolving external references."""
import json
from pathlib import Path

METHODS = ("get", "head", "options", "post", "put", "patch", "delete", "trace")


def inspect_spec(path):
    with Path(path).open("rb") as stream:
        data = stream.read(2_000_001)
    if len(data) > 2_000_000:
        raise ValueError("OpenAPI JSON exceeds 2 MB.")
    document = json.loads(data.decode("utf-8-sig"))
    if not isinstance(document, dict) or not str(document.get("openapi", "")).startswith("3."):
        raise ValueError("Select an OpenAPI 3 JSON document.")
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("Invalid OpenAPI paths.")
    rows = []
    for route, item in sorted(paths.items()):
        if not route.startswith("/") or not isinstance(item, dict):
            raise ValueError("Invalid OpenAPI path item.")
        if "$ref" in item:
            rows.append(("", route, "reference"))
            continue
        for method in METHODS:
            if method not in item:
                continue
            operation = item[method]
            if not isinstance(operation, dict):
                raise ValueError("Invalid OpenAPI operation.")
            security = operation.get("security", document.get("security", []))
            if not isinstance(security, list) or any(not isinstance(rule, dict) for rule in security):
                raise ValueError("Invalid OpenAPI security declaration.")
            state = "optional" if any(not rule for rule in security) else "required" if security else "none"
            rows.append((method.upper(), route, state))
    return rows
