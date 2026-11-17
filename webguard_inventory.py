"""Import inventory from saved documents; never fetch references or submit operations."""
import json
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

from webguard_scope import MAX_PAGES, scope_urls


def import_inventory(start, files):
    origin = urlsplit(scope_urls(start, [])[0])
    root = f"{origin.scheme}://{origin.netloc}/"
    urls = {}
    skipped = 0
    for file in files:
        path = Path(file)
        with path.open("rb") as stream:
            data = stream.read(2_000_001)
        if len(data) > 2_000_000:
            raise ValueError("Inventory files are limited to 2 MB.")
        text = data.decode("utf-8-sig")
        if path.suffix.lower() == ".xml":
            if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
                raise ValueError("XML declarations of entities or DTDs are unsupported.")
            tree = ElementTree.fromstring(text)
            if tree.tag.rsplit("}", 1)[-1] != "urlset":
                raise ValueError("Select a URL sitemap. For an index, select the constituent XML files.")
            candidates = [loc.text.strip() for url in tree.findall("{*}url")
                          for loc in url.findall("{*}loc") if loc.text]
        else:
            candidates = api_urls(json.loads(text), root)
        for candidate in candidates:
            try:
                if "," in candidate or urlsplit(candidate).scheme not in {"http", "https"}:
                    raise ValueError
                approved = scope_urls(start, [candidate])
            except ValueError:
                skipped += 1
                continue
            if len(approved) == 2:
                urls[approved[1]] = None
    available = list(urls)
    return available[:MAX_PAGES - 1], skipped + max(0, len(available) - MAX_PAGES + 1)


def api_urls(document, root):
    if not isinstance(document, dict) or not str(document.get("openapi", "")).startswith("3."):
        raise ValueError("Select an OpenAPI 3 JSON document.")
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("Invalid OpenAPI paths.")
    urls = []
    for route, item in paths.items():
        if not route.startswith("/") or route.startswith("//") or "{" in route or not isinstance(item, dict):
            continue
        operation = item.get("get")
        if not isinstance(operation, dict) or "$ref" in item or "$ref" in operation:
            continue
        servers = operation.get("servers", item.get("servers", document.get("servers"))) or [{"url": "/"}]
        if not isinstance(servers, list):
            raise ValueError("Invalid OpenAPI servers.")
        for server in servers:
            base = server.get("url") if isinstance(server, dict) else None
            if not isinstance(base, str) or "{" in base or urlsplit(base).query or urlsplit(base).fragment:
                continue
            urls.append(urljoin(root, base).rstrip("/") + route)
    return urls


def batch_rows(urls, entries):
    observed = dict(entries)
    rows = []
    for url in urls:
        if url not in observed:
            state, status = "not_attempted", None
        elif observed[url] is None:
            state, status = "failed", None
        else:
            report = observed[url]
            status = report["status"]
            state = ("redirect" if 300 <= status < 400 else "http_error" if status >= 400 else
                     "limited" if report.get("html_status") in {"partial", "failed"} or report.get("body_truncated")
                     else "complete")
        rows.append((url, state, status))
    return rows
