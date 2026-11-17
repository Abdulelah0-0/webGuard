"""Bounded passive audits of an explicit, same-origin URL list."""
from html.parser import HTMLParser
from pathlib import Path
from threading import Event
from time import monotonic
from urllib.parse import urljoin, urlsplit

from webguard import ScanError, normalize_url, scan

MAX_PAGES = 50


def scope_urls(start, lines):
    start = normalize_url(start)

    def origin(url):
        parts = urlsplit(url)
        return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)

    urls = list(dict.fromkeys([start, *(normalize_url(line) for line in lines if line.strip())]))
    if len(urls) > MAX_PAGES:
        raise ValueError("Maximum 50 URLs per assessment.")
    if any(origin(url) != origin(start) or urlsplit(url).query for url in urls):
        raise ValueError("Use same-origin URLs without query strings for a standard assessment.")
    return urls


def audit_urls(urls, timeout, cancel=None):
    urls = scope_urls(urls[0], urls[1:])
    cancel = cancel if cancel is not None else Event()
    deadline = monotonic() + timeout
    results = []
    for index, url in enumerate(urls):
        if index and cancel.wait(1):
            break
        remaining = deadline - monotonic()
        if cancel.is_set() or remaining <= 0:
            break
        try:
            report = scan(url, remaining, hide_path=False, cancel=cancel)
        except ScanError:
            if not cancel.is_set():
                results.append((url, None))
        else:
            report["scan_mode"] = "standard"
            results.append((url, report))
    return results


def discover_saved_html(start, file):
    """Suggest internal links from a local document without making network requests."""
    start = scope_urls(start, [])[0]
    with Path(file).open("rb") as source:
        data = source.read(1_000_001)
    if len(data) > 1_000_000:
        raise ValueError("Saved HTML exceeds 1 MB.")
    proposed = {}

    class Links(HTMLParser):
        def handle_starttag(self, tag, attrs):
            if tag != "a" or len(proposed) >= MAX_PAGES - 1:
                return
            href = dict(attrs).get("href")
            if not href or href.startswith("#"):
                return
            try:
                candidate = urljoin(start, href)
                if urlsplit(candidate).scheme not in {"http", "https"}:
                    return
                scoped = scope_urls(start, [candidate])
            except ValueError:
                return
            if len(scoped) == 2 and "," not in scoped[1]:
                proposed[scoped[1]] = None

    parser = Links()
    parser.feed(data.decode("utf-8-sig", "replace"))
    parser.close()
    return list(proposed)
