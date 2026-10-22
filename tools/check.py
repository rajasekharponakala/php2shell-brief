#!/usr/bin/env python3
"""Structural verification for the PHP2Shell brief.

Usage: python3 tools/check.py [--online]

Exits 0 when every check passes, 1 otherwise. Each failure prints one
FAIL: <description> line. With --online, every external http(s) link in
index.html is HEAD-checked and any non-2xx/3xx status is a failure.
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INDEX = ROOT / "index.html"
STATUS = ROOT / "data" / "status.json"

FIXED_VERSIONS = {"8.5.12", "8.4.27", "8.3.36", "8.2.35"}
REQUIRED_SECTIONS = [
    "status", "root-cause", "impact", "versions", "do-now",
    "mitigations", "hunting", "timeline", "ai-inflection",
    "disclosure", "sources",
]
REQUIRED_STATUS_KEYS = [
    "lastUpdated", "severity", "cvss", "affectedFrom", "fixedVersions",
    "exploitation", "offlineServices", "advisories", "timeline",
]
BANNED_TEXT = ["TBD", "TODO", "FIXME", "Lorem ipsum", "lorem ipsum", "XXX"]

failures = []


def fail(message):
    failures.append(message)


class Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = []
        self.text = []
        self._in_title = False
        self.title = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        self.text.append(data)


def check_files():
    for path in (INDEX, STATUS, ROOT / "styles.css", ROOT / "main.js"):
        if not path.exists():
            fail(f"missing required file: {path.relative_to(ROOT)}")
    if (ROOT / ".nojekyll").exists():
        if (ROOT / ".nojekyll").read_text().strip():
            fail(".nojekyll must be empty")


def check_status():
    try:
        data = json.loads(STATUS.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"data/status.json is not valid JSON: {exc}")
        return None
    for key in REQUIRED_STATUS_KEYS:
        if key not in data:
            fail(f"data/status.json missing key: {key}")
    fixed = data.get("fixedVersions")
    if isinstance(fixed, list):
        for entry in fixed:
            version = entry.get("version") if isinstance(entry, dict) else entry
            if version not in FIXED_VERSIONS:
                fail(f"data/status.json fixed version not in approved set: {version}")
    if data.get("cvss") != "9.2":
        fail(f"data/status.json cvss must be '9.2', got {data.get('cvss')!r}")
    return data


def check_renderer():
    served = ROOT / "main.js"
    if not served.exists():
        fail("main.js is missing, cannot verify it reads data/status.json")
        return
    source = served.read_text()
    for key in ("lastUpdated", "fixedVersions", "exploitation", "advisories", "timeline"):
        if key not in source:
            fail(f"main.js does not read status.json key: {key}")


def check_hooks():
    """Render hooks must exist in the markup, whatever else is missing."""
    html = INDEX.read_text() if INDEX.exists() else ""
    for hook in ("data-status-timestamp", "data-status-severity", "data-status-versions",
                 "data-status-exploitation", "data-status-offline", "data-status-advisories",
                 "data-status-timeline"):
        if hook not in html:
            fail(f"index.html missing render hook: {hook}")


def check_markup(collector):
    for section in REQUIRED_SECTIONS:
        if section not in collector.ids:
            fail(f"index.html missing section id: {section}")
    for link in collector.links:
        if link.startswith("#") and len(link) > 1:
            if link[1:] not in collector.ids:
                fail(f"index.html anchor has no target: {link}")
    body = " ".join(collector.text)
    for banned in BANNED_TEXT:
        if banned in body:
            fail(f"index.html contains banned placeholder text: {banned}")
    if "CVE-2026-109618" not in body or "CVE-2026-109619" not in body:
        fail("index.html must name both CVE identifiers")
    for version in FIXED_VERSIONS:
        if version not in body and version not in json.dumps(
            json.loads(STATUS.read_text()) if STATUS.exists() else {}
        ):
            fail(f"fixed version {version} appears nowhere on the page or in status.json")
    external = [
        link for link in collector.links
        if link.startswith("http://") or link.startswith("https://")
    ]
    return external


def check_no_external_assets():
    html = INDEX.read_text() if INDEX.exists() else ""
    for pattern in (r'src\s*=\s*["\']https?://', r'href\s*=\s*["\']https?://[^"\']+\.css'):
        if re.search(pattern, html):
            fail(f"index.html loads an external asset, pattern matched: {pattern}")
    if "fonts.googleapis.com" in html or "cdn.jsdelivr.net" in html:
        fail("index.html references a CDN or web font")


def check_online(urls):
    for url in sorted(set(urls)):
        request = urllib.request.Request(
            url, method="HEAD", headers={"User-Agent": "php2shell-brief-linkcheck"}
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.status >= 400:
                    fail(f"external link returned {response.status}: {url}")
        except urllib.error.HTTPError as exc:
            if exc.code not in (403, 405):
                fail(f"external link returned {exc.code}: {url}")
        except Exception as exc:  # noqa: BLE001 - report any transport failure
            fail(f"external link failed ({exc.__class__.__name__}): {url}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--online", action="store_true")
    args = parser.parse_args()

    check_files()
    check_status()
    check_renderer()
    check_hooks()
    collector = Collector()
    if INDEX.exists():
        collector.feed(INDEX.read_text())
        external = check_markup(collector)
        check_no_external_assets()
    else:
        external = []
    if args.online:
        check_online(external)

    if failures:
        for message in failures:
            print(f"FAIL: {message}")
        return 1
    print("OK: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
