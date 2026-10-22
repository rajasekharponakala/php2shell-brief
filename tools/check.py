#!/usr/bin/env python3
"""Structural verification for the PHP2Shell brief.

Usage: python3 tools/check.py [--online]

Exits 0 when every check passes, 1 otherwise. Each failure prints one
FAIL: <description> line. With --online, every external http(s) link in
index.html, data/status.json and SOURCES.md is HEAD-checked.
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
SOURCES = ROOT / "SOURCES.md"

FIXED_VERSIONS = ["8.5.12", "8.4.27", "8.3.36", "8.2.35"]
REQUIRED_SECTIONS = [
    "status", "root-cause", "impact", "versions", "do-now",
    "mitigations", "hunting", "timeline", "ai-inflection",
    "disclosure", "sources",
]
REQUIRED_STATUS_KEYS = [
    "lastUpdated", "severity", "cvss", "cvssVector", "affectedFrom",
    "fixedVersions", "cves", "exploitation", "offlineServices",
    "advisories", "timeline", "ai",
]
REQUIRED_HOOKS = [
    "data-status-timestamp", "data-status-severity", "data-status-severity-line",
    "data-status-versions", "data-status-fixed", "data-status-fixed-inline",
    "data-status-exploitation", "data-status-offline", "data-status-advisories",
    "data-status-timeline", "data-status-cves", "data-status-tiles",
    "data-status-footer-timestamp",
]
REQUIRED_PHRASES = [
    "memory_limit", "post_max_size", "session.upload_progress.enabled",
    "fatal_error_backtraces", "PHPSESSID", "mod_php", "PHP-FPM",
    "restart every worker", "RLIMIT_AS", "nine hours", "block mode",
    "exploitation attempts that followed the disclosure",
    "Defender's Window",
]
FORBIDDEN_PHRASES = [
    "the exploitation that followed",
    "Phishing campaigns ride on headlines",
    "more than a day",
]
# claim text -> required host in the href of the anchor that carries it
INLINE_LINK_RULES = [
    ("70% of the web", "wiz.io"),
    ("$1 billion", "openai.com"),
    ("15 CVEs", "thephp.foundation"),
]
BANNED_TEXT = ["TBD", "TODO", "FIXME", "Lorem ipsum", "lorem ipsum", "XXX"]

failures = []


def fail(message):
    failures.append(message)


def rel(path):
    return str(path.relative_to(ROOT))


class Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = []
        self.anchors = []          # (href, text)
        self.text = []             # all text
        self.body_text = []        # text outside <noscript>
        self.noscript_text = []
        self._anchor_stack = []
        self._noscript_depth = 0
        self._in_title = False
        self.title = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])
            self._anchor_stack.append([attrs["href"], ""])
        if tag == "noscript":
            self._noscript_depth += 1
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "a" and self._anchor_stack:
            href, text = self._anchor_stack.pop()
            self.anchors.append((href, text))
        if tag == "noscript" and self._noscript_depth:
            self._noscript_depth -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        self.text.append(data)
        if self._noscript_depth:
            self.noscript_text.append(data)
        else:
            self.body_text.append(data)
        if self._anchor_stack:
            self._anchor_stack[-1][1] += data


def contrast_ratio(hex_a, hex_b):
    def luminance(value):
        value = value.lstrip("#")
        channels = [int(value[i:i + 2], 16) / 255 for i in (0, 2, 4)]
        linear = [
            c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
            for c in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    light, dark = sorted((luminance(hex_a), luminance(hex_b)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def check_files():
    for path in (INDEX, STATUS, ROOT / "styles.css", ROOT / "main.js",
                 ROOT / "README.md", SOURCES):
        if not path.exists():
            fail(f"missing required file: {rel(path)}")
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
    if "honeypot" not in json.dumps(data):
        fail("data/status.json must describe the Amazon attempt as a honeypot detection")
    for entry in data.get("offlineServices", []) + data.get("advisories", []):
        url = entry.get("source") or entry.get("url")
        if not url or not url.startswith("http"):
            fail(f"data/status.json entry without a source URL: {entry}")
    return data


def check_renderer():
    served = ROOT / "main.js"
    if not served.exists():
        fail("main.js is missing, cannot verify it reads data/status.json")
        return
    source = served.read_text()
    for key in ("lastUpdated", "fixedVersions", "exploitation", "advisories",
                "timeline", "cves", "ai"):
        if key not in source:
            fail(f"main.js does not read status.json key: {key}")
    for needed in ("keydown", ".catch(", "aria-label", "execCommand"):
        if needed not in source:
            fail(f"main.js is missing required behaviour: {needed}")


def check_hooks():
    """Render hooks must exist in the markup, whatever else is missing."""
    html = INDEX.read_text() if INDEX.exists() else ""
    for hook in REQUIRED_HOOKS:
        if hook not in html:
            fail(f"index.html missing render hook: {hook}")


def check_styles():
    """Stylesheet rules and palette contrast the page depends on."""
    css = ROOT / "styles.css"
    if not css.exists():
        return
    source = css.read_text()
    if ":focus-visible" not in source:
        fail("styles.css has no :focus-visible styles")
    if not re.search(r"\.section[^{]*\{[^}]*scroll-margin-top", source):
        fail("styles.css sets no scroll-margin-top on .section, the sticky nav covers headings")
    if not re.search(r"\.mono[^{]*\{[^}]*overflow-wrap", source):
        fail("styles.css does not let long .mono tokens wrap, long values overflow on mobile")
    faint = re.search(r"--faint:\s*(#[0-9a-fA-F]{6})", source)
    ink = re.search(r"--ink:\s*(#[0-9a-fA-F]{6})", source)
    if faint and ink:
        ratio = contrast_ratio(faint.group(1), ink.group(1))
        if ratio < 4.5:
            fail(f"--faint on --ink contrast is {ratio:.2f}:1, WCAG AA needs 4.5:1")
    else:
        fail("styles.css must define --faint and --ink as hex colours")


def check_markup(collector, status):
    for section in REQUIRED_SECTIONS:
        if section not in collector.ids:
            fail(f"index.html missing section id: {section}")
    for link in collector.links:
        if link.startswith("#") and len(link) > 1:
            if link[1:] not in collector.ids:
                fail(f"index.html anchor has no target: {link}")
    body = " ".join(collector.text)
    body_outside_noscript = " ".join(collector.body_text)
    noscript = " ".join(collector.noscript_text)
    for banned in BANNED_TEXT:
        if banned in body:
            fail(f"index.html contains banned placeholder text: {banned}")
    if "CVE-2026-109618" not in body or "CVE-2026-109619" not in body:
        fail("index.html must name both CVE identifiers")
    for version in FIXED_VERSIONS:
        if version not in body and version not in json.dumps(status or {}):
            fail(f"fixed version {version} appears nowhere on the page or in status.json")
        if version in body_outside_noscript:
            fail(f"fixed version {version} is hardcoded in prose, it must come from data/status.json")
    if status:
        cvss = status.get("cvss")
        if cvss and cvss not in noscript:
            fail("the <noscript> fallback must carry the CVSS score so it matches status.json")
        for version in FIXED_VERSIONS:
            if version not in noscript:
                fail(f"the <noscript> fallback must list fixed version {version}")
    for phrase in REQUIRED_PHRASES:
        if phrase not in body:
            fail(f"index.html missing required phrase: {phrase}")
    for phrase in FORBIDDEN_PHRASES:
        if phrase in body:
            fail(f"index.html contains an overclaiming phrase: {phrase}")
    for claim, host in INLINE_LINK_RULES:
        matches = [href for href, text in collector.anchors if claim in text]
        if not matches:
            fail(f"no link carries the claim {claim!r}, it must be sourced inline")
        elif not any(host in href for href in matches):
            fail(f"the claim {claim!r} is not linked to {host}")
    if "nav__toggle" not in INDEX.read_text() or "aria-expanded" not in INDEX.read_text():
        fail("index.html nav must use a collapsible toggle button on mobile")
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


def collect_urls(status):
    urls = set()
    collector = Collector()
    if INDEX.exists():
        collector.feed(INDEX.read_text())
        for link in collector.links:
            if link.startswith("http://") or link.startswith("https://"):
                urls.add(link)
    for source in (status or {}).get("exploitation", {}).get("events", []):
        if source.get("source"):
            urls.add(source["source"])
    for entry in (status or {}).get("offlineServices", []) + (status or {}).get("advisories", []):
        url = entry.get("source") or entry.get("url")
        if url:
            urls.add(url)
    if SOURCES.exists():
        urls.update(re.findall(r"https?://[^\s\)\]]+", SOURCES.read_text()))
    return urls


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
    status = check_status()
    check_renderer()
    check_hooks()
    check_styles()
    collector = Collector()
    external = []
    if INDEX.exists():
        collector.feed(INDEX.read_text())
        external = check_markup(collector, status)
        check_no_external_assets()
    external.extend(url for url in collect_urls(status) if url not in external)
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
