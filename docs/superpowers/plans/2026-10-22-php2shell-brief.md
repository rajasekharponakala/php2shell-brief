# PHP2Shell Status Brief Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish a factual, dependency-free GitHub Pages brief on the PHP core RCE vulnerabilities CVE-2026-109618 / CVE-2026-109619 ("php2shell"), live at `https://rajasekharponakala.github.io/php2shell-brief/`.

**Architecture:** Static site — one `index.html` holding all twelve sections, `styles.css` for the design system, `main.js` to render volatile values out of `data/status.json`, and inline SVG for the root-cause diagram. No build step, no npm, no external requests. A committed verification script (`tools/check.py`, stdlib only) validates structure, data shape, anchors and (optionally) external links, so a broken edit fails loudly instead of shipping.

**Tech Stack:** HTML5, CSS custom properties, vanilla ES2020 JavaScript, GitHub Actions `actions/deploy-pages`, Python 3 stdlib for verification.

**Spec:** `docs/superpowers/specs/2026-10-22-php2shell-brief-design.md`

## Global Constraints

- Repository `rajasekharponakala/php2shell-brief`, public, default branch `main`.
- Zero runtime dependencies: no npm packages, no CDN links, no web fonts, no analytics, no trackers, no external images.
- Page title and metadata must name the two CVEs exactly: `CVE-2026-109618` and `CVE-2026-109619`.
- Severity is stated only as `CVSS v4.0 9.2` (Critical). The `10.0` figure that circulated on 2026-10-20 is an error and is only ever described as wrong.
- Fixed versions are exactly `8.5.12`, `8.4.27`, `8.3.36`, `8.2.35`. Never write a version that is not in that set as "fixed".
- Affected range is `PHP 5.4` and later; PHP `8.1` and older get no upstream updates.
- Every quantitative claim in the page carries a hyperlink to the source that states it.
- Footer states: the page is a secondary summary and php.net plus the national CERT advisories are authoritative.
- `data/status.json` is the single source for the timestamp, severity, version matrix, exploitation figures and advisory list. `index.html` must not hardcode those values.
- Style palette is fixed in the spec: `--ink #0b0d10`, `--ink-2 #12161b`, `--ink-3 #191f26`, `--text #e8eaed`, `--muted #9aa4b0`, `--faint #6b7682`, `--alert #ff4d3d`, `--warn #ffb020`, `--ok #35c46b`.
- No `TBD`, `TODO`, `Lorem ipsum`, or empty section bodies anywhere in the repository.

## Review Focus

Five input classes or failure modes the spec implies but that no structural check exercises; each is pinned to a test in the owning task.

1. `data/status.json` edited with a fixed version outside `8.5.12 / 8.4.27 / 8.3.36 / 8.2.35` → the check must fail, not silently publish a wrong patch version (Task 2).
2. `data/status.json` missing or malformed → the page must still render every section and show a visible "status unavailable" state instead of a blank tile (Task 2).
3. An in-page link `#section-id` whose target was renamed → the check must fail (Task 3).
4. Mobile viewport (390px) → the sticky nav must not cover the first heading and tables must scroll inside their own container rather than breaking the layout (Task 7).
5. An external advisory link that goes dead or redirects off the expected host → the online link check must report it (Task 1).

---

### Task 1: Verification harness and repository scaffold

**Files:**
- Create: `tools/check.py`
- Create: `.nojekyll`
- Create: `.gitignore`
- Create: `LICENSE`
- Create: `.github/workflows/pages.yml`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `python3 tools/check.py` — exits 0 when the site is sound, exits 1 with a list of failures otherwise. Supports `--online` to additionally HEAD-check every external URL. Later tasks extend this file's assertions; they must keep the exit-code contract and the `FAIL:` prefix format.

- [ ] **Step 1: Write the failing check script**

Create `tools/check.py`:

```python
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
```

- [ ] **Step 2: Run the check to verify it fails**

Run: `cd /home/rajasekhar/opencode-brain/php2shell-brief && python3 tools/check.py`
Expected: FAIL — `missing required file: index.html` and the other missing-file failures.

- [ ] **Step 3: Add the scaffold files**

`.nojekyll` — empty file.

`.gitignore`:
```
.DS_Store
__pycache__/
*.pyc
```

`LICENSE` — MIT, copyright line `Copyright (c) 2026 rajasekhar`.

`.github/workflows/pages.yml`:
```yaml
name: Deploy Pages

on:
  push:
    branches: ["main"]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: false

jobs:
  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with:
          path: .
      - id: deployment
        uses: actions/deploy-pages@v4
```

- [ ] **Step 4: Run the check again**

Run: `python3 tools/check.py`
Expected: FAIL only on the still-missing `index.html`, `styles.css`, `main.js`, `data/status.json` — no other failure classes appear yet.

- [ ] **Step 5: Commit**

```bash
git add tools/check.py .nojekyll .gitignore LICENSE .github/workflows/pages.yml
git commit -m "chore: add verification harness and pages deploy workflow"
```

---

### Task 2: Status data model and renderer

**Files:**
- Create: `data/status.json`
- Create: `main.js`
- Modify: `tools/check.py`

**Interfaces:**
- Consumes: `tools/check.py` from Task 1.
- Produces: `data/status.json` with keys `lastUpdated`, `severity`, `cvss`, `affectedFrom`, `fixedVersions`, `exploitation`, `offlineServices`, `advisories`, `timeline`. `main.js` exposes `window.renderStatus(data)` (no arguments beyond the data) and, on `DOMContentLoaded`, fetches `data/status.json` with a relative path, calls `renderStatus`, and on any failure calls `renderStatus(null)` so the page still renders with a visible unavailable state.

- [ ] **Step 1: Write the failing assertion**

Append to `tools/check.py`, inside `check_status()`, after the `cvss` assertion:

```python
    served = ROOT / "main.js"
    if served.exists():
        source = served.read_text()
        for key in ("lastUpdated", "fixedVersions", "exploitation", "advisories", "timeline"):
            if key not in source:
                fail(f"main.js does not read status.json key: {key}")
```

- [ ] **Step 2: Run the check to verify it fails**

Run: `python3 tools/check.py`
Expected: FAIL — `main.js does not read status.json key: lastUpdated` (and the same for the other four keys), plus the missing-file failures for `index.html`, `styles.css`, `data/status.json`.

- [ ] **Step 3: Create `data/status.json`**

```json
{
  "lastUpdated": "2026-10-22T00:00:00Z",
  "severity": "Critical",
  "cvss": "9.2",
  "cvssVector": "CVSS v4.0",
  "affectedFrom": "5.4",
  "fixedVersions": [
    {"branch": "8.5", "version": "8.5.12", "eol": "not scheduled"},
    {"branch": "8.4", "version": "8.4.27", "eol": "not scheduled"},
    {"branch": "8.3", "version": "8.3.36", "eol": "not scheduled"},
    {"branch": "8.2", "version": "8.2.35", "eol": "2026-12-31"}
  ],
  "cves": [
    {
      "id": "CVE-2026-109618",
      "name": "RCE via OOM corruption",
      "ghsa": "GHSA-w8hw-w9fx-j79w",
      "summary": "An out-of-memory failure can interrupt PHP while request data is only partly initialised. Request cleanup then treats the invalid data as valid, corrupting memory."
    },
    {
      "id": "CVE-2026-109619",
      "name": "RCE via stale global state",
      "ghsa": "GHSA-6wmf-4rv5-p3rp",
      "summary": "Request-owned internal state can survive after its backing memory has been freed. A later request on the same worker may use that stale state before normal initialisation resets it."
    }
  ],
  "exploitation": {
    "observed": true,
    "summary": "Attempts confirmed by watchTowr, Cloudflare and Amazon; CISA had not observed exploitation when it published its alert.",
    "events": [
      {"when": "2026-10-17", "what": "Amazon reports exploit attempts against its properties, four days before public disclosure.", "source": "https://www.sophos.com/en-us/security-advisories/sophos-sa-20261021-php2shell"},
      {"when": "2026-10-20", "what": "CVE identifiers and a proof-of-concept tool circulate publicly before the coordinated disclosure.", "source": "https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/"},
      {"when": "2026-10-21", "what": "Cloudflare sees thousands of attempts in the ten hours before the announcement, tens of thousands within 45 minutes after, hundreds of thousands within two hours, and millions from there on.", "source": "https://www.bbc.com/news/articles/c3qjnwye0ep5o"}
    ]
  },
  "offlineServices": [
    {"who": "BBC", "what": "Took sites offline as a precaution.", "source": "https://www.bbc.com/news/articles/c3qjnwye0ep5o"},
    {"who": "Wikimedia (Wikipedia)", "what": "Took a number of systems offline as a precaution.", "source": "https://www.bbc.com/news/articles/c3qjnwye0ep5o"},
    {"who": "Finnish government", "what": "Sites and pages taken offline.", "source": "https://www.bbc.com/news/articles/c3qjnwye0ep5o"},
    {"who": "Edinburgh council", "what": "Site taken offline.", "source": "https://www.bbc.com/news/articles/c3qjnwye0ep5o"},
    {"who": "Netherlands NCSC", "what": "Pulled its website.", "source": "https://www.bbc.com/news/articles/c3qjnwye0ep5o"},
    {"who": "Scottish councils and health boards", "what": "Public sites taken offline.", "source": "https://www.bbc.com/news/articles/c3qjnwye0ep5o"},
    {"who": "University of Geneva", "what": "Website taken offline after a call from CERT-EU.", "source": "https://www.bbc.com/news/articles/c3qjnwye0ep5o"},
    {"who": "Moodle", "what": "Took its public-facing sites offline as a precaution.", "source": "https://www.facebook.com/moodle/posts/a-precautionary-measure-in-response-to-the-php2shell-vulnerability-which-was-/1571864764968591/"}
  ],
  "advisories": [
    {"who": "PHP", "level": "Advisory", "url": "https://www.php.net/archive/2026.php#2026-10-21-5"},
    {"who": "PHP Foundation", "level": "Post-mortem", "url": "https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/"},
    {"who": "UK NCSC", "level": "Alert", "url": "https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php"},
    {"who": "US CISA", "level": "Alert", "url": "https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching"},
    {"who": "Wiz Research", "level": "Technical report", "url": "https://www.wiz.io/blog/php2shell-php-rce"},
    {"who": "Calif Research", "level": "Technical report", "url": "https://calif.io/php2shell/"},
    {"who": "OpenAI", "level": "Response framework", "url": "https://openai.com/index/coordinated-disclosure-of-critical-vulnerabilities"},
    {"who": "Cloudflare", "level": "WAF guidance", "url": "https://blog.cloudflare.com/php-vulnerabilities-waf-protection/"},
    {"who": "watchTowr", "level": "Threat intel", "url": "https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/"},
    {"who": "BBC News", "level": "Reporting", "url": "https://www.bbc.com/news/articles/c3qjnwye0ep5o"}
  ],
  "timeline": [
    {"when": "2004", "what": "Stefan Esser finds the first PHP memory-limit remote vulnerability; commercial firms build non-public exploits."},
    {"when": "2020", "what": "PHP bug #78876 reports that long multipart variables cause an out-of-memory condition and leaked temp files."},
    {"when": "2024", "what": "An OSTIF-funded Quarkslab audit rediscovers the same out-of-memory problem. Exploitation is theorised but not proven, so it is not fixed."},
    {"when": "2026-08-01", "what": "Calif finds multiple paths to remote code execution and reports the first bug to PHP on 11 August."},
    {"when": "2026-08-19", "what": "Wiz Research independently discovers the first vulnerability and reports it on 24 August."},
    {"when": "2026-08-21", "what": "Calif reports the second bug to PHP; PHP confirms the proof of concept on 15 August."},
    {"when": "2026-09-21", "what": "PHP acknowledges the reports and starts building a coordinated fix."},
    {"when": "2026-10-20", "what": "The CVE identifiers leak publicly with a wrong release time and a wrong score of 10.0. PHP pulls its pre-announcement forward to 19:30 UTC."},
    {"when": "2026-10-21", "what": "Patched releases ship for 8.2, 8.3, 8.4 and 8.5. The public advisory follows, and exploit attempts surge."},
    {"when": "2026-10-22", "what": "Patch waves continue across hosting providers and government. Security agencies keep urging operators to patch or go offline."}
  ]
}
```

- [ ] **Step 4: Create `main.js`**

```javascript
/* PHP2Shell brief — renders volatile values from data/status.json.
   No dependencies, no build step. If the JSON cannot be loaded the page
   still renders; status-dependent blocks show an explicit unavailable
   state instead of silently disappearing. */
(function () {
  "use strict";

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    if (text !== undefined && text !== null) { node.textContent = String(text); }
    return node;
  }

  function clear(node) {
    while (node.firstChild) { node.removeChild(node.firstChild); }
  }

  function renderTimestamp(data) {
    var stamp = document.querySelector("[data-status-timestamp]");
    if (!stamp) { return; }
    if (!data || !data.lastUpdated) {
      stamp.textContent = "status unavailable";
      stamp.classList.add("is-unavailable");
      return;
    }
    var parsed = new Date(data.lastUpdated);
    var text = Number.isNaN(parsed.getTime())
      ? data.lastUpdated
      : parsed.toISOString().slice(0, 10) + " " +
        parsed.toISOString().slice(11, 16) + " UTC";
    stamp.textContent = "as of " + text;
  }

  function renderSeverity(data) {
    var target = document.querySelector("[data-status-severity]");
    if (!target) { return; }
    if (!data) {
      target.textContent = "status unavailable";
      return;
    }
    clear(target);
    target.appendChild(el("span", "chip chip--alert", data.severity));
    target.appendChild(el("span", "chip", data.cvssVector + " " + data.cvss));
    target.appendChild(el("span", "chip", "PHP " + data.affectedFrom + " and later"));
  }

  function renderVersions(data) {
    var body = document.querySelector("[data-status-versions]");
    if (!body) { return; }
    clear(body);
    if (!data || !data.fixedVersions || !data.fixedVersions.length) {
      body.appendChild(el("p", "note", "Version table unavailable."));
      return;
    }
    var table = el("table", "table");
    var head = el("thead");
    var headRow = el("tr");
    ["Branch", "Fixed version", "Branch end of life"].forEach(function (label) {
      headRow.appendChild(el("th", null, label));
    });
    head.appendChild(headRow);
    table.appendChild(head);
    var bodyEl = el("tbody");
    data.fixedVersions.forEach(function (row) {
      var tr = el("tr");
      tr.appendChild(el("td", "mono", "PHP " + row.branch));
      tr.appendChild(el("td", "mono is-fixed", row.version));
      tr.appendChild(el("td", null, row.eol));
      bodyEl.appendChild(tr);
    });
    table.appendChild(bodyEl);
    body.appendChild(table);
  }

  function renderExploitation(data) {
    var body = document.querySelector("[data-status-exploitation]");
    if (!body) { return; }
    clear(body);
    if (!data || !data.exploitation) {
      body.appendChild(el("p", "note", "Exploitation status unavailable."));
      return;
    }
    body.appendChild(el("p", "lead", data.exploitation.summary));
    var list = el("ul", "timeline");
    data.exploitation.events.forEach(function (event) {
      var item = el("li");
      item.appendChild(el("span", "timeline__when mono", event.when));
      var text = el("span", "timeline__what", event.what);
      if (event.source) {
        var link = el("a", "link", "source");
        link.href = event.source;
        link.rel = "noopener noreferrer";
        text.appendChild(document.createTextNode(" "));
        text.appendChild(link);
      }
      item.appendChild(text);
      list.appendChild(item);
    });
    body.appendChild(list);
  }

  function renderList(selector, items, renderItem) {
    var body = document.querySelector(selector);
    if (!body) { return; }
    clear(body);
    if (!items || !items.length) {
      body.appendChild(el("p", "note", "Nothing to report."));
      return;
    }
    var list = el("ul", "cards");
    items.forEach(function (item) {
      var card = el("li", "card");
      renderItem(card, item);
      list.appendChild(card);
    });
    body.appendChild(list);
  }

  function renderOffline(data) {
    renderList("[data-status-offline]", data && data.offlineServices, function (card, item) {
      card.appendChild(el("h3", "card__title", item.who));
      card.appendChild(el("p", "card__body", item.what));
      var link = el("a", "link", "source");
      link.href = item.source;
      link.rel = "noopener noreferrer";
      card.appendChild(link);
    });
  }

  function renderAdvisories(data) {
    renderList("[data-status-advisories]", data && data.advisories, function (card, item) {
      card.appendChild(el("h3", "card__title", item.who));
      card.appendChild(el("p", "card__body", item.level));
      var link = el("a", "link", "open");
      link.href = item.url;
      link.rel = "noopener noreferrer";
      card.appendChild(link);
    });
  }

  function renderTimeline(data) {
    var body = document.querySelector("[data-status-timeline]");
    if (!body) { return; }
    clear(body);
    if (!data || !data.timeline) {
      body.appendChild(el("p", "note", "Timeline unavailable."));
      return;
    }
    var list = el("ol", "timeline timeline--full");
    data.timeline.forEach(function (event) {
      var item = el("li");
      item.appendChild(el("span", "timeline__when mono", event.when));
      item.appendChild(el("span", "timeline__what", event.what));
      list.appendChild(item);
    });
    body.appendChild(list);
  }

  window.renderStatus = function (data) {
    renderTimestamp(data);
    renderSeverity(data);
    renderVersions(data);
    renderExploitation(data);
    renderOffline(data);
    renderAdvisories(data);
    renderTimeline(data);
    document.body.classList.add("is-loaded");
  };

  function start() {
    fetch("data/status.json", { cache: "no-cache" })
      .then(function (response) {
        if (!response.ok) { throw new Error("HTTP " + response.status); }
        return response.json();
      })
      .then(window.renderStatus)
      .catch(function () { window.renderStatus(null); });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
```

- [ ] **Step 5: Run the check again**

Run: `python3 tools/check.py`
Expected: FAIL only for `index.html` and `styles.css` missing, and for the `index.html` content assertions that run only when the file exists. No `data/status.json` failures — the JSON parses, all required keys are present, every fixed version is in the approved set, and `cvss` is `"9.2"`.

- [ ] **Step 6: Commit**

```bash
git add data/status.json main.js tools/check.py
git commit -m "feat: add status data model and renderer"
```

---

### Task 3: Page skeleton and design system

**Files:**
- Create: `index.html`
- Create: `styles.css`
- Modify: `tools/check.py`

**Interfaces:**
- Consumes: `data/status.json` and `main.js` from Task 2.
- Produces: `index.html` with the eleven section ids required by `REQUIRED_SECTIONS` (`status`, `root-cause`, `impact`, `versions`, `do-now`, `mitigations`, `hunting`, `timeline`, `ai-inflection`, `disclosure`, `sources`), the hero, the sticky nav, and the `data-status-*` hooks consumed by `main.js`. `styles.css` defines the CSS custom properties from Global Constraints and the layout classes used by `main.js`: `.chip`, `.chip--alert`, `.table`, `.mono`, `.is-fixed`, `.note`, `.lead`, `.timeline`, `.timeline__when`, `.timeline__what`, `.cards`, `.card`, `.card__title`, `.card__body`, `.link`, `.is-unavailable`.

- [ ] **Step 1: Write the failing assertion**

Add to `tools/check.py`, inside `check_markup()`:

```python
    for hook in ("data-status-timestamp", "data-status-severity", "data-status-versions",
                 "data-status-exploitation", "data-status-offline", "data-status-advisories",
                 "data-status-timeline"):
        if hook not in collector.text and hook not in INDEX.read_text():
            fail(f"index.html missing render hook: {hook}")
```

- [ ] **Step 2: Run the check to verify it fails**

Run: `python3 tools/check.py`
Expected: FAIL — `index.html missing section id: status` (and the other nine section ids), `index.html missing render hook: data-status-timestamp` (and the other six hooks).

- [ ] **Step 3: Create `index.html` skeleton**

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PHP2Shell — CVE-2026-109618 and CVE-2026-109619: what happened and what to do</title>
<meta name="description" content="A sourced brief on the critical PHP core remote-code-execution vulnerabilities CVE-2026-109618 and CVE-2026-109619: root cause, affected versions, exploitation status, interim mitigations and hunting signals.">
<meta name="color-scheme" content="dark">
<link rel="stylesheet" href="styles.css">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%230b0d10'/%3E%3Cpath d='M8 22V10h7a6 6 0 0 1 0 12h-3' stroke='%23ff4d3d' stroke-width='2.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>

<header class="masthead">
  <div class="masthead__inner">
    <p class="masthead__label">Security brief</p>
    <h1 class="masthead__title">PHP2Shell</h1>
    <p class="masthead__lede">
      Two critical, unauthenticated remote-code-execution flaws in the PHP engine itself.
      PHP runs about 70% of the web, including WordPress, Wikipedia and Drupal.
      Patches shipped 21 October 2026. This is what happened and what to do.
    </p>
    <p class="masthead__meta">
      <span class="chip chip--alert" data-status-severity>status unavailable</span>
      <span class="stamp" data-status-timestamp>loading</span>
    </p>
    <p class="masthead__cta">
      <a class="button" href="https://www.php.net/archive/2026.php#2026-10-21-5" rel="noopener noreferrer">Read the PHP advisory</a>
      <a class="button button--ghost" href="#do-now">Jump to what to do now</a>
    </p>
    <p class="masthead__fixed">
      Fixed in <span class="mono">8.5.12</span>, <span class="mono">8.4.27</span>,
      <span class="mono">8.3.36</span>, <span class="mono">8.2.35</span>
    </p>
  </div>
</header>

<nav class="nav" aria-label="Sections">
  <div class="nav__inner">
    <ol class="nav__list">
      <li><a href="#status">Status</a></li>
      <li><a href="#root-cause">Root cause</a></li>
      <li><a href="#impact">Impact</a></li>
      <li><a href="#versions">Versions</a></li>
      <li><a href="#do-now">Do this now</a></li>
      <li><a href="#mitigations">Mitigations</a></li>
      <li><a href="#hunting">Hunting</a></li>
      <li><a href="#timeline">Timeline</a></li>
      <li><a href="#ai-inflection">AI</a></li>
      <li><a href="#disclosure">Disclosure</a></li>
      <li><a href="#sources">Sources</a></li>
    </ol>
  </div>
</nav>

<main id="main">
  <section id="status" class="section">
    <h2 class="section__title">Status right now</h2>
    <div data-status-exploitation></div>
    <h3>Services taken offline</h3>
    <div data-status-offline></div>
    <h3>Official advisories</h3>
    <div data-status-advisories></div>
  </section>

  <section id="root-cause" class="section">
    <h2 class="section__title">Root cause</h2>
  </section>

  <section id="impact" class="section">
    <h2 class="section__title">Impact</h2>
  </section>

  <section id="versions" class="section">
    <h2 class="section__title">Which versions are affected</h2>
    <div data-status-versions></div>
  </section>

  <section id="do-now" class="section">
    <h2 class="section__title">Do this now</h2>
  </section>

  <section id="mitigations" class="section">
    <h2 class="section__title">Interim mitigations</h2>
  </section>

  <section id="hunting" class="section">
    <h2 class="section__title">What to hunt for</h2>
  </section>

  <section id="timeline" class="section">
    <h2 class="section__title">Timeline</h2>
    <div data-status-timeline></div>
  </section>

  <section id="ai-inflection" class="section">
    <h2 class="section__title">The AI inflection point</h2>
  </section>

  <section id="disclosure" class="section">
    <h2 class="section__title">How the disclosure went</h2>
  </section>

  <section id="sources" class="section">
    <h2 class="section__title">Sources</h2>
  </section>
</main>

<footer class="footer">
  <p>This page is a secondary summary assembled from public sources. It is not authoritative:
     the PHP security advisory and the national CERT advisories are. Verify before acting.</p>
  <p>Content licensed MIT. Built as a static GitHub Pages site.</p>
</footer>

<script src="main.js"></script>
</body>
</html>
```

- [ ] **Step 4: Create `styles.css`**

```css
/* PHP2Shell brief — design system.
   Dark editorial palette; every accent colour carries meaning. */

:root {
  --ink: #0b0d10;
  --ink-2: #12161b;
  --ink-3: #191f26;
  --text: #e8eaed;
  --muted: #9aa4b0;
  --faint: #6b7682;
  --alert: #ff4d3d;
  --warn: #ffb020;
  --ok: #35c46b;
  --line: #232a32;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  --measure: 72ch;
  --step: 1.5rem;
}

* { box-sizing: border-box; }

html { scroll-behavior: smooth; }

@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  * { animation: none !important; transition: none !important; }
}

body {
  margin: 0;
  background: var(--ink);
  color: var(--text);
  font-family: var(--sans);
  font-size: 17px;
  line-height: 1.65;
  -webkit-font-smoothing: antialiased;
}

.skip {
  position: absolute;
  left: -9999px;
  top: 0;
  background: var(--alert);
  color: #fff;
  padding: 0.6rem 1rem;
  z-index: 20;
}
.skip:focus { left: 0; }

.masthead {
  border-bottom: 1px solid var(--line);
  background:
    radial-gradient(120% 140% at 85% -20%, rgba(255, 77, 61, 0.14), transparent 60%),
    var(--ink);
}
.masthead__inner {
  max-width: 68rem;
  margin: 0 auto;
  padding: 4.5rem var(--step) 3rem;
}
.masthead__label,
.section__kicker,
.card__label {
  font-family: var(--mono);
  font-size: 0.72rem;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--faint);
  margin: 0 0 0.9rem;
}
.masthead__title {
  font-size: clamp(3rem, 9vw, 6.5rem);
  line-height: 0.92;
  letter-spacing: -0.035em;
  margin: 0 0 1.25rem;
  font-weight: 700;
}
.masthead__lede {
  max-width: 46rem;
  font-size: 1.15rem;
  color: var(--muted);
  margin: 0 0 1.75rem;
}
.masthead__meta {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  align-items: center;
  margin: 0 0 1.75rem;
}
.masthead__cta { display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 0 0 1.25rem; }
.masthead__fixed { margin: 0; color: var(--muted); font-size: 0.95rem; }

.chip {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  font-family: var(--mono);
  font-size: 0.78rem;
  padding: 0.32rem 0.7rem;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--ink-2);
  color: var(--muted);
}
.chip--alert {
  border-color: rgba(255, 77, 61, 0.5);
  background: rgba(255, 77, 61, 0.12);
  color: #ffb3aa;
}
.chip--ok { border-color: rgba(53, 196, 107, 0.45); color: #8fe3b1; }
.chip--warn { border-color: rgba(255, 176, 32, 0.45); color: #ffd88a; }

.stamp { font-family: var(--mono); font-size: 0.78rem; color: var(--faint); }
.stamp.is-unavailable { color: var(--warn); }

.button {
  display: inline-block;
  padding: 0.7rem 1.2rem;
  border-radius: 4px;
  background: var(--alert);
  color: #fff;
  text-decoration: none;
  font-weight: 600;
  font-size: 0.95rem;
  border: 1px solid var(--alert);
}
.button:hover { background: #ff6152; }
.button--ghost { background: transparent; color: var(--text); border-color: var(--line); }
.button--ghost:hover { border-color: var(--muted); background: var(--ink-2); }

.nav {
  position: sticky;
  top: 0;
  z-index: 10;
  background: rgba(11, 13, 16, 0.92);
  backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--line);
}
.nav__inner { max-width: 68rem; margin: 0 auto; padding: 0.6rem var(--step); }
.nav__list {
  list-style: none;
  display: flex;
  gap: 1.15rem;
  margin: 0;
  padding: 0;
  overflow-x: auto;
  scrollbar-width: thin;
}
.nav__list a {
  color: var(--muted);
  text-decoration: none;
  font-family: var(--mono);
  font-size: 0.76rem;
  letter-spacing: 0.04em;
  white-space: nowrap;
  padding-bottom: 0.25rem;
  border-bottom: 1px solid transparent;
}
.nav__list a:hover, .nav__list a[aria-current="true"] {
  color: var(--text);
  border-bottom-color: var(--alert);
}

.section {
  max-width: 68rem;
  margin: 0 auto;
  padding: 3.5rem var(--step);
  border-bottom: 1px solid var(--line);
}
.section:last-of-type { border-bottom: 0; }
.section__title {
  font-size: clamp(1.6rem, 3.4vw, 2.3rem);
  letter-spacing: -0.02em;
  margin: 0 0 1.5rem;
  line-height: 1.15;
}
.section h3 {
  font-size: 1.05rem;
  letter-spacing: 0.01em;
  margin: 2.5rem 0 1rem;
  color: var(--text);
}
.section p { max-width: var(--measure); color: var(--muted); }
.section p.lead { color: var(--text); font-size: 1.05rem; }
.section a { color: var(--text); }
.section ul, .section ol { max-width: var(--measure); color: var(--muted); }
.section li { margin: 0.45rem 0; }

.mono { font-family: var(--mono); }
.link { color: var(--alert); text-decoration: none; border-bottom: 1px solid rgba(255, 77, 61, 0.35); }
.link:hover { border-bottom-color: var(--alert); }
.note {
  border-left: 2px solid var(--warn);
  padding: 0.75rem 1rem;
  background: rgba(255, 176, 32, 0.07);
  color: var(--text);
  border-radius: 0 4px 4px 0;
}
.is-fixed { color: var(--ok); }

.table-wrap { overflow-x: auto; }
.table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.95rem;
}
.table th, .table td {
  text-align: left;
  padding: 0.65rem 0.9rem;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
}
.table th {
  font-family: var(--mono);
  font-size: 0.72rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--faint);
  font-weight: 500;
}

.cards {
  list-style: none;
  padding: 0;
  margin: 0;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(15rem, 1fr));
  gap: 0.85rem;
}
.card {
  background: var(--ink-2);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 1rem 1.1rem;
  margin: 0;
}
.card__title { font-size: 0.95rem; margin: 0 0 0.35rem; }
.card__body { margin: 0 0 0.5rem; font-size: 0.9rem; color: var(--muted); }

.timeline { list-style: none; padding: 0; margin: 0; }
.timeline li {
  display: grid;
  grid-template-columns: 9.5rem 1fr;
  gap: 1rem;
  padding: 0.7rem 0;
  border-bottom: 1px solid var(--line);
  margin: 0;
}
.timeline__when { color: var(--faint); font-size: 0.82rem; }
.timeline__what { color: var(--muted); }
.timeline--full li { grid-template-columns: 9.5rem 1fr; }

.footer {
  max-width: 68rem;
  margin: 0 auto;
  padding: 3rem var(--step) 4rem;
  color: var(--faint);
  font-size: 0.85rem;
}
.footer p { max-width: var(--measure); }

.steps { counter-reset: step; list-style: none; padding: 0; margin: 0; max-width: var(--measure); }
.steps li {
  counter-increment: step;
  position: relative;
  padding: 0.85rem 0 0.85rem 2.6rem;
  border-bottom: 1px solid var(--line);
}
.steps li::before {
  content: counter(step, decimal-leading-zero);
  position: absolute;
  left: 0;
  top: 0.85rem;
  font-family: var(--mono);
  font-size: 0.78rem;
  color: var(--alert);
}
.steps strong { color: var(--text); }

.code {
  font-family: var(--mono);
  font-size: 0.85rem;
  background: var(--ink-2);
  border: 1px solid var(--line);
  border-radius: 5px;
  padding: 0.85rem 1rem;
  color: var(--text);
  overflow-x: auto;
  white-space: pre;
  display: block;
}

.figure { margin: 2rem 0; }
.figure figcaption { color: var(--faint); font-size: 0.85rem; margin-top: 0.75rem; }
.figure svg { width: 100%; height: auto; }

@media (max-width: 700px) {
  body { font-size: 16px; }
  .masthead__inner { padding-top: 3rem; }
  .section { padding: 2.5rem var(--step); }
  .timeline li, .timeline--full li { grid-template-columns: 1fr; gap: 0.15rem; }
}
```

- [ ] **Step 5: Run the check again**

Run: `python3 tools/check.py`
Expected: FAIL only on content assertions — `index.html must name both CVE identifiers`, `fixed version ... appears nowhere`, and any missing section body. No structural failures: all eleven section ids resolve and every `#anchor` in the nav has a target.

- [ ] **Step 6: Commit**

```bash
git add index.html styles.css tools/check.py
git commit -m "feat: add page skeleton and design system"
```

---

### Task 4: Author the operator-facing sections

**Files:**
- Modify: `index.html` (sections `#root-cause`, `#impact`, `#versions`, `#do-now`, `#mitigations`, `#hunting`)

**Interfaces:**
- Consumes: `styles.css` classes `.section`, `.note`, `.lead`, `.steps`, `.code`, `.table-wrap`, `.table`, `.chips`.
- Produces: markup for six sections. The versions table lives inside `[data-status-versions]` and is rendered by `main.js`, so the HTML for `#versions` must contain only the explanatory prose and the container element — no duplicate table.

- [ ] **Step 1: Write the failing assertion**

Add to `tools/check.py`, inside `check_markup()`:

```python
    required_phrases = [
        "memory_limit", "post_max_size", "session.upload_progress.enabled",
        "fatal_error_backtraces", "PHPSESSID", "mod_php", "PHP-FPM",
        "restart every worker", "RLIMIT_AS",
    ]
    for phrase in required_phrases:
        if phrase not in body:
            fail(f"index.html missing required phrase: {phrase}")
```

- [ ] **Step 2: Run the check to verify it fails**

Run: `python3 tools/check.py`
Expected: FAIL — `index.html missing required phrase: memory_limit` (and the other eight phrases).

- [ ] **Step 3: Fill in `#root-cause`, `#impact`, `#versions`, `#do-now`, `#mitigations`, `#hunting`**

Replace each placeholder section body with the following content. Keep every factual sentence traceable to the sources in Task 8's source list.

`#root-cause` — plain-English first, then the mechanics:

```html
<section id="root-cause" class="section">
  <h2 class="section__title">Root cause</h2>
  <p class="lead">Both flaws are the same shape: PHP frees a request's memory while
    internal bookkeeping still points into it, and the next request on that worker
    reads the freed memory as if it were live.</p>
  <p>PHP allocates memory for each request and releases it when the request ends.
    If the request dies unexpectedly — a fatal error, or an allocation that hits
    <span class="mono">memory_limit</span> — the cleanup path can run with half-built
    or already-freed data. The worker process survives. Its globals still reference
    memory that no longer exists. The next request handled by that worker can consume
    the stale state, which an attacker can steer into controlled memory corruption or
    into a leak of live process memory.</p>
  <p>The two CVEs are two different points where this can happen:</p>
  <ul>
    <li><strong>CVE-2026-109618 — RCE via OOM corruption.</strong> An out-of-memory
      failure interrupts PHP while request data is only partly initialised. Request
      cleanup then treats the invalid data as valid.</li>
    <li><strong>CVE-2026-109619 — RCE via stale global state.</strong> A fatal error
      leaves request-owned internal state pointing at memory that was freed when the
      request ended. A later request on the same worker uses that stale state before
      normal initialisation resets it.</li>
  </ul>
  <p>Which SAPI you run decides how easy the second step is. On Apache with
    <span class="mono">mod_php</span>, a fatal error during request startup still
    runs request cleanup and the worker is reused, so the stale state is reachable on
    the next request. On PHP-FPM, a failure during startup terminates the worker
    instead, so the path that matters is a fatal error after startup succeeded —
    reached through the Session upload-progress feature, which is enabled by default.</p>
  <figure class="figure">
    <svg viewBox="0 0 880 260" role="img" aria-labelledby="rc-title rc-desc" xmlns="http://www.w3.org/2000/svg">
      <title id="rc-title">How the stale state is reached</title>
      <desc id="rc-desc">Request A hits a fatal error, the request heap is freed while globals still point into it, the worker survives, and request B on the same worker consumes the freed memory.</desc>
      <defs>
        <marker id="rc-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0 0 L10 5 L0 10 z" fill="#6b7682"/>
        </marker>
      </defs>
      <g font-family="ui-monospace, Menlo, monospace" font-size="13">
        <rect x="16" y="90" width="180" height="80" rx="6" fill="#12161b" stroke="#232a32"/>
        <text x="32" y="120" fill="#e8eaed">Request A</text>
        <text x="32" y="142" fill="#9aa4b0">fatal error</text>
        <text x="32" y="160" fill="#9aa4b0">(OOM or fatal)</text>

        <rect x="250" y="90" width="180" height="80" rx="6" fill="#12161b" stroke="#232a32"/>
        <text x="266" y="120" fill="#e8eaed">Request heap</text>
        <text x="266" y="142" fill="#ff4d3d">freed</text>
        <text x="266" y="160" fill="#9aa4b0">globals still point in</text>

        <rect x="484" y="90" width="180" height="80" rx="6" fill="#12161b" stroke="#232a32"/>
        <text x="500" y="120" fill="#e8eaed">Worker survives</text>
        <text x="500" y="142" fill="#9aa4b0">stale globals kept</text>
        <text x="500" y="160" fill="#9aa4b0">next request reuses it</text>

        <rect x="718" y="90" width="146" height="80" rx="6" fill="#1a0f0d" stroke="#ff4d3d"/>
        <text x="734" y="120" fill="#ffb3aa">Request B</text>
        <text x="734" y="142" fill="#ffb3aa">reads freed memory</text>
        <text x="734" y="160" fill="#9aa4b0">RCE or leak</text>

        <line x1="196" y1="130" x2="242" y2="130" stroke="#6b7682" stroke-width="1.5" marker-end="url(#rc-arrow)"/>
        <line x1="430" y1="130" x2="476" y2="130" stroke="#6b7682" stroke-width="1.5" marker-end="url(#rc-arrow)"/>
        <line x1="664" y1="130" x2="710" y2="130" stroke="#6b7682" stroke-width="1.5" marker-end="url(#rc-arrow)"/>
      </g>
    </svg>
    <figcaption>The shared shape of both vulnerabilities. The specific interruption
      points differ, and the reachability differs between SAPI modes.</figcaption>
  </figure>
</section>
```

`#impact`:

```html
<section id="impact" class="section">
  <h2 class="section__title">Impact</h2>
  <p class="lead">Unauthenticated remote code execution, and a separate path to reading
    live process memory. The bug is in the PHP engine, not in your application code.</p>
  <p>Exploitation does not need an account, a session, or a flaw in the CMS on top. A
    "Hello World" page on an affected PHP version is enough. The researchers
    demonstrated pre-authentication remote code execution against WordPress, Drupal,
    Joomla, MediaWiki, Roundcube, Magento, phpMyAdmin, Nextcloud, Laravel, Symfony and
    WHMCS, and against plain PHP scripts.</p>
  <p>Separately, they showed that an attacker can read live worker memory without
    achieving code execution at all. PHP parses multipart requests before normal
    initialisation finishes, so an attacker can make freed heap contents get
    URL-encoded into an oversized or malformed <span class="mono">PHPSESSID</span>
    response cookie. That memory can hold passwords, session tokens, API keys and
    certificates belonging to other users' requests or to the server itself.</p>
  <p>Risk is highest on Apache with <span class="mono">mod_php</span>, where an
    unauthenticated request can trigger the attack before any application code runs.
    Every SAPI that serves web requests is in scope: PHP-FPM,
    <span class="mono">mod_php</span>, <span class="mono">php-cgi</span>,
    FrankenPHP and LiteSpeed.</p>
</section>
```

`#versions`:

```html
<section id="versions" class="section">
  <h2 class="section__title">Which versions are affected</h2>
  <p class="lead">Every PHP version from 5.4 onwards is affected by at least one of the
    two flaws. Patches exist for the four supported branches.</p>
  <div data-status-versions></div>
  <p>PHP 8.1 and older no longer receive updates from the PHP project. Some
    distributions and LTS vendors provide backported fixes — check yours. The PHP
    security team also published minimal source backports for the 7.4, 8.0 and 8.1
    branches for people building from source or without an LTS vendor.</p>
  <p>Linux distributions and LTS vendors received the patches before the public
    release, so the update is usually a normal package upgrade. The volunteer
    <span class="mono">rpms.remirepo.net</span> repository was not updated: move to
    distribution packages or build from source. PHP 8.2 reaches end of life on
    31 December 2026 and takes no further security fixes after that, so plan the
    upgrade to a supported branch.</p>
</section>
```

`#do-now`:

```html
<section id="do-now" class="section">
  <h2 class="section__title">Do this now</h2>
  <p class="lead">Updating is the only complete fix. Everything else buys time or adds
    defence in depth.</p>

  <h3>If you own a website and do not run the server</h3>
  <ol class="steps">
    <li><strong>Ask whoever hosts it whether the PHP security update is applied.</strong>
      The fix must land on PHP itself. Updating WordPress, a theme or a plugin does
      not fix it.</li>
    <li><strong>If the answer is no, or the answer takes more than a day, ask for the
      site to be taken offline</strong> until it can be patched. Several public bodies
      did exactly this.</li>
    <li><strong>Watch for security messages</strong> from services you use, and treat
      any "change your password" request that arrives with the publicity around this
      incident with suspicion. Phishing campaigns ride on headlines like this one.</li>
  </ol>

  <h3>If you run servers</h3>
  <ol class="steps">
    <li><strong>Inventory every PHP installation</strong>, internet-facing first. PHP is
      often bundled inside appliances, appliances and appliances' vendor images, and
      prevalence is not directly observable from the application layer. Do not limit
      discovery to outdated versions: all versions may be affected.</li>
    <li><strong>Update to the fixed release for your branch</strong> — 8.5.12, 8.4.27,
      8.3.36 or 8.2.35.</li>
    <li><strong>Restart every PHP worker</strong> after the update, so the fix is
      actually live in every process.</li>
    <li><strong>Preserve logs and configuration snapshots before you change anything,</strong>
      then look for evidence of compromise: web shells, new cron entries, new
      accounts, PHP workers launching shells or downloading tools.</li>
    <li><strong>Restrict internet access to PHP systems</strong> that could not be
      patched in time.</li>
    <li><strong>Keep WAF rules as defence in depth.</strong> Cloudflare shipped managed
      rules for both CVEs to all customers including the free tier, several hours
      before disclosure. A WAF reduces exposure; it does not replace the patch.</li>
  </ol>

  <h3>If you are a hosting or platform provider</h3>
  <ol class="steps">
    <li><strong>Ship the patched packages</strong> to every customer image and let
      them upgrade, and tell them clearly which versions are fixed.</li>
    <li><strong>Offer a documented mitigation path</strong> for customers who cannot
      upgrade immediately, and be explicit about what it does and does not stop.</li>
    <li><strong>Publish an inventory of affected products</strong> so downstream
      operators can find what they are running.</li>
  </ol>
</section>
```

`#mitigations`:

```html
<section id="mitigations" class="section">
  <h2 class="section__title">Interim mitigations</h2>
  <p class="note">These reduce exposure to specific attack paths. They do not make an
    installation safe, and PHP says updating is the only complete solution.</p>

  <h3>For CVE-2026-109618, RCE via OOM corruption</h3>
  <ul>
    <li>Set <span class="mono">memory_limit=-1</span>, in a way applications cannot
      override, such as <span class="mono">php_admin_value</span> in the FPM pool or
      the Apache configuration. Check that no pool, directory or application setting
      puts a finite limit back. This removes the controllable memory-limit failure,
      but an underlying allocation failure can still reach the vulnerable path.</li>
    <li>Set a low <span class="mono">post_max_size</span> — 8M for applications that
      do not need uploads, 32M when uploads are required. Keep
      <span class="mono">upload_max_filesize</span> below it. Enforce limits for
      decoded request size, field count, multipart part count, header count and
      nesting depth at the web server or proxy, including for requests without a
      usable <span class="mono">Content-Length</span>.</li>
    <li>Use a container or cgroup limit as an availability boundary, with a policy
      that kills only the affected worker. Do not substitute
      <span class="mono">RLIMIT_AS</span> or <span class="mono">RLIMIT_DATA</span>:
      they can trigger the vulnerable allocation failure.</li>
  </ul>

  <h3>For CVE-2026-109619, RCE via stale global state</h3>
  <ul>
    <li>Set <span class="mono">session.upload_progress.enabled=0</span> and restart
      every worker. Apply it in <span class="mono">php.ini</span>, the FPM pool or
      server configuration, so it applies before request parsing. Do not rely on
      <span class="mono">ini_set()</span> or a per-directory
      <span class="mono">.user.ini</span>. This blocks the confirmed session paths,
      not other variants.</li>
    <li>On PHP 8.5, set <span class="mono">fatal_error_backtraces=0</span> and restart
      every worker. This blocks the confirmed fatal backtrace path only.</li>
    <li>Remove invalid or deprecated per-request settings that emit diagnostics before
      initialisation. Hiding diagnostics with
      <span class="mono">error_reporting</span>,
      <span class="mono">display_errors</span> or <span class="mono">@</span> does not
      help.</li>
    <li>Fix attacker-reachable fatal errors and execution timeouts, including failures
      in callbacks, upload or import processing and cleanup.</li>
  </ul>

  <h3>Worked example</h3>
  <code class="code">; php.ini — FPM pool or server level, not .user.ini
session.upload_progress.enabled = 0
post_max_size = 8M
upload_max_filesize = 2M
memory_limit = -1

; PHP 8.5 only
fatal_error_backtraces = 0

; then: restart every worker</code>
</section>
```

`#hunting`:

```html
<section id="hunting" class="section">
  <h2 class="section__title">What to hunt for</h2>
  <p class="lead">These bugs execute below the application layer, so application logs
    may show very little context. Look one level lower.</p>
  <ul>
    <li>Unusual multipart requests followed by memory-limit errors or repeated
      HTTP 500 responses.</li>
    <li>Unexpectedly large or malformed <span class="mono">PHPSESSID</span> response
      cookies — a normal session id is short, and this one is a leak of heap
      contents.</li>
    <li>Unexplained PHP worker churn: workers restarting or dying under load without
      a matching traffic explanation.</li>
    <li>PHP worker processes launching shells or downloading tools.</li>
    <li>New web shells, unexpected cron jobs, and newly created accounts tied to PHP
      processes.</li>
  </ul>
  <p>National agencies also ask operators to look for backdoors an attacker may have
    installed, and to treat vendor advisories about appliances and services that bundle
    PHP as part of the same patch wave.</p>
</section>
```

- [ ] **Step 4: Run the check again**

Run: `python3 tools/check.py`
Expected: FAIL only on `index.html must name both CVE identifiers` and the `fixed version ... appears nowhere` lines, both of which are fixed in Task 5. No phrase failures remain.

- [ ] **Step 5: Commit**

```bash
git add index.html tools/check.py
git commit -m "feat: write operator-facing sections"
```

---

### Task 5: Author the context sections

**Files:**
- Modify: `index.html` (sections `#ai-inflection`, `#disclosure`, `#sources`)

**Interfaces:**
- Consumes: `styles.css` classes `.section`, `.timeline`, `.steps`, `.cards`, `.link`.
- Produces: the three remaining sections. `#sources` holds a static grouped list of links in addition to the JS-rendered advisory cards in `#status`.

- [ ] **Step 1: Write the failing assertion**

Add to `tools/check.py`, inside `check_markup()`:

```python
    for cve_id in ("CVE-2026-109618", "CVE-2026-109619"):
        if cve_id not in body:
            fail(f"index.html must name {cve_id}")
    if "9.2" not in body:
        fail("index.html must state the CVSS score 9.2")
```

- [ ] **Step 2: Run the check to verify it fails**

Run: `python3 tools/check.py`
Expected: FAIL — `index.html must name CVE-2026-109618` (both ids) and `index.html must state the CVSS score 9.2`.

- [ ] **Step 3: Fill in the three sections**

`#ai-inflection`:

```html
<section id="ai-inflection" class="section">
  <h2 class="section__title">The AI inflection point</h2>
  <p class="lead">The bugs had been in the codebase for over a decade. What changed was
    that frontier models could chain them into a working exploit.</p>
  <p>The underlying faults were old: a memory-limit remote vulnerability class first
    described in 2004, an out-of-memory bug reported in 2020, and the same problem
    rediscovered in a 2024 audit where exploitation was theorised but not proven, so
    it was not fixed. Turning those faults into an exploit meant chaining several
    bugs and adapting to how each target's memory is laid out — work that had sat
    at the edge of what a human team could practically achieve.</p>
  <p>Frontier models removed that barrier. Calif found the first paths while auditing
    PHP through OpenAI's Patch the Planet programme, using GPT-5.6 Sol. Wiz Research
    found them independently with Wiz Atlas, Gemini 4 Argon and GPT-5.6 Sol, and
    credited Gemini 4 Argon with a decisive contribution to finding the flaw, building
    the exploit, detecting attacks and validating the patch. OpenAI had also reported
    the same root cause on its own.</p>
  <p>Wiz's framing is the one worth holding: one researcher with the right tooling
    completed in a week what would previously have taken a world-class team months.
    Complexity, they argue, is no longer a meaningful barrier — which changes the
    practical economics of what counts as exploitable.</p>
  <p>The same capabilities cut both ways. WatchTowr reported active exploitation
    attempts against both CVEs, Cloudflare saw attempt volume climb into the millions
    within hours of disclosure, and OpenAI notes that the same tools help attackers
    build offensive tooling rapidly. OpenAI is funding $1 billion in subsidised access
    to its Daybreak models for organisations with limited security resources, and
    published a PHP version checker as a Codex skill.</p>
</section>
```

`#disclosure`:

```html
<section id="disclosure" class="section">
  <h2 class="section__title">How the disclosure went</h2>
  <p class="lead">It did not go as planned. Reading this part tells you why the
    timeline looks compressed and why vendor mitigations shipped before the patch.</p>
  <p>The coordinated plan was a pre-announcement on 20 October, then a release on
    21 October at 14:00 UTC. Instead, the CVE identifiers and a wrong release time
    began circulating around 15:00 UTC that day, together with a CVSS score of 10.0
    — the real score is 9.2. No technical details leaked in the first wave. The PHP
    project pulled its pre-announcement forward to 19:30 UTC and moved the release up
    a day to 21 October, a compromise between acting quickly and giving distributors
    time to package the fix.</p>
  <p>Two things then made it worse. Calif, one of the firms that had reported the
    issues, mistakenly published a video showing its proof of concept against several
    targets; copies circulated and accelerated proof-of-concept development. And on
    21 October at 07:41 UTC, more than six hours before the coordinated release,
    Chainguard published container images that already contained the fix — which let
    anyone study the patch in binary form while every other PHP user was still
    waiting. The PHP security team said it did not find a functional exploit among
    the proof-of-concept material it inspected before release.</p>
  <p>The PHP Foundation's own account of the fix is unusually blunt, and worth
    reading in full. A PHP core developer found early signs of the out-of-memory
    problem while fixing an audit finding in 2024. The security team developed several
    candidate fixes, each carrying compatibility breaks, new denial-of-service risk,
    or changes that would require coordinating across the extension ecosystem. With
    no known path to remote code execution and a very small team of people who know
    the engine deeply, the decision stalled and restarted repeatedly over months.
    The Foundation calls the delay a structural failure caused by its own decision
    process and a lack of resources.</p>
  <p>It has since built out: an Ecosystem Security Team in May 2026, an AI Security
    Engineer in Residence, dedicated triage and hardening hires through the summer,
    scans with Anthropic's Claude Mythos through Alpha-Omega, and OpenAI's Daybreak
    Red for validating reports. The security team published 15 CVEs since 1 July and
    worked through more than 100 reports that turned out to be invalid, duplicate or
    not reproducible. The Foundation is now asking organisations that depend on PHP
    to fund the security work that makes the next one of these finish sooner.</p>
</section>
```

`#sources`:

```html
<section id="sources" class="section">
  <h2 class="section__title">Sources</h2>
  <p>Every claim on this page traces to one of these. Where a source is dated, the
    facts may have moved on since.</p>

  <h3>Primary vendor and maintainer sources</h3>
  <ul>
    <li><a href="https://www.php.net/archive/2026.php#2026-10-21-5" rel="noopener noreferrer">PHP security advisory: critical remote code execution vulnerabilities</a> — fixed versions, affected SAPIs, interim mitigations.</li>
    <li><a href="https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/" rel="noopener noreferrer">PHP Foundation: today's PHP security release</a> — the fix history, the disclosure leak, the security organisation rebuild.</li>
    <li><a href="https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w" rel="noopener noreferrer">php-src advisory GHSA-w8hw-w9fx-j79w (CVE-2026-109618)</a> and <a href="https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp" rel="noopener noreferrer">GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)</a> — technical detail.</li>
    <li><a href="https://openai.com/index/coordinated-disclosure-of-critical-vulnerabilities" rel="noopener noreferrer">OpenAI: global response coordination</a> — the response framework, Daybreak funding, the Defender's Window framing, and the PHP version checker.</li>
  </ul>

  <h3>Independent research</h3>
  <ul>
    <li><a href="https://www.wiz.io/blog/php2shell-php-rce" rel="noopener noreferrer">Wiz Research: PHP2Shell</a> — the four exploited bugs, the AI inflection point, the disclosure timeline.</li>
    <li><a href="https://calif.io/php2shell/" rel="noopener noreferrer">Calif Research: a tale of two PHP remote vulnerabilities</a> — the full technical write-up and the 2004-to-2026 history.</li>
    <li><a href="https://blog.cloudflare.com/php-vulnerabilities-waf-protection/" rel="noopener noreferrer">Cloudflare: WAF protections for php2shell</a> — deployment timings and managed rule sets.</li>
    <li><a href="https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/" rel="noopener noreferrer">watchTowr: PHP remote code execution intelligence</a> — exploitation observations and the incident timeline.</li>
  </ul>

  <h3>Government and agency advisories</h3>
  <ul>
    <li><a href="https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php" rel="noopener noreferrer">UK NCSC: critical security issue affecting PHP</a> — priority actions, including the compromise check and taking systems offline.</li>
    <li><a href="https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching" rel="noopener noreferrer">US CISA: critical vulnerabilities in PHP require immediate patching</a> — inventory, prioritisation and hunting guidance.</li>
    <li><a href="https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4630238/nsa-advisory-php-updates/" rel="noopener noreferrer">NSA: advisory on PHP updates</a> — take systems offline if they cannot be patched immediately.</li>
  </ul>

  <h3>Reporting</h3>
  <ul>
    <li><a href="https://www.bbc.com/news/articles/c3qjnwye0ep5o" rel="noopener noreferrer">BBC News: what is PHP and why did it spark a global cyber-security scramble?</a> — the global response, sites taken offline and the exploitation volume.</li>
    <li><a href="https://en.wikipedia.org/wiki/PHP2Shell" rel="noopener noreferrer">Wikipedia: PHP2Shell</a> — a live overview that tracks the situation further than this page does.</li>
  </ul>
</section>
```

- [ ] **Step 4: Run the check again**

Run: `python3 tools/check.py`
Expected: FAIL only on the `fixed version ... appears nowhere` lines — `8.5.12`, `8.4.27`, `8.3.36` and `8.2.35` must appear in the rendered page, and the check compares against `status.json` too, so they should now pass. Confirm the exact remaining failures before moving on.

- [ ] **Step 5: Commit**

```bash
git add index.html tools/check.py
git commit -m "feat: write AI, disclosure and sources sections"
```

---

### Task 6: Navigation highlighting and copy buttons

**Files:**
- Modify: `main.js`
- Modify: `index.html` (add `data-copy` attributes to the mitigation command block)

**Interfaces:**
- Consumes: `index.html` section ids and the `.nav__list a` elements.
- Produces: `main.js` highlights the nav entry for the section currently in view via `aria-current="true"`, and attaches click-to-copy to any `[data-copy]` element.

- [ ] **Step 1: Write the failing assertion**

Add to `tools/check.py`, inside `check_markup()`:

```python
    if "data-copy" not in INDEX.read_text():
        fail("index.html has no data-copy element, copy-to-clipboard is unused")
```

- [ ] **Step 2: Run the check to verify it fails**

Run: `python3 tools/check.py`
Expected: FAIL — `index.html has no data-copy element, copy-to-clipboard is unused`.

- [ ] **Step 3: Implement nav highlighting and copy buttons in `main.js`**

Append inside the IIFE, before `window.renderStatus = ...`:

```javascript
  function initNavHighlight() {
    var links = Array.prototype.slice.call(
      document.querySelectorAll(".nav__list a[href^='#']")
    );
    if (!links.length || !("IntersectionObserver" in window)) { return; }
    var byId = {};
    links.forEach(function (link) {
      byId[link.getAttribute("href").slice(1)] = link;
    });
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        var link = byId[entry.target.id];
        if (!link) { return; }
        if (entry.isIntersecting) {
          links.forEach(function (other) { other.removeAttribute("aria-current"); });
          link.setAttribute("aria-current", "true");
        }
      });
    }, { rootMargin: "-45% 0px -50% 0px", threshold: 0 });
    Object.keys(byId).forEach(function (id) {
      var section = document.getElementById(id);
      if (section) { observer.observe(section); }
    });
  }

  function initCopyButtons() {
    var targets = document.querySelectorAll("[data-copy]");
    Array.prototype.forEach.call(targets, function (target) {
      target.classList.add("is-copyable");
      target.setAttribute("tabindex", "0");
      target.setAttribute("role", "button");
      target.addEventListener("click", function () {
        var text = target.getAttribute("data-copy") || target.textContent.trim();
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            target.classList.add("is-copied");
            setTimeout(function () { target.classList.remove("is-copied"); }, 1400);
          });
        }
      });
    });
  }
```

And call both from `start()`:

```javascript
  function start() {
    initNavHighlight();
    initCopyButtons();
    fetch("data/status.json", { cache: "no-cache" })
```

Add the matching rule to `styles.css`:

```css
.is-copyable { cursor: pointer; position: relative; }
.is-copyable::after {
  content: "click to copy";
  position: absolute;
  top: 0.6rem;
  right: 0.8rem;
  font-family: var(--mono);
  font-size: 0.68rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--faint);
}
.is-copied::after { content: "copied"; color: var(--ok); }
```

- [ ] **Step 4: Add `data-copy` to the command block in `index.html`**

Change the mitigation example to:

```html
<code class="code" data-copy="session.upload_progress.enabled = 0
post_max_size = 8M
upload_max_filesize = 2M
memory_limit = -1
fatal_error_backtraces = 0">; php.ini — FPM pool or server level, not .user.ini
session.upload_progress.enabled = 0
post_max_size = 8M
upload_max_filesize = 2M
memory_limit = -1

; PHP 8.5 only
fatal_error_backtraces = 0

; then: restart every worker</code>
```

- [ ] **Step 5: Run the check again**

Run: `python3 tools/check.py`
Expected: FAIL only on `fixed version ... appears nowhere` if the check still cannot see the versions; otherwise `OK: all checks passed`.

- [ ] **Step 6: Commit**

```bash
git add main.js index.html styles.css tools/check.py
git commit -m "feat: add nav highlighting and copy-to-clipboard"
```

---

### Task 7: Responsive and accessibility pass

**Files:**
- Modify: `styles.css`
- Modify: `index.html`

**Interfaces:**
- Consumes: the markup from Tasks 3 to 6.
- Produces: a layout that holds at 390px and 1440px, focus styles on every interactive element, and headings that are not hidden behind the sticky nav.

- [ ] **Step 1: Write the failing assertion**

Add to `tools/check.py`, inside `check_markup()`:

```python
    html = INDEX.read_text()
    if 'name="viewport"' not in html:
        fail("index.html is missing the viewport meta tag")
    if ":focus-visible" not in (ROOT / "styles.css").read_text():
        fail("styles.css has no :focus-visible styles")
    if "scroll-margin-top" not in (ROOT / "styles.css").read_text():
        fail("styles.css has no scroll-margin-top, headings can hide under the sticky nav")
```

- [ ] **Step 2: Run the check to verify it fails**

Run: `python3 tools/check.py`
Expected: FAIL — `styles.css has no :focus-visible styles` and `styles.css has no scroll-margin-top, headings can hide under the sticky nav`.

- [ ] **Step 3: Apply the fixes in `styles.css`**

Add:

```css
.section h2, .section h3 { scroll-margin-top: 5rem; }

:where(a, button, [tabindex]):focus-visible {
  outline: 2px solid var(--alert);
  outline-offset: 3px;
  border-radius: 2px;
}

@media (max-width: 700px) {
  .nav__inner { padding: 0.5rem var(--step); }
  .nav__list { gap: 0.9rem; }
  .masthead__cta .button { width: 100%; text-align: center; }
  .cards { grid-template-columns: 1fr; }
  .figure svg { min-width: 640px; }
  .figure { overflow-x: auto; }
}
```

- [ ] **Step 4: Run the check again**

Run: `python3 tools/check.py`
Expected: `OK: all checks passed`.

- [ ] **Step 5: Commit**

```bash
git add styles.css index.html tools/check.py
git commit -m "fix: responsive layout and focus styles"
```

---

### Task 8: Repository documentation

**Files:**
- Create: `README.md`
- Create: `SOURCES.md`

**Interfaces:**
- Consumes: the finished site and the source list used in Task 5.
- Produces: instructions for updating the page and a full source ledger.

- [ ] **Step 1: Write the failing assertion**

Add to `tools/check.py`, inside `check_files()`:

```python
    for name in ("README.md", "SOURCES.md"):
        if not (ROOT / name).exists():
            fail(f"missing required file: {name}")
```

- [ ] **Step 2: Run the check to verify it fails**

Run: `python3 tools/check.py`
Expected: FAIL — `missing required file: README.md` and `missing required file: SOURCES.md`.

- [ ] **Step 3: Write `README.md`**

````markdown
# PHP2Shell brief

A static, dependency-free brief on the critical PHP core remote-code-execution
vulnerabilities **CVE-2026-109618** and **CVE-2026-109619**, published through GitHub
Pages.

Live site: <https://rajasekharponakala.github.io/php2shell-brief/>

## What this is

Not an authoritative source. It is a readable summary of public primary sources, with
a link back to every claim. The PHP security advisory and the national CERT advisories
are the authority — see [SOURCES.md](SOURCES.md).

## Update the status

Volatile values live in [`data/status.json`](data/status.json):

| Key | What it drives |
| --- | --- |
| `lastUpdated` | The "as of" timestamp in the hero and footer |
| `severity`, `cvss`, `affectedFrom` | The severity chips in the hero |
| `fixedVersions` | The fixed-version table in "Which versions are affected" |
| `cves` | The two CVE summaries |
| `exploitation` | The exploitation timeline in "Status right now" |
| `offlineServices` | The "Services taken offline" cards |
| `advisories` | The "Official advisories" cards |
| `timeline` | The full timeline section |

Edit the JSON, then open `index.html` in a browser to see the change. Prose that
changes meaning — the root-cause explanation, the mitigations — lives in
`index.html` and should be edited there, with the matching source added to
`SOURCES.md`.

## Verify before pushing

```bash
python3 tools/check.py          # structure, data shape, anchors
python3 tools/check.py --online # also HEAD-checks every external link
```

The script exits non-zero on any failure, so it works as a pre-push gate.

## Local preview

```bash
python3 -m http.server 8000
# open http://localhost:8000
```

## Deploy

Pushing to `main` runs `.github/workflows/pages.yml`, which uploads the repository
root as a Pages artifact and deploys it. There is no build step: the site is the
repository contents.

## Licence

MIT. See [LICENSE](LICENSE).

Content is a summary of third-party public sources; those sources remain the
copyright holders of their own text.
````

- [ ] **Step 4: Write `SOURCES.md`**

````markdown
# Sources

Every factual claim on the page traces to one of these. Access dates are
2026-10-22; pages may change afterwards.

## Vendor and maintainer

| Source | What it supports |
| --- | --- |
| [PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5) | Fixed versions 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; affected SAPIs; interim mitigations; "updating is the only safe choice"; source backports for 7.4 / 8.0 / 8.1; `rpms.remirepo.net` not updated; PHP 8.2 end of life 2026-12-31 |
| [PHP Foundation release post](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/) | Fix history since the 2024 audit; the 2026-10-20 leak and the wrong CVSS 10.0; the Chainguard embargo break at 07:41 UTC; the Foundation's account of the stalled fix; the new security organisation; 15 CVEs since 1 July and 100+ invalid reports |
| [php-src advisory GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | CVE-2026-109618 technical detail |
| [php-src advisory GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | CVE-2026-109619 technical detail |
| [OpenAI: global response coordination](https://openai.com/index/coordinated-disclosure-of-critical-vulnerabilities) | Patch the Planet; Daybreak funding; the five-stage response framework; the Defender's Window framing; the PHP version checker released as a Codex skill |
| [NCSC-NL product inventory](https://github.com/NCSC-NL/php2shell) | Downstream software with a vulnerable PHP dependency |

## Independent research

| Source | What it supports |
| --- | --- |
| [Wiz Research: PHP2Shell](https://www.wiz.io/blog/php2shell-php-rce) | The four exploited bugs under two CVEs; PHP 5.4 onwards affected; the AI inflection point and the models used; the disclosure timeline; hunting signals |
| [Calif Research](https://calif.io/php2shell/) | The full technical write-up; the 2004 / 2020 / 2024 history; the tested application versions; the mod_php versus PHP-FPM difference; the memory-disclosure primitive |
| [Cloudflare](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/) | WAF deployment about nine hours before disclosure; protection by default from 2026-10-21 03:02 UTC on all plans including free; the request-and-response detection approach |
| [watchTowr](https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/) | Active exploitation attempts against both CVEs; the leak timeline; "if you have not applied the patch, your deployment is vulnerable" |

## Government and agencies

| Source | What it supports |
| --- | --- |
| [UK NCSC alert](https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php) | Priority actions; checking for backdoors installed by an attacker; taking systems offline when patching is not possible |
| [US CISA alert](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching) | Immediate patching; taking PHP-based systems offline; WAF as interim protection; hunting for PHP workers launching shells or downloading tools; "not observed exploitation as of publication" |
| [NSA advisory](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4630238/nsa-advisory-php-updates/) | Take PHP systems offline if they cannot be patched immediately; the flaw as a direct path to the database; heightened awareness in the coming weeks |

## Reporting

| Source | What it supports |
| --- | --- |
| [BBC News](https://www.bbc.com/news/articles/c3qjnwye0ep5o) | The global response; named sites taken offline; the Cloudflare attempt-volume escalation; Amazon's pre-disclosure attempts; the phrase "millions and millions" of affected sites |
| [Wikipedia: PHP2Shell](https://en.wikipedia.org/wiki/PHP2Shell) | A live overview that tracks developments beyond this page |

## Corrections

If a source is wrong or a figure moves, update `data/status.json` and the matching
sentence in `index.html`, then re-run `python3 tools/check.py --online`.
````

- [ ] **Step 5: Run the check again**

Run: `python3 tools/check.py`
Expected: `OK: all checks passed`.

- [ ] **Step 6: Commit**

```bash
git add README.md SOURCES.md tools/check.py
git commit -m "docs: add readme and source ledger"
```

---

### Task 9: Browser verification

**Files:**
- Modify: `index.html`, `styles.css` only if a defect is found (fix, re-run Task 9 checks, commit the fix)

**Interfaces:**
- Consumes: the complete site from Task 8.
- Produces: verified rendering at two viewport widths with a clean console.

- [ ] **Step 1: Serve the site locally**

Run: `cd /home/rajasekhar/opencode-brain/php2shell-brief && python3 -m http.server 8000`
Expected: `Serving HTTP on 0.0.0.0 port 8000`. Keep it running in the background for the rest of this task.

- [ ] **Step 2: Check the JSON is served**

Run: `curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/data/status.json`
Expected: `200`.

- [ ] **Step 3: Load the page in a browser at 1440px and capture a screenshot**

Use the playwright browser tool: navigate to `http://localhost:8000/`, resize to 1440x900, wait for the hero to render, and capture a full-page screenshot. Check: severity chips populated from `status.json`, the "as of" timestamp shows a date rather than "status unavailable", the fixed-version table rendered, and the nav is sticky.

- [ ] **Step 4: Load the page at 390px and capture a screenshot**

Navigate again with a 390x844 viewport. Check: no horizontal overflow of the page body, the nav scrolls horizontally inside its own container, the version table scrolls inside its container, the timeline stacks to one column, and the diagram scrolls rather than squeezing.

- [ ] **Step 5: Check the console**

Read browser console messages for the page. Expected: no errors. A failed `fetch("data/status.json")` would show as an error and the hero would read "status unavailable".

- [ ] **Step 6: Verify graceful degradation when the status file is missing**

Run: `mv data/status.json /tmp/opencode/status.json.bak`, reload `http://localhost:8000/` in the browser, and confirm the page still renders every section and shows "status unavailable" in the hero and in the status-dependent blocks instead of empty space. Then run `mv /tmp/opencode/status.json.bak data/status.json` and reload to confirm the normal state returns.

- [ ] **Step 6: Fix any defect found, then re-run Steps 3 to 5**

Fix in the smallest possible change, re-run `python3 tools/check.py`, and commit:

```bash
git add index.html styles.css
git commit -m "fix: <short description of the defect>"
```

- [ ] **Step 7: Stop the local server**

Run: `pkill -f "http.server 8000"`.

---

### Task 10: Publish to GitHub Pages and verify

**Files:**
- Modify: none (publishing only)

**Interfaces:**
- Consumes: the verified repository from Task 9.
- Produces: the public repository and a live Pages URL.

- [ ] **Step 1: Create the remote repository and push**

Run:
```bash
cd /home/rajasekhar/opencode-brain/php2shell-brief
gh repo create rajasekharponakala/php2shell-brief --public --source=. --remote=origin --push --description "Status brief on the PHP2Shell RCE vulnerabilities (CVE-2026-109618 / CVE-2026-109619)"
```
Expected: repository created and branch pushed.

- [ ] **Step 2: Confirm the push landed**

Run: `git status -sb && git log --oneline -3`
Expected: branch tracking `origin/main` with a clean working tree.

- [ ] **Step 3: Watch the Pages workflow**

Run:
```bash
gh run list --repo rajasekharponakala/php2shell-brief --limit 5
```
Expected: a `Deploy Pages` run. Wait for it to reach `completed` with conclusion `success`. If it fails, read the log with `gh run view <run-id> --log-failed` and fix.

- [ ] **Step 4: Verify the live URL**

Run:
```bash
curl -s -o /dev/null -w '%{http_code}\n' https://rajasekharponakala.github.io/php2shell-brief/
curl -s -o /dev/null -w '%{http_code}\n' https://rajasekharponakala.github.io/php2shell-brief/data/status.json
```
Expected: `200` for both.

- [ ] **Step 5: Verify the live page renders**

Open `https://rajasekharponakala.github.io/php2shell-brief/` in the browser, capture a screenshot, and confirm the same content as the local build, including the `data/status.json`-driven sections.

- [ ] **Step 6: Run the full check against the live content**

Run: `python3 tools/check.py --online`
Expected: `OK: all checks passed`, with no dead external links.

- [ ] **Step 7: Tag the release**

```bash
git tag -a v1.0 -m "First published brief on CVE-2026-109618 and CVE-2026-109619"
git push origin v1.0
```
