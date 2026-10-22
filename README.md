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
| `lastUpdated` | The "as of" timestamp in the hero |
| `severity`, `cvss`, `cvssVector`, `affectedFrom` | The severity chips in the hero |
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

`lastUpdated` is a UTC ISO-8601 timestamp. The page renders it as
`as of YYYY-MM-DD HH:MM UTC`.

## Verify before pushing

```bash
python3 tools/check.py          # structure, data shape, anchors
python3 tools/check.py --online # also HEAD-checks every external link
```

The script exits non-zero on any failure, so it works as a pre-push gate. It checks,
among other things, that every fixed version listed in `status.json` is one of the
four PHP actually shipped, that every in-page anchor resolves to a real section, and
that the page loads no external assets.

## Local preview

```bash
python3 -m http.server 8000
# open http://localhost:8000
```

Serving over HTTP matters: the page loads `data/status.json` with `fetch`, which
browsers block on `file://` URLs.

## Deploy

Pushing to `main` runs `.github/workflows/pages.yml`, which uploads the repository
root as a Pages artifact and deploys it. There is no build step: the site is the
repository contents.

## Licence

MIT. See [LICENSE](LICENSE).

Content is a summary of third-party public sources; those sources remain the
copyright holders of their own text.
