# Design: PHP2Shell status brief — GitHub Pages

Date: 2026-10-22
Status: approved in chat 2026-10-22 (design below matches what was approved; no new decisions introduced)

## Purpose

Publish a factual, continuously-updatable brief on the PHP core remote-code-execution
vulnerabilities tracked as CVE-2026-109618 and CVE-2026-109619 (the "php2shell" issue),
covering what happened, what it means, and what operators must do.

Success criteria:

- A reader who owns a website can determine in under 60 seconds whether they are affected
  and what to do next.
- A reader who is a security engineer can find the root cause, affected versions,
  interim mitigations and hunting signals without leaving the page.
- Every factual claim traces to a cited primary source. No unsourced numbers.
- The page loads fast, works on a phone, and needs no build step to publish an update.

## Scope

In scope: what the vulnerabilities are, how they were found, what happened during
disclosure, current exploitation and outage status, fixed versions, interim mitigations,
detection signals, and next steps by role.

Out of scope: exploit code, weaponisation details beyond publicly disclosed root cause,
a live feed of exploit attempts (no data source exists for that), and any claim to be
authoritative. The page points at php.net as the authority and says so in the footer.

## Deliverable

Repository `github.com/rajasekharponakala/php2shell-brief`, public, default branch
`main`. Live site at `https://rajasekharponakala.github.io/php2shell-brief/`, served by
GitHub Pages through `.github/workflows/pages.yml` (`actions/deploy-pages`, source
`.`).

Files:

| File | Purpose |
| --- | --- |
| `index.html` | Entire page markup, semantic sections, inline SVG diagram |
| `styles.css` | Design system and layout |
| `main.js` | Renders volatile values from `data/status.json`; nav highlight; copy-to-clipboard for commands |
| `data/status.json` | `lastUpdated`, severity, version matrix, stat figures, advisories list |
| `SOURCES.md` | Full source list with what each source supports |
| `README.md` | What the page is, how to update it, how to publish |
| `LICENSE` | MIT |
| `.nojekyll` | Prevent Jekyll processing of `data/` |
| `.github/workflows/pages.yml` | Deploy Pages on push to `main` |

## Technology choices

- No framework, no bundler, no npm. Plain HTML + CSS + vanilla JS. A GitHub Pages site
  that a stranger can read and update without a build pipeline is worth more than
  framework ergonomics.
- No external requests: system font stacks only, no CDN, no analytics, no trackers.
- Content is static in `index.html`. Only genuinely volatile values (timestamp,
  version matrix, exploitation figures) come from `data/status.json`, so refreshing the
  status does not touch the markup.
- Inline SVG for the root-cause diagram instead of an image asset, so it inherits theme
  colours and stays sharp.

## Design system

Dark editorial, high contrast, no cyberpunk decoration.

- Surfaces: `--ink: #0b0d10` page, `--ink-2: #12161b` panels, `--ink-3: #191f26` raised.
- Text: `--text: #e8eaed`, `--muted: #9aa4b0`, `--faint: #6b7682`.
- Accent: `--alert: #ff4d3d` for severity and critical actions, `--warn: #ffb020` for
  partial/conditional states, `--ok: #35c46b` for fixed/resolved states.
- Type: system sans for prose, `ui-monospace` stack for labels, versions, figures and
  commands. Labels are small, uppercase, letter-spaced.
- Structure: max-width 72ch prose column inside a wider grid; sections separated by
  hairline rules, not heavy boxes; sticky section nav on desktop, collapsible on mobile.
- Every accent colour is used for meaning (severity, status), never for decoration.

## Page structure

Twelve sections, ordered so a reader can stop at any depth.

1. **Hero** — "PHP2Shell", one-sentence summary, severity chips (CVSS v4.0 9.2 Critical,
   unauthenticated RCE, PHP 5.4+ affected), the four fixed versions, patch-now CTA to
   the php.net advisory, and a live "as of" timestamp from `data/status.json`.
2. **Status right now** — four stat tiles: exploitation volume; services pulled offline;
   government advisories; the AI angle. Each tile links to the source.
3. **Root cause** — one bug pattern, two CVEs. Plain-English paragraph, then the inline
   SVG diagram: request A fatals → request heap freed → worker survives holding globals
   that point into the freed heap → request B consumes the stale state. The two
   variants: fatal during request startup (mod_php, worker reused) versus fatal after
   startup (PHP-FPM, worker survives).
4. **Impact** — remote code execution plus process-memory disclosure (freed heap
   contents URL-encoded into an oversized `PHPSESSID` cookie). Application-agnostic:
   the bug is in the PHP engine, not in WordPress. Highest demonstrated risk is
   `mod_php`, where the attack completes before any application code runs.
5. **Affected versions** — table of branch, affected range, fixed version. Note that
   8.1 and older get no upstream updates (8.2 reaches end of life 2026-12-31), that
   minimal source backports exist for 7.4 / 8.0 / 8.1, that `rpms.remirepo.net` was not
   updated, and that distributions and LTS vendors patched in advance.
6. **Do this now** — three role checklists (site owner, developer, sysadmin or hosting
   provider), ordered by priority: patch, restart every worker, hunt for compromise,
   restrict access, keep WAF rules as defence in depth.
7. **Interim mitigations** — the php.net measures with the explicit caveat that they
   reduce exposure to specific paths and do not make an installation safe.
   `memory_limit=-1`, `post_max_size` 8M/32M, `session.upload_progress.enabled=0`,
   `fatal_error_backtraces=0` on 8.5, container or cgroup limits, and the warning not
   to substitute `RLIMIT_AS` or `RLIMIT_DATA`.
8. **Hunting signals** — unusual multipart requests followed by memory-limit errors or
   repeated HTTP 500s, unexpectedly large or malformed `PHPSESSID` cookies, unexplained
   PHP worker churn, PHP worker processes launching shells or downloading tools, new
   web shells, new cron entries, new accounts.
9. **Timeline** — 2004 through the October 2026 release, including the leak and the
   embargo break.
10. **The AI inflection** — how the bugs were found (Calif with GPT-5.6 Sol; Wiz with
    Wiz Atlas, Gemini 4 Argon and GPT-5.6 Sol), the "Defender's Window" framing, and
    the same capability lowering the bar for attackers.
11. **The disclosure mess** — the 2026-10-20 leak with a wrong CVSS score, the release
    moved forward, the mistaken proof-of-concept video, Chainguard breaking the
    embargo, and the PHP Foundation's own account of why the fix stalled and what it
    changed as a result.
12. **Sources** — grouped links, every claim traceable.

Footer: last-updated timestamp, licence, and a plain statement that the page is a
secondary summary and php.net and the national CERTs are the authority.

## Accuracy rules

- Severity is CVSS v4.0 9.2. The 10.0 figure that circulated on 2026-10-20 was wrong
  and is described only as an error.
- Exploitation is stated as *attempts observed*: watchTowr reported active exploitation
  attempts against both CVEs, Cloudflare saw request volume escalate into the
  millions, Amazon reported attempt activity on 2026-10-17 before disclosure, and CISA
  had not observed exploitation as of its alert. The page says exactly that and does not
  claim confirmed compromise of any named site.
- Named sites are described as "took offline as a precaution" or "reported attempts",
  matching the sources.
- Interpolated PHP versions in the target list (WordPress 7.1.2 and so on) are stated as
  the versions tested by the researchers, not as "vulnerable versions".
- Any figure without a source is not printed.

## Testing

- Serve locally over `python3 -m http.server` and load in a browser.
- Check the rendered page at 390px and 1440px widths.
- Confirm no console errors and that `data/status.json` loads (fetch path is relative,
  so it works under a project-path Pages URL).
- Confirm every link in the source list resolves (HEAD request per URL).
- After push, confirm the Pages deployment succeeded and the public URL returns 200 and
  renders the same content.

## Out-of-band

The same content can be posted as a summary article or linked from the README. Nothing
in this spec requires a backend, a database, or a scheduled job.
