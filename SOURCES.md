# Sources

Every factual claim on the page traces to one of these. Access dates are 2026-10-22;
pages may change afterwards.

## Vendor and maintainer

| Source | What it supports |
| --- | --- |
| [PHP security advisory](https://www.php.net/archive/2026.php#2026-10-21-5) | Fixed versions 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; affected SAPIs and highest risk on mod_php; interim mitigations; "updating is the only safe choice"; source backports for 7.4 / 8.0 / 8.1; `rpms.remirepo.net` not updated; PHP 8.2 end of life 2026-12-31 |
| [PHP Foundation release post](https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/) | Fix history since the 2024 audit; the 2026-10-20 leak with the wrong CVSS 10.0; the release moved forward a day; the mistaken proof-of-concept video; the Chainguard embargo break at 07:41 UTC; the Foundation's account of the stalled fix; the new security organisation; 15 CVEs since 1 July and 100+ invalid reports |
| [php-src advisory GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | CVE-2026-109618 technical detail |
| [php-src advisory GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | CVE-2026-109619 technical detail |
| [OpenAI: global response coordination](https://openai.com/index/coordinated-disclosure-of-critical-vulnerabilities) | Patch the Planet; $1 billion in subsidised Daybreak access for frontline defenders; the five-stage response framework; the Defender's Window framing; the PHP version checker released as a Codex skill |
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
| [NSA advisory](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4630238/nsa-advisory-critical-patches-recommended-for-php-vulnerabilities/) | Take PHP systems offline if they cannot be patched immediately; the flaw as a direct path to the database; heightened awareness in the coming weeks |

## Reporting

| Source | What it supports |
| --- | --- |
| [BBC News](https://www.bbc.com/news/articles/c3qjnwye0ep5o) | The global response; named sites taken offline; the Cloudflare attempt-volume escalation; Amazon's pre-disclosure attempts; the scale of affected sites |
| [The Hacker News](https://thehackernews.com/2026/10/someone-tried-to-exploit-php2shell-4.html) | Amazon's exploitation attempt on 17 October 2026, four days before public disclosure |
| [Wikipedia: PHP2Shell](https://en.wikipedia.org/wiki/PHP2Shell) | A live overview that tracks developments beyond this page |

## Corrections

If a source is wrong or a figure moves, update `data/status.json` and the matching
sentence in `index.html`, then re-run `python3 tools/check.py --online`.
