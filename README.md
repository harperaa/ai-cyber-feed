# vuln-feed

Static-site generator: one command builds a responsive `index.html`, `data.json` and RSS `feed.xml`
listing recent high/critical vulnerabilities and exploit activity. Python 3.9+ standard library only, no paid APIs.

    python3 build.py        # output in ./public  (index.html, data.json, feed.xml)

Serve/preview: `python3 -m http.server -d public 8000`. Nothing is published by this tool.

## What it collects (default window: last 7 days)
**Authoritative records** (main "Vulnerabilities" tab, one merged row per CVE):
- **NVD API 2.0** – CVSS ≥ 7.0 CVEs published/modified in the last 7 days (CVSS v3.x HIGH+CRITICAL query; rejected CVEs dropped).
- **CISA KEV** – entries added in the last 7 days; *any* CVE in the full KEV catalog gets the "EXPLOITED" badge (+ ransomware flag).
- **GitHub global security advisories** – reviewed, high/critical, updated in the last 7 days (unauthenticated OK).
- **FIRST EPSS** – exploit-probability score per CVE (enrichment only).

**Chatter & exploit news** (second tab, clearly labelled *unverified*; CVE ids extracted and cross-linked to main records):
Reddit (r/netsec, r/cybersecurity, r/blueteamsec, r/AskNetsec via public RSS, keyword-filtered), Exploit-DB RSS,
vendor feeds (Microsoft MSRC, Cisco PSIRT, Fortinet PSIRT, Palo Alto, Chrome Releases), news (BleepingComputer,
The Hacker News, SecurityWeek, Krebs, Project Zero), and **X items** from an optional `x_items.json`
(array of `{url, author, text, created_at, cves[]}`) next to `build.py`; if absent it is simply skipped.

Vendor/package tagging (`vendors.py`: Microsoft, Google/Chrome/Android, Apple, Cisco, Fortinet, Palo Alto, Ivanti,
VMware/Broadcom, Oracle, Adobe, Citrix, SAP, Linux kernel, OpenSSL, Apache, nginx, OpenSSH, Log4j, Atlassian, GitLab,
WordPress, Docker/Kubernetes, popular npm/PyPI/etc. packages, …) is heuristic: CPE vendor/product + keywords. Edit `RULES` to extend.
The page filters by severity, source, vendor, "exploited in the wild", "major vendors only", with search and sorting.

## Failure handling
- HTTP retries with exponential backoff on 403/429/5xx/timeouts (honours `Retry-After`); NVD is throttled (6.5 s between requests, 0.8 s with a key).
- Every source's last good data is kept in `cache/state.json`. If a source fails, its previous items are reused and
  marked `stale` (or `partial`) in the "Data sources & status" panel and `data.json -> sources`.
- Exit code is non-zero only if no vulnerability records at all could be produced.

## Options
    python3 build.py --days 7 --kev-days 7 --out public
    python3 build.py --skip nvd,ghsa          # skip sources (also: kev, chatter, or a feed name e.g. "r/netsec")
    python3 build.py --cache-only             # re-render from cache, no network
Env vars (optional): `NVD_API_KEY` (free, faster NVD), `GITHUB_TOKEN` (higher GitHub limit), `SITE_URL` (absolute links in RSS).

## Refresh several times a day
    0 */4 * * *  cd /path/to/vuln-feed && python3 build.py && rsync -a public/ user@host:/var/www/vuln/

## Notes / limits
- NVD can be slow (a full run took ~10 min on a bad day because of large responses); CVEs with only a CVSS v4 score are not returned by the v3 severity query.
- Reddit RSS rate-limits (HTTP 429) aggressively; failed subreddits fall back to cached items.
- MSRC items are kept only if the CVE is already in the feed or the text says exploited/zero-day.
- Informational only; verify against vendor advisories.
