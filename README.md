# AI Cyber Feed

Static-site generator: one command builds a responsive `index.html`, `data.json` and RSS `feed.xml`
listing recent high/critical vulnerabilities and exploit activity, with AI-related items flagged and sorted first. Python 3.9+ standard library only, no paid APIs.

    python3 build.py        # output in ./public  (index.html, data.json, feed.xml, summary.json)
    SITE_URL=https://harperaa.github.io/ai-cyber-feed python3 build.py --out docs   # what GitHub Pages serves

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

## Incidents & breaches (non-CVE news) and X search guidance
Not every important event has a CVE (e.g. the Oct 2026 Railway breach). The single editable vocabulary is `INCIDENT_TERMS` in `ai_rules.py`;
`build.py` derives `KW` (news feeds), `REDDIT_KW` and `AI_SEC_KW` from it, tags matching chatter items `incident: true`
(shown as an "Incident" badge and an "Incidents & breaches" filter on the Chatter tab) and the AI "impact" rule
"breach touching AI provider / inference keys" uses the same verbs. Incident items about major platforms (cloud/dev platforms, SaaS, AI providers)
can also be promoted to Summary focus cards with an empty `cves` list.

**X queries for the hourly routine** (run each, plus the CVE/exploit queries, and write hits to `x_items.json`; use `cves: []` when none):
`hacked`, `breached`, `breach`, `data breach`, `compromised`, `cyberattack` / `"cyber attack"` / `attacked`, `intrusion`, `"unauthorized access"`,
`"data theft"`, `exfiltrated`, `leak` / `leaked` / `"exposed data"`, `stolen`, `"credential theft"`, `"account takeover"`, `"ransomware attack"`,
`extortion`, `defaced`, `"supply chain attack"`, `backdoored`, `"malicious package"`, `infostealer`, `"rotate keys"` / `"rotate secrets"` / `"revoke keys"`,
`"urges users to"`, `"rotate your"`. Combine with major names where useful (e.g. `(hacked OR breached) (Railway OR Vercel OR GitHub OR npm OR PyPI OR OpenAI OR Anthropic OR "Hugging Face" OR AWS OR Azure OR Cloudflare)`)
and AI terms (`"API keys" (stolen OR leaked) (OpenAI OR Anthropic)`).

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

## AI angle (`ai_rules.py`)
Every CVE record and chatter item gets `ai_angle`: `null` or a list (highest priority first) of
`{"type": "cause|product|impact", "why": "<matched rule / snippet>"}`.
- **cause** – vuln found by AI, AI-generated/assisted exploit, AI-written code flaw, AI attack tooling (highest priority)
- **product** – vuln in AI/ML software (LLM runtimes, ML frameworks, MCP servers, AI coding agents, vector DBs, AI vendor products, prompt injection / model supply chain)
- **impact** – AI-related abuse/impact (attackers using AI, deepfake/AI phishing, AI supply chain, exposed AI infrastructure)

Rules are plain regex lists plus package-name and CPE lists in `ai_rules.py`; `MANUAL` pins angles for specific CVE ids
(e.g. PHP2Shell, AI-discovered) and `FEED_DEFAULT` marks AI-security-only feeds. The page has AI badges, an "AI angle" filter and an
"AI first" default sort (cause > product > impact, then exploited, severity, EPSS). `data.json -> counts.ai_vulns / ai_chatter` hold the totals.
Extra AI sources: GHSA advisories for ~70 ML packages (`affects=` query, incl. medium), r/LocalLLaMA and r/MachineLearning (security-keyword filtered),
OWASP GenAI, Embrace The Red, Simon Willison's prompt-injection feed, Trail of Bits and Wiz blogs.

## Summary tab (`summary.json`)
The first tab ("Summary", deep link `#summary`) is rendered from a **hand-written** `summary.json` next to `build.py`
(rewritten about every 4 hours; the feed itself refreshes hourly). `build.py` copies it to `docs/summary.json` and embeds it in the page;
if the file is absent the tab shows a friendly "summary pending" message. Schema:

    {
      "updated_at": "2026-10-23T11:00:00Z",        // ISO UTC; shown as "Summary updated (UTC)"
      "next_update_note": "text",
      "headline": "1-2 sentences",
      "ai_headline": "1-2 sentences on the AI angle",
      "focus": [{                                    // rendered AI-cause first, then AI-product, AI-impact, then the rest
        "title": "", "severity": "critical|high", "exploited": true, "cves": ["CVE-..."], "vendor": "",
        "why": "1-2 sentences", "action": "what to do (e.g. patch version)", "url": "https://...",
        "ai_angle": ["cause|product|impact"],        // [] if none
        "ai_note": "short why-the-AI-angle"
      }],
      "news":  [{"title": "", "source": "", "url": "", "blurb": ""}],
      "watch": ["short strings"],
      "ai_activity": {                               // ALWAYS present: roll-up of ALL AI-related exploit/attack activity, last 7 days, newest first
        "overview": "2-4 sentences",
        "counts": {"ai_cause": 0, "ai_product_exploited": 0, "ai_impact": 0},   // = number of items per group
        "groups": [{"label": "AI as the cause" | "AI products being exploited" | "AI impact / AI keys & infrastructure",
                    "items": [{"title": "", "date": "ISO UTC", "summary": "", "status": "exploited|reported|unverified|patched",
                               "cves": ["CVE-..."], "url": "https://...", "source": ""}]}],
        "trend_note": "1-2 sentences"
      }
    }

CVE ids in a focus card filter the Vulnerabilities tab when the record is in the feed (plus an NVD link), otherwise link to NVD.

### `ai_activity` roll-up (always present, right below the AI angle section)
Rendered as a prominent section with collapsible groups, status badges (EXPLOITED / REPORTED / PATCHED / **UNVERIFIED**, the last also dashed-bordered with a warning line) and links.
It is **not** limited to the focus list: it must list every AI-flagged exploit/attack item from `data.json` (`ai_angle` set and `exploited`, or chatter tagged AI cause / incident) plus
anything already in the previous summary. Verify each item against the data/sources, never invent facts, and label single-source or X/Reddit claims `unverified`.
`python3 make_ai_activity.py` prints a first-draft block from `docs/data.json` (`--merge` writes it into `summary.json`, `--days N`, `--data path`); it groups, merges topics (`TOPICS`, `TOPIC_GROUP` in the script),
guesses status and drops obvious noise. It is only a draft: the 4-hour routine must edit it by judgment before publishing. If `ai_activity` is missing the page shows a "roll-up pending" placeholder.

### Summary archive ("Previous summaries")
Every earlier summary is kept in `summary_archive/<updated_at UTC>.json` (e.g. `2026-10-23T1641Z.json`); nothing is ever trimmed.
**The 4-hour summary routine MUST run `python3 archive_summary.py` BEFORE overwriting `summary.json`** (it copies the current `summary.json` into the archive if its `updated_at` is not archived yet; `--backfill` also recovers older committed versions from git history), then write the new `summary.json`, then build and commit `summary_archive/` together with `summary.json`.
`build.py` reads the archive (newest first, excluding the current summary), writes `docs/summary_archive.json`, and inlines the entries into the page only while they fit in ~150 KB; beyond that the page lazy-loads `summary_archive.json` when the section scrolls into view.
The bottom of the Summary tab shows "Previous summaries" paginated (50 collapsed entries per page, Previous/Next, "Page X of Y"); each entry is headed by its time in New York time and UTC and expands to the headline, AI headline, `ai_activity`, focus, news and watch list in compact form.
