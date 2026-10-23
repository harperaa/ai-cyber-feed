#!/usr/bin/env python3
"""AI Cyber Feed: static vulnerability / exploit feed generator with AI-angle flagging (see ai_rules.py).

    python3 build.py            # fetch everything, write ./public/{index.html,data.json,feed.xml,summary.json}

Options: --out DIR  --days N  --kev-days N  --skip a,b  --cache-only
Env:     NVD_API_KEY, GITHUB_TOKEN (optional, raise rate limits), SITE_URL (for RSS links)
No paid APIs; standard library only.
"""
import argparse
import shutil
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from xml.sax.saxutils import escape

import ai_rules as AIR
import sources as S
from sources import FetchError, log
from vendors import tag_vendors

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE_PATH = os.path.join(HERE, "cache", "state.json")
X_ITEMS_PATH = os.path.join(HERE, "x_items.json")

# ---- chatter / news sources -------------------------------------------------
# kind: reddit | exploit | vendor | news ; flt: keyword filter regex applied to title+summary
# Incident / breach wording lives in ONE place: ai_rules.INCIDENT_TERMS
INCIDENT_PAT = AIR.INCIDENT_PAT
INCIDENT_RX = re.compile(INCIDENT_PAT, re.I)
_CVE_KW = (r"CVE-\d{4}-\d{4,7}|exploit|0[- ]?day|zero[- ]?day|\bpoc\b|proof[- ]of[- ]concept|\brce\b|"
           r"vulnerab|\bflaw\b|backdoor|actively|in the wild|ransomware|patch")
KW = re.compile(_CVE_KW + "|" + INCIDENT_PAT, re.I)
REDDIT_KW = re.compile(r"CVE-\d{4}-\d{4,7}|exploit|0[- ]?day|zero[- ]?day|\bpoc\b|proof[- ]of[- ]concept|\brce\b|" + INCIDENT_PAT, re.I)
AI_SEC_KW = re.compile(r"CVE-\d{4}-\d{4,7}|vulnerab|exploit|jailbreak|prompt[- ]injection|backdoor|malicious|\brce\b|"
                       r"supply[- ]chain|poison|sandbox escape|\bcve\b|" + INCIDENT_PAT, re.I)
FEEDS = [
    # name, kind, url, keyword filter (None=keep all), max items
    ("r/netsec", "reddit", "https://www.reddit.com/r/netsec/new/.rss?limit=100", REDDIT_KW, 40),
    ("r/cybersecurity", "reddit", "https://www.reddit.com/r/cybersecurity/new/.rss?limit=100", REDDIT_KW, 40),
    ("r/blueteamsec", "reddit", "https://www.reddit.com/r/blueteamsec/new/.rss?limit=100", REDDIT_KW, 40),
    ("r/AskNetsec", "reddit", "https://www.reddit.com/r/AskNetsec/new/.rss?limit=100", REDDIT_KW, 25),
    ("Exploit-DB", "exploit", "https://www.exploit-db.com/rss.xml", None, 40),
    ("Microsoft MSRC", "vendor", "https://api.msrc.microsoft.com/update-guide/rss", "msrc", 60),
    ("Cisco PSIRT", "vendor", "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml", None, 40),
    ("Fortinet PSIRT", "vendor", "https://www.fortiguard.com/rss/ir.xml", None, 40),
    ("Palo Alto Security Advisories", "vendor", "https://security.paloaltonetworks.com/rss.xml", None, 40),
    ("Chrome Releases", "vendor", "https://feeds.feedburner.com/GoogleChromeReleases",
     re.compile(r"CVE-\d{4}|security fix", re.I), 15),
    ("BleepingComputer", "news", "https://www.bleepingcomputer.com/feed/", KW, 30),
    ("The Hacker News", "news", "https://feeds.feedburner.com/TheHackersNews", KW, 30),
    ("SecurityWeek", "news", "https://feeds.feedburner.com/securityweek", KW, 30),
    ("Krebs on Security", "news", "https://krebsonsecurity.com/feed/", None, 15),
    ("Project Zero", "news", "https://projectzero.google/feed.xml", None, 10),
    # --- AI-security sources (kind "ai" = AI security blogs; Reddit ML subs filtered for security keywords)
    ("r/LocalLLaMA", "reddit", "https://www.reddit.com/r/LocalLLaMA/new/.rss?limit=100", AI_SEC_KW, 30),
    ("r/MachineLearning", "reddit", "https://www.reddit.com/r/MachineLearning/new/.rss?limit=100", AI_SEC_KW, 30),
    ("OWASP GenAI", "ai", "https://genai.owasp.org/feed/", None, 15),
    ("Embrace The Red", "ai", "https://embracethered.com/blog/index.xml", None, 15),
    ("Simon Willison (prompt injection)", "ai", "https://simonwillison.net/tags/prompt-injection.atom", None, 15),
    ("Trail of Bits", "news", "https://blog.trailofbits.com/feed/", KW, 15),
    ("Wiz Blog", "news", "https://www.wiz.io/feed/rss.xml", KW, 15),
]

# ---------------------------------------------------------------------------

def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, path)


def recent(dt_str, cutoff):
    d = S.parse_date(dt_str)
    return bool(d and d >= cutoff)


def pretty_cpe(vp):
    v, p = vp.split(":", 1)
    return f"{v.replace('_', ' ').title()} {p.replace('_', ' ')}"


# ---- fetch stage: each source updates cache + status ------------------------

def run_sources(args, cache, now):
    status = {}
    skip = set(filter(None, args.skip.split(",")))
    cutoff = now - timedelta(days=args.days)

    def ok(name, n, **kw):
        status[name] = {"status": "ok", "count": n, "fetched_at": S.iso(now), **kw}

    def fail(name, err, n):
        prev = cache.get("status", {}).get(name, {})
        status[name] = {"status": "stale" if n else "failed", "count": n, "error": str(err)[:300],
                        "fetched_at": prev.get("fetched_at") or prev.get("last_success"),
                        "last_success": prev.get("fetched_at") or prev.get("last_success")}
        log(f"  !! {name}: {err} -> keeping {n} previous item(s)")

    def skipped(name):
        n = len(cache.get(name, {}))
        prev = cache.get("status", {}).get(name, {})
        status[name] = dict(prev) if prev else {"status": "skipped", "count": n}
        status[name]["count"] = n

    # NVD ----------------------------------------------------------------
    if "nvd" in skip or args.cache_only:
        skipped("nvd")
    else:
        log("NVD ...")
        try:
            items, err = S.fetch_nvd(args.days, os.environ.get("NVD_API_KEY"))
        except Exception as e:  # noqa - never let one source kill the build
            items, err = {}, f"unexpected: {e!r}"
            log("  NVD crashed:", err)
        prev = cache.get("nvd", {})
        if err and not items:
            fail("nvd", err, len(prev))
        else:
            if err:
                cache["nvd"] = {**prev, **items}
                status["nvd"] = {"status": "partial", "count": len(cache["nvd"]), "error": err[:300],
                                 "fetched_at": S.iso(now)}
            else:
                cache["nvd"] = items
                ok("nvd", len(items))
    # KEV ----------------------------------------------------------------
    if "kev" in skip or args.cache_only:
        skipped("kev")
    else:
        log("CISA KEV ...")
        try:
            cache["kev"] = S.fetch_kev()
            ok("kev", len(cache["kev"]))
        except Exception as e:  # noqa
            fail("kev", e, len(cache.get("kev", {})))
    # GHSA ---------------------------------------------------------------
    if "ghsa" in skip or args.cache_only:
        skipped("ghsa")
    else:
        log("GitHub advisories ...")
        try:
            items, err = S.fetch_ghsa(args.days, os.environ.get("GITHUB_TOKEN"))
        except Exception as e:  # noqa
            items, err = {}, f"unexpected: {e!r}"
            log("  GHSA crashed:", err)
        prev = cache.get("ghsa", {})
        if err and not items:
            fail("ghsa", err, len(prev))
        elif err:
            m = dict(prev); m.update(items); cache["ghsa"] = m
            status["ghsa"] = {"status": "partial", "count": len(m), "error": err[:300], "fetched_at": S.iso(now)}
        else:
            cache["ghsa"] = items
            ok("ghsa", len(items))
    # GHSA: dedicated pass for AI/ML packages (also medium severity), merged into the same cache ------
    if not ("ghsa" in skip or args.cache_only):
        log("GitHub advisories (AI/ML packages) ...")
        try:
            mitems, merr = S.fetch_ghsa(args.days, os.environ.get("GITHUB_TOKEN"), max_pages=5,
                                        severities=("critical", "high", "medium"), affects=AIR.ML_QUERY_PACKAGES)
        except Exception as e:  # noqa
            mitems, merr = {}, f"unexpected: {e!r}"
        cache.setdefault("ghsa", {}).update(mitems)
        status["ghsa:ml-packages"] = ({"status": "partial" if merr else "ok", "count": len(mitems),
                                       "fetched_at": S.iso(now), **({"error": merr[:300]} if merr else {})})
    # prune old
    cache["ghsa"] = {k: v for k, v in cache.get("ghsa", {}).items() if recent(v.get("modified"), cutoff)}
    cache["nvd"] = {k: v for k, v in cache.get("nvd", {}).items() if recent(v.get("modified"), cutoff)}

    # Enrich KEV-recent CVEs that NVD window query did not return (severity lookup), capped
    extra = cache.setdefault("nvd_extra", {})
    kev_cut = now - timedelta(days=args.kev_days)
    need = [c for c, k in cache.get("kev", {}).items()
            if recent(k["kev_added"], kev_cut) and c not in cache["nvd"] and c not in extra
            and c not in {g["id"] for g in cache.get("ghsa", {}).values()}]
    if need and not args.cache_only and "nvd" not in skip and status["nvd"]["status"] in ("ok", "partial"):
        key = os.environ.get("NVD_API_KEY")
        log(f"NVD enrichment for {len(need)} KEV CVEs (cap 20) ...")
        for c in need[:20]:
            time.sleep(0.8 if key else 6.5)
            try:
                extra[c] = S.fetch_nvd_single(c, key) or {"id": c, "missing": True}
            except FetchError as e:
                log("  enrichment failed:", c, e)
                break

    # Chatter feeds --------------------------------------------------------
    chat = cache.setdefault("chatter", {})
    cwin = now - timedelta(days=args.days)
    for name, kind, url, flt, cap in FEEDS:
        key = "chatter:" + name
        if "chatter" in skip or name in skip or args.cache_only:
            status[key] = {**cache.get("status", {}).get(key, {"status": "skipped", "kind": kind}),
                           "count": len(chat.get(name, []))}
            continue
        log(f"Feed {name} ...")
        try:
            data, _ = S.http_get(url, timeout=60, retries=3, backoff=5, max_bytes=30_000_000)
            entries = S.parse_feed(data)
            if not entries:
                raise FetchError("no entries parsed")
        except (FetchError, Exception) as e:  # noqa - XML parse errors too
            prev = chat.get(name, [])
            status[key] = {"status": "stale" if prev else "failed", "count": len(prev), "kind": kind,
                           "error": str(e)[:300],
                           "fetched_at": cache.get("status", {}).get(key, {}).get("fetched_at")}
            log(f"  !! {name}: {e} -> keeping {len(prev)} previous")
            if name.startswith("r/"):
                time.sleep(2)
            continue
        out = []
        for e in entries:
            d = e["date"] or now
            if d < cwin:
                continue
            title = S.strip_html(e["title"], 220)
            summ = S.strip_html(e["summary"], 400)
            text = title + " " + S.strip_html(e["content"], 6000)
            if flt == "msrc":
                pass  # filtered after cross-link step
            elif flt is not None and not flt.search(title + " " + summ + " " + text[:3000]):
                continue
            link = S.safe_url(e["link"])
            if not link:
                continue
            ext = ""
            if kind == "reddit":  # external article linked from the submission
                m = re.search(r'href="(https?://[^"]+)"[^>]*>\[link\]', re.sub("&quot;", '"', e["content"] or ""))
                m = m or re.search(r'&lt;a href=&quot;(https?://[^&]+)&quot;&gt;\[link\]', e["content"] or "")
                ext = S.safe_url(m.group(1)) if m else ""
                summ = "" if summ.lower().startswith("submitted by") else summ
            cves = S.extract_cves(title, summ, text[:5000])[:12]
            out.append({
                "kind": kind, "source": name, "title": title, "url": link, "ext_url": ext,
                "summary": summ if summ != title else "",
                "author": S.strip_html(e["author"], 60), "date": S.iso(d), "cves": cves,
                "vendors": tag_vendors(title + " " + summ + " " + name),
                "_ai": text[:2000],
            })
        out.sort(key=lambda x: x["date"], reverse=True)
        chat[name] = out[: max(cap * (4 if flt == "msrc" else 1), cap)]
        ok(key, len(chat[name]), kind=kind)
        if name.startswith("r/"):
            time.sleep(2)  # be polite to reddit
    cache["status"] = {**cache.get("status", {}), **status}
    return status


def load_x_items(now):
    """Optional hook: x_items.json = [{url, author, text, created_at, cves[]}]"""
    if not os.path.exists(X_ITEMS_PATH):
        return [], {"status": "absent", "count": 0}
    try:
        raw = json.load(open(X_ITEMS_PATH, encoding="utf-8"))
        assert isinstance(raw, list)
    except Exception as e:  # noqa
        return [], {"status": "failed", "count": 0, "error": f"x_items.json unreadable: {e}"}
    out = []
    for r in raw:
        if not isinstance(r, dict):
            continue
        url = S.safe_url(r.get("url", ""))
        text = S.strip_html(str(r.get("text", "")), 500)
        if not url or not text:
            continue
        d = S.parse_date(str(r.get("created_at", ""))) or now
        cves = S.extract_cves(" ".join(map(str, r.get("cves") or [])), text)[:12]
        out.append({"kind": "x", "source": "X", "title": text[:220], "url": url, "ext_url": "",
                    "summary": text if len(text) > 220 else "", "author": S.strip_html(str(r.get("author", "")), 60),
                    "date": S.iso(d), "cves": cves, "vendors": tag_vendors(text)})
    out.sort(key=lambda x: x["date"], reverse=True)
    return out, {"status": "ok", "count": len(out), "fetched_at": S.iso(now), "kind": "x"}


# ---- merge stage ------------------------------------------------------------

def merge(cache, args, now, status):
    kev_all = cache.get("kev", {})
    kev_cut = now - timedelta(days=args.kev_days)
    recs = {}

    def rec(cid):
        return recs.setdefault(cid, {"id": cid, "sources": [], "links": {}})

    for cid, n in cache.get("nvd", {}).items():
        r = rec(cid)
        r["sources"].append("NVD")
        r.update(description=n["description"], published=n["published"], modified=n["modified"],
                 score=n["score"], severity=n["severity"], cvss_version=n["cvss_version"], vector=n["vector"],
                 cpes=n["cpes"])
        r["links"]["NVD"] = "https://nvd.nist.gov/vuln/detail/" + cid
    for g in cache.get("ghsa", {}).values():
        gid = g["id"]
        r = rec(gid)
        if "GHSA" not in r["sources"]:
            r["sources"].append("GHSA")
        r["links"]["GHSA"] = S.safe_url(g["url"]) or "https://github.com/advisories/" + g["ghsa_id"]
        r["ghsa_id"] = g["ghsa_id"]
        r["packages"] = [f"{e}:{n}" if e else n for e, n in g["packages"]]
        r["_pk"] = g["packages"]
        if "severity" not in r or not r.get("severity"):
            r.update(severity=g["severity"], score=g["score"], vector=g.get("vector"))
        r.setdefault("description", g["description"])
        r.setdefault("published", g["published"])
        r.setdefault("modified", g["modified"])
    for cid, k in kev_all.items():
        if cid in recs or recent(k["kev_added"], kev_cut):
            r = rec(cid)
            if recent(k["kev_added"], kev_cut) and "KEV" not in r["sources"]:
                r["sources"].append("KEV")
            r["links"]["KEV"] = ("https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext="
                                 + cid)
            r.update(exploited=True, kev_added=k["kev_added"], kev_due=k["due"], ransomware=k["ransomware"],
                     kev_action=k["action"])
            r["kev_vendor"], r["kev_product"], r["kev_name"] = k["vendor"], k["product"], k["name"]
            r.setdefault("description", k["description"])
            r.setdefault("published", k["kev_added"])
            r.setdefault("modified", k["kev_added"])
            if not r.get("severity"):
                x = cache.get("nvd_extra", {}).get(cid)
                if x and not x.get("missing") and x.get("score") is not None:
                    r.update(severity=(x["severity"] or "").upper(), score=x["score"], cvss_version=x["cvss_version"],
                             vector=x["vector"], cpes=x["cpes"])
                    r["description"] = x["description"] or r["description"]
                    r["published"] = x["published"] or r["published"]
                    r["modified"] = x["modified"] or r["modified"]
                    r["links"]["NVD"] = "https://nvd.nist.gov/vuln/detail/" + cid
    out = []
    pk_all = {cid: r.get("_pk", []) for cid, r in recs.items()}
    cpes_all = {cid: list(r.get("cpes", [])) for cid, r in recs.items()}
    for cid, r in recs.items():
        if not r["sources"]:
            continue
        r.setdefault("exploited", False)
        hs = [r.get("description", "")] + r.get("cpes", []) + [r.get("kev_vendor", ""), r.get("kev_product", "")]
        hs += [p for _, p in r.get("_pk", [])]
        r["vendors"] = tag_vendors(" ".join(hs), r.pop("_pk", []))
        # display vendor / product
        if r.get("kev_vendor"):
            vp = f"{r['kev_vendor']} {r['kev_product']}".strip()
        elif r.get("cpes"):
            vp = ", ".join(pretty_cpe(c) for c in r["cpes"][:2])
        elif r.get("packages"):
            vp = ", ".join(r["packages"][:2])
        else:
            vp = ""
        r["product"] = vp
        r["description"] = S.strip_html(r.get("description", ""), 420)
        r["cpes"] = r.get("cpes", [])[:3]
        r["primary_url"] = r["links"].get("NVD") or r["links"].get("KEV") or r["links"].get("GHSA")
        r["severity"] = r.get("severity") or "UNKNOWN"
        dates = [r.get("modified"), r.get("published"), r.get("kev_added")]
        r["activity"] = max(d for d in dates if d)
        txt = " ".join([r["description"], r["product"], r.get("kev_name", ""), " ".join(r.get("packages", [])),
                        " ".join(r.get("cpes", []))])
        r["ai_angle"] = AIR.classify(txt, packages=pk_all.get(cid, []), cpes=cpes_all.get(cid, []), cve_ids=[cid])
        out.append(r)
    out.sort(key=lambda r: r["activity"], reverse=True)
    return out


def attach_epss(vulns, cache, args):
    ids = [v["id"] for v in vulns if v["id"].startswith("CVE-")]
    ep = cache.setdefault("epss", {})
    if not args.cache_only:
        log(f"EPSS for {len(ids)} CVEs ...")
        new, err = S.fetch_epss(ids, ep)
        cache["epss"] = ep = new
        return ({"status": "partial" if err else "ok", "count": len([i for i in ids if i in ep]),
                 **({"error": err[:300]} if err else {})})
    return {"status": "skipped", "count": len([i for i in ids if i in ep])}


# ---- output stage -------------------------------------------------------------

def build_rss(vulns, now, site_url):
    items = []
    top = sorted(vulns, key=lambda v: (v["activity"]), reverse=True)
    top = [v for v in top if v["exploited"] or v["severity"] == "CRITICAL" or v.get("ai_angle")]
    top = sorted(top, key=lambda v: AIR.rank(v.get("ai_angle")), reverse=True)[:60]  # AI-first (stable: newest first inside)
    for v in top:
        flags = []
        if v.get("ai_angle"):
            flags.append("AI:" + "/".join(a["type"] for a in v["ai_angle"]))
        if v["exploited"]:
            flags.append("EXPLOITED")
        flags.append(f"{v['severity']} {v['score'] if v.get('score') else ''}".strip())
        title = f"[{' | '.join(flags)}] {v['id']}" + (f" - {v['product']}" if v["product"] else "")
        desc = v["description"]
        if v.get("kev_added"):
            desc += f" (CISA KEV added {v['kev_added'][:10]})"
        d = S.parse_date(v["activity"]) or now
        items.append(
            "<item><title>%s</title><link>%s</link><guid isPermaLink=\"false\">%s</guid>"
            "<pubDate>%s</pubDate><description>%s</description>%s</item>" % (
                escape(title), escape(v["primary_url"] or ""), escape(v["id"] + "@" + v["activity"]),
                format_datetime(d), escape(desc),
                "".join(f"<category>{escape(t)}</category>" for t in v["vendors"][:4])))
    home = site_url or "https://example.invalid/"
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">'
            "<channel><title>AI Cyber Feed - AI-flagged, exploited &amp; critical vulnerabilities</title>"
            f"<link>{escape(home)}</link><description>Exploited-in-the-wild and critical CVEs from NVD, CISA KEV "
            "and GitHub advisories</description><language>en</language>"
            f"<lastBuildDate>{format_datetime(now)}</lastBuildDate>"
            + (f'<atom:link href="{escape(site_url.rstrip("/") + "/feed.xml")}" rel="self" type="application/rss+xml"/>'
               if site_url else "")
            + "".join(items) + "</channel></rss>\n")


def esc(s):
    return escape(str(s), {'"': "&quot;"})


SUMMARY_PATH = os.path.join(HERE, "summary.json")


def load_summary():
    """Hand-written summary.json (see README). Returns None if absent/invalid -> page shows 'summary pending'."""
    try:
        with open(SUMMARY_PATH, encoding="utf-8") as f:
            s = json.load(f)
        return s if isinstance(s, dict) else None
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as e:
        log("WARNING: summary.json unreadable:", e)
        return None


ARCHIVE_DIR = os.path.join(HERE, "summary_archive")
ARCHIVE_INLINE_MAX = 150_000  # bytes of JSON; above this the page lazy-loads summary_archive.json instead of inlining


def load_archive(current=None):
    """All archived summaries (summary_archive/*.json, see archive_summary.py), newest first, NOT capped.
    The current summary is excluded (it is shown at the top)."""
    out, seen = [], set()
    cur = (current or {}).get("updated_at")
    for fn in sorted(os.listdir(ARCHIVE_DIR)) if os.path.isdir(ARCHIVE_DIR) else []:
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(ARCHIVE_DIR, fn), encoding="utf-8") as f:
                s = json.load(f)
        except (OSError, ValueError):
            log("WARNING: unreadable archive file", fn)
            continue
        ts = s.get("updated_at") if isinstance(s, dict) else None
        if not ts or ts == cur or ts in seen:
            continue
        seen.add(ts)
        out.append(s)
    out.sort(key=lambda s: s["updated_at"], reverse=True)
    return out


def js_safe(obj):
    p = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return p.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026") \
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def build_html(data, summary=None, archive=None):
    tpl = open(os.path.join(HERE, "template.html"), encoding="utf-8").read()
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026") \
                     .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    # static fallback for no-JS / crawlers: most important 60 rows
    top = sorted(data["vulnerabilities"], key=lambda v: v["activity"], reverse=True)
    top = sorted(top, key=lambda v: (not v["exploited"], v["severity"] != "CRITICAL"))[:60]
    rows = "".join(
        "<tr><td><a href=\"%s\">%s</a></td><td>%s %s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(v["primary_url"] or "#"), esc(v["id"]), esc(v["severity"]), esc(v.get("score") or ""),
            "EXPLOITED" if v["exploited"] else "", esc(v["product"]), esc(v["description"][:160]))
        for v in top)
    nos = ("<noscript><p>JavaScript is required for filtering. Top items:</p><table><tr><th>CVE</th><th>Severity</th>"
           "<th>Exploited</th><th>Product</th><th>Description</th></tr>" + rows + "</table></noscript>")
    if summary:
        items = "".join("<li><b>%s</b> (%s%s) &mdash; %s</li>" % (
            esc(f.get("title", "")), esc(f.get("severity", "")), ", exploited" if f.get("exploited") else "",
            esc(f.get("action", ""))) for f in summary.get("focus", []) if isinstance(f, dict))
        nos += ("<noscript><h2>Summary</h2><p>%s</p><ul>%s</ul></noscript>" % (esc(summary.get("headline", "")), items))
    archive = archive or []
    inline = len(json.dumps(archive, ensure_ascii=False)) <= ARCHIVE_INLINE_MAX
    arch_js = js_safe({"count": len(archive), "url": "summary_archive.json", "entries": archive if inline else None})
    return (tpl.replace("/*__SUMMARY__*/null", js_safe(summary)).replace("/*__ARCHIVE__*/null", arch_js).replace("/*__DATA__*/null", payload).replace("<!--__NOSCRIPT__-->", nos)
               .replace("__UPDATED__", esc(data["generated_at"].replace("T", " ").replace("Z", " UTC"))))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(HERE, "public"))
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--kev-days", type=int, default=7)
    ap.add_argument("--skip", default="", help="comma list: nvd,kev,ghsa,chatter,<feed name>")
    ap.add_argument("--cache-only", action="store_true", help="re-render from cache, no network")
    args = ap.parse_args()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    cache = load_json(CACHE_PATH, {})

    status = run_sources(args, cache, now)
    vulns = merge(cache, args, now, status)
    status["epss"] = attach_epss(vulns, cache, args)
    ep = cache.get("epss", {})
    for v in vulns:
        e = ep.get(v["id"])
        if e:
            v["epss"], v["epss_pct"] = e
    x_items, x_status = load_x_items(now)
    status["chatter:X"] = x_status
    chatter = [dict(c) for items in cache.get("chatter", {}).values() for c in items] + x_items
    ids = {v["id"] for v in vulns}
    # MSRC: keep only entries that matter (CVE already in feed / actively exploited wording)
    chatter = [c for c in chatter if not (c["source"] == "Microsoft MSRC" and not
               (set(c["cves"]) & ids or re.search(r"exploited|zero-day", c["title"] + c["summary"], re.I)))]
    msrc = [c for c in chatter if c["source"] == "Microsoft MSRC"]
    if len(msrc) > 60:
        drop = {id(c) for c in msrc[60:]}
        chatter = [c for c in chatter if id(c) not in drop]
    for c in chatter:
        c["ai_angle"] = AIR.classify(c["title"] + " " + c["summary"] + " " + c.pop("_ai", ""), feed=c["source"])
        c["linked"] = [x for x in c["cves"] if x in ids]
        c["incident"] = bool(INCIDENT_RX.search(c["title"] + " " + c["summary"]))
    mentions = {}
    for c in chatter:
        for x in c["linked"]:
            mentions[x] = mentions.get(x, 0) + 1
    for v in vulns:
        v["mentions"] = mentions.get(v["id"], 0)
    chatter.sort(key=lambda c: c["date"], reverse=True)

    cache["status"] = {**cache.get("status", {}), **status}
    counts = {
        "vulnerabilities": len(vulns),
        "nvd_high_critical": sum("NVD" in v["sources"] for v in vulns),
        "cisa_kev_recent": sum("KEV" in v["sources"] for v in vulns),
        "github_advisories": sum("GHSA" in v["sources"] for v in vulns),
        "exploited_in_wild": sum(v["exploited"] for v in vulns),
        "critical": sum(v["severity"] == "CRITICAL" for v in vulns),
        "chatter_items": len(chatter),
        "ai_vulns": {"total": sum(bool(v["ai_angle"]) for v in vulns),
                     **{t: sum(any(a["type"] == t for a in (v["ai_angle"] or [])) for v in vulns) for t in AIR.RANK}},
        "ai_chatter": {"total": sum(bool(c["ai_angle"]) for c in chatter),
                       **{t: sum(any(a["type"] == t for a in (c["ai_angle"] or [])) for c in chatter) for t in AIR.RANK}},
        "chatter_by_source": {s: sum(1 for c in chatter if c["source"] == s) for s in sorted({c["source"] for c in chatter})},
    }
    data = {
        "generated_at": S.iso(now), "window_days": args.days, "kev_window_days": args.kev_days,
        "counts": counts, "sources": {k: v for k, v in status.items()},
        "vulnerabilities": vulns, "chatter": chatter,
    }
    save_json(CACHE_PATH, cache)  # persist fetched state first, so outputs can be re-rendered
    os.makedirs(args.out, exist_ok=True)
    save_json(os.path.join(args.out, "data.json"), data)
    summary = load_summary()
    dst = os.path.join(args.out, "summary.json")
    if summary is not None:
        shutil.copyfile(SUMMARY_PATH, dst)
    elif os.path.exists(dst):
        os.remove(dst)
    archive = load_archive(summary)
    save_json(os.path.join(args.out, "summary_archive.json"), archive)
    log("summary archive: %d earlier summaries" % len(archive))
    with open(os.path.join(args.out, "index.html"), "w", encoding="utf-8") as f:
        f.write(build_html(data, summary, archive))
    with open(os.path.join(args.out, "feed.xml"), "w", encoding="utf-8") as f:
        f.write(build_rss(vulns, now, os.environ.get("SITE_URL", "")))
    log("\nDone:", json.dumps(counts, indent=1))
    log("Source status:")
    for k, v in status.items():
        log(f"  {k:38} {v['status']:8} {v.get('count', '')} {v.get('error', '')}")
    # exit non-zero only if nothing at all could be produced
    return 0 if vulns else 2


if __name__ == "__main__":
    sys.exit(main())
