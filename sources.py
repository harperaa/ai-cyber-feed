"""Network helpers and per-source fetchers. Standard library only."""
import gzip
import http.client
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

UA = "vuln-feed/1.0 (+static vulnerability feed builder; no tracking)"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def log(*a):
    print(*a, file=sys.stderr, flush=True)


class FetchError(Exception):
    pass


def http_get(url, headers=None, timeout=60, retries=4, backoff=5.0, max_bytes=40_000_000):
    """GET with retry/backoff on 403/429/5xx/timeouts. Returns (bytes, headers)."""
    h = {"User-Agent": UA, "Accept-Encoding": "gzip", "Accept": "*/*"}
    h.update(headers or {})
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise FetchError("response too large")
                if r.headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                return data, r.headers
        except urllib.error.HTTPError as e:
            last = f"HTTP {e.code}"
            if e.code in (403, 429, 500, 502, 503, 504):
                ra = e.headers.get("Retry-After") if e.headers else None
                wait = backoff * (2 ** attempt)
                if ra and ra.isdigit():
                    wait = min(max(wait, int(ra)), 120)
                # GitHub unauthenticated rate limit exhausted: don't hammer
                if e.headers and e.headers.get("X-RateLimit-Remaining") == "0":
                    raise FetchError(f"rate limited (HTTP {e.code}); resets at "
                                     f"{e.headers.get('X-RateLimit-Reset')}")
                log(f"  {last} for {url[:90]} - retry in {wait:.0f}s")
                time.sleep(wait)
                continue
            raise FetchError(last)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, http.client.HTTPException) as e:
            last = f"{type(e).__name__}: {e}"
            wait = backoff * (2 ** attempt)
            log(f"  {last} for {url[:90]} - retry in {wait:.0f}s")
            time.sleep(wait)
    raise FetchError(f"gave up after {retries} attempts ({last})")


def http_json(url, **kw):
    data, hdrs = http_get(url, **kw)
    try:
        return json.loads(data.decode("utf-8")), hdrs
    except ValueError as e:
        raise FetchError(f"bad JSON: {e}")


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_date(s):
    """Parse ISO-8601 or RFC-822 dates to aware UTC datetime; None on failure."""
    if not s:
        return None
    s = s.strip()
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        try:
            d = parsedate_to_datetime(s)
        except (TypeError, ValueError):
            try:  # e.g. "Thu, 22 Oct 2026 22:13:53 Z"
                d = parsedate_to_datetime(re.sub(r"\sZ$", " +0000", s))
            except (TypeError, ValueError):
                return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def safe_url(u):
    if isinstance(u, str) and re.match(r"^https?://", u.strip(), re.I):
        return u.strip()
    return ""


def strip_html(s, limit=400):
    s = html.unescape(re.sub(r"<(script|style).*?</\1>", " ", s or "", flags=re.S | re.I))
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(re.sub(r"\s+", " ", s)).strip()
    return s if len(s) <= limit else s[: limit - 1].rstrip() + "…"


def extract_cves(*texts):
    out = []
    for t in texts:
        for m in CVE_RE.findall(t or ""):
            m = m.upper()
            if m not in out:
                out.append(m)
    return out


# ----------------------------------------------------------------- NVD
def sev_from_score(score):
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def parse_nvd_vuln(v):
    c = v.get("cve", {})
    cid = c.get("id")
    if not cid or c.get("vulnStatus") == "Rejected":
        return None
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    if desc.startswith("** REJECT"):
        return None
    best = None  # (score, severity, version, vector)
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        for m in c.get("metrics", {}).get(key, []):
            d = m.get("cvssData", {})
            sc = d.get("baseScore")
            if sc is None:
                continue
            sev = d.get("baseSeverity") or sev_from_score(sc)
            if best is None or sc > best[0]:
                best = (sc, sev, ver, d.get("vectorString"))
    cpes = []
    for conf in c.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", True):
                    continue
                parts = m.get("criteria", "").split(":")
                if len(parts) > 5:
                    vp = f"{parts[3]}:{parts[4]}"
                    if vp not in cpes:
                        cpes.append(vp)
    return {
        "id": cid,
        "description": desc,
        "published": c.get("published", "")[:19] + "Z",
        "modified": c.get("lastModified", "")[:19] + "Z",
        "score": best[0] if best else None,
        "severity": best[1].upper() if best else None,
        "cvss_version": best[2] if best else None,
        "vector": best[3] if best else None,
        "cpes": cpes[:12],
        "nvd_kev": bool(c.get("cisaExploitAdd")),
    }


def fetch_nvd(days, api_key=None, prev=None, deadline=None):
    """Return (items_by_id, partial_error). Queries HIGH and CRITICAL (CVSS v3.x) CVEs
    last-modified (covers new + updated) in the window."""
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    delay = 0.8 if api_key else 6.5  # public limit: 5 req / rolling 30s
    headers = {"apiKey": api_key} if api_key else {}
    items, err = {}, None
    first = True
    for sev in ("CRITICAL", "HIGH"):
        idx = 0
        while True:
            q = urllib.parse.urlencode({
                "lastModStartDate": start, "lastModEndDate": end,
                "cvssV3Severity": sev, "resultsPerPage": 500, "startIndex": idx})
            if not first:
                time.sleep(delay)
            first = False
            try:
                data, _ = http_json("https://services.nvd.nist.gov/rest/json/cves/2.0?" + q,
                                    headers=headers, timeout=180, retries=4, backoff=10)
            except FetchError as e:
                err = f"NVD {sev} startIndex={idx}: {e}"
                log("  NVD error:", err)
                return items, err
            for v in data.get("vulnerabilities", []):
                p = parse_nvd_vuln(v)
                if p and p["score"] is not None and p["score"] >= 7.0:
                    items[p["id"]] = p
            total = data.get("totalResults", 0)
            idx += data.get("resultsPerPage", 500)
            log(f"  NVD {sev}: {min(idx, total)}/{total}")
            if idx >= total:
                break
    return items, err


def fetch_nvd_single(cve_id, api_key=None):
    data, _ = http_json("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id,
                        headers={"apiKey": api_key} if api_key else {}, timeout=60, retries=3, backoff=10)
    vs = data.get("vulnerabilities", [])
    return parse_nvd_vuln(vs[0]) if vs else None


# ----------------------------------------------------------------- CISA KEV
def fetch_kev():
    data, _ = http_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                        timeout=60)
    out = {}
    for v in data.get("vulnerabilities", []):
        cid = v.get("cveID")
        if not cid:
            continue
        out[cid] = {
            "id": cid,
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "description": v.get("shortDescription", ""),
            "kev_added": (v.get("dateAdded") or "") + "T00:00:00Z",
            "due": v.get("dueDate", ""),
            "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "action": v.get("requiredAction", ""),
        }
    if not out:
        raise FetchError("KEV catalog empty")
    return out


# ----------------------------------------------------------------- GitHub advisories
def fetch_ghsa(days, token=None, max_pages=10):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = "Bearer " + token
    items, err = {}, None
    for sev in ("critical", "high"):
        url = "https://api.github.com/advisories?" + urllib.parse.urlencode({
            "severity": sev, "type": "reviewed", "per_page": 100,
            "updated": ">=" + since, "sort": "updated", "direction": "desc"})
        pages = 0
        while url and pages < max_pages:
            try:
                data, hdrs = http_json(url, headers=headers, timeout=60, retries=3, backoff=8)
            except FetchError as e:
                err = f"GHSA {sev}: {e}"
                log("  GHSA error:", err)
                return items, err
            pages += 1
            for a in data:
                if a.get("withdrawn_at"):
                    continue
                pk = []
                for vu in a.get("vulnerabilities") or []:
                    p = vu.get("package") or {}
                    if p.get("name"):
                        pk.append((p.get("ecosystem", ""), p["name"]))
                score = (a.get("cvss") or {}).get("score") or 0
                gid = a.get("ghsa_id")
                items[gid] = {
                    "ghsa_id": gid,
                    "id": a.get("cve_id") or gid,
                    "summary": a.get("summary", ""),
                    "description": a.get("summary", ""),
                    "severity": (a.get("severity") or "").upper(),
                    "score": score or None,
                    "vector": (a.get("cvss") or {}).get("vector_string"),
                    "published": a.get("published_at"),
                    "modified": a.get("updated_at"),
                    "url": a.get("html_url"),
                    "packages": pk[:8],
                }
            link = hdrs.get("Link", "") or ""
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            url = m.group(1) if m else None
            if url:
                time.sleep(1)
    return items, err


# ----------------------------------------------------------------- EPSS
def fetch_epss(cves, prev=None):
    """Return {cve: [epss, percentile]}; keeps previous values on failure."""
    out = dict(prev or {})
    cves = sorted(cves)
    err = None
    for i in range(0, len(cves), 100):
        batch = cves[i:i + 100]
        try:
            data, _ = http_json("https://api.first.org/data/v1/epss?cve=" + ",".join(batch),
                                timeout=60, retries=3, backoff=5)
        except FetchError as e:
            err = str(e)
            log("  EPSS error:", err)
            break
        for r in data.get("data", []):
            try:
                out[r["cve"]] = [round(float(r["epss"]), 5), round(float(r["percentile"]), 5)]
            except (KeyError, ValueError):
                pass
        time.sleep(0.5)
    return out, err


# ----------------------------------------------------------------- RSS / Atom
def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _child_text(el, name):
    for c in el:
        if _local(c.tag) == name:
            return (c.text or "").strip() if c.text else "".join(c.itertext()).strip()
    return ""


def parse_feed(data):
    """Generic RSS 2.0 / Atom parser -> list of dicts(title, link, summary, date, author, content)."""
    root = ET.fromstring(data)
    out = []
    for el in root.iter():
        n = _local(el.tag)
        if n not in ("item", "entry"):
            continue
        link = ""
        if n == "entry":
            for c in el:
                if _local(c.tag) == "link" and (c.get("rel") in (None, "alternate")):
                    link = c.get("href", "")
                    break
        else:
            link = _child_text(el, "link") or _child_text(el, "guid")
        author = ""
        for c in el:
            if _local(c.tag) in ("author", "creator"):
                author = _child_text(c, "name") or (c.text or "").strip()
        content = _child_text(el, "content") or _child_text(el, "encoded") or ""
        summary = _child_text(el, "summary") or _child_text(el, "description") or content
        out.append({
            "title": _child_text(el, "title"),
            "link": link.strip(),
            "summary": summary,
            "content": content or summary,
            "date": parse_date(_child_text(el, "pubDate") or _child_text(el, "published")
                               or _child_text(el, "updated") or _child_text(el, "date")),
            "author": author,
        })
    return out
