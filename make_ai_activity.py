#!/usr/bin/env python3
"""First-draft `ai_activity` block for summary.json, generated from docs/data.json (or public/data.json).

    python3 make_ai_activity.py                 # print JSON to stdout
    python3 make_ai_activity.py --merge         # put it into summary.json (run archive_summary.py FIRST)
    python3 make_ai_activity.py --data public/data.json --days 7

It is only a DRAFT for the 4-hourly summary routine: review/edit by judgment (merge duplicates, fix status, rewrite
summaries, verify against the sources, drop noise such as r/LocalLLaMA hobby posts) before publishing. Never invent facts.
Selection (last N days, newest first):
  * vulnerabilities with ai_angle set and exploited=true (CISA KEV / known exploited), shown even if the KEV date is older
  * chatter items with ai_angle 'cause', OR ai_angle (any) AND (incident flag OR exploitation words in the text)
Groups: AI as the cause > AI products being exploited > AI impact / AI keys & infrastructure (an item appears once, highest first).
Status heuristic: exploited (KEV/'actively exploited'/'in the wild'/'exploitation'), unverified (X / Reddit / 'claims'), patched (fixed + no exploitation), else reported.
Items about the same topic (TOPICS below) are merged, preferring non-X sources. Standard library only.
"""
import json, os, re, sys
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
LABELS = {"cause": "AI as the cause", "product": "AI products being exploited", "impact": "AI impact / AI keys & infrastructure"}
KEYS = {"cause": "ai_cause", "product": "ai_product_exploited", "impact": "ai_impact"}
EXPL = re.compile(r"actively exploited|exploited in the wild|being exploited|exploitation|exploited|compromised|backdoor|supply[- ]chain attack|breach|stolen|hijack|intrusion|attack", re.I)
STRONG = re.compile(r"actively exploited|exploited in the wild|being exploited|exploitation hits|confirmed", re.I)
NOISE_SRC = {"r/LocalLLaMA", "r/MachineLearning", "Chrome Releases"}
# topic key -> regex; items matching the same topic are merged into one entry (edit as new campaigns appear)
TOPICS = [
    ("litellm", r"litellm"), ("railway", r"railway"), ("artex-connectwise", r"artex|connectwise|storm-0940"),
    ("mythos-aisi", r"mythos|aisi|ai security institute"), ("php2shell", r"php2shell"), ("rejetto", r"rejetto"),
    ("papercut", r"papercut"), ("opencode", r"opencode"), ("cybercartel", r"cybercartel|carliy0s|straiker"),
    ("ransomware-ai", r"ransomware affiliates|phantom|autonomous red team"), ("tidb", r"tidb|pingcap|fulcrumsec"),
    ("llmjacking", r"llmjacking"),
]
TOPICS = [(k, re.compile(r, re.I)) for k, r in TOPICS]
TOPIC_GROUP = {"litellm": "product", "railway": "impact", "opencode": "impact", "tidb": "impact", "llmjacking": "impact"}  # manual overrides
NOISE_TITLE = re.compile(r"stable channel update|tabletop|harness is the hard|your ai agent fixed|you gave your ai agent|pirate gold|noun-verb|in other news|unvetted ai agents|model tampering", re.I)


def parse(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def status_of(text, source, kev=False):
    if kev or STRONG.search(text) and source not in ("X",) or re.search(r"actively exploited|exploited in the wild", text, re.I) and source != "X":
        return "exploited"
    if source == "X" or source.startswith("r/") or re.search(r"\bclaims?\b|alleged|reportedly|unverified", text, re.I):
        return "unverified"
    if re.search(r"\b(fixed|patched|patch)\b", text, re.I) and not EXPL.search(text):
        return "patched"
    return "reported"


def group_of(types):
    for t in ("cause", "product", "impact"):
        if t in types:
            return t
    return None


def build(data, days):
    now = parse(data["generated_at"]) or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    cand = []
    for v in data["vulnerabilities"]:
        if v.get("ai_angle") and v.get("exploited"):
            types = [a["type"] for a in v["ai_angle"]]
            g = "cause" if "cause" in types else "product"
            cand.append(dict(topic=v["id"], g=g, title="%s: %s" % (v["id"], (v.get("product") or v["description"][:70])),
                             date=v.get("kev_added") or v.get("modified") or v.get("published"), source="CISA KEV / NVD",
                             summary=v["description"][:260], status="exploited", cves=[v["id"]],
                             url=v.get("primary_url") or "https://nvd.nist.gov/vuln/detail/" + v["id"], x=False))
    for c in data["chatter"]:
        t = c.get("ai_angle") or []
        types = [a["type"] for a in t]
        d = parse(c["date"])
        if not t or not d or d < cutoff or c["source"] in NOISE_SRC and "cause" not in types:
            continue
        text = c["title"] + " " + c["summary"]
        if NOISE_TITLE.search(c["title"]):
            continue
        if not ("cause" in types or c.get("incident") or EXPL.search(text)):
            continue
        topic = next((k for k, rx in TOPICS if rx.search(text)), None) or "t:" + re.sub(r"\W+", " ", c["title"].lower())[:50]
        cand.append(dict(topic=topic, g=group_of(types), title=c["title"], date=c["date"], source=c["source"],
                         summary=re.sub(r"\s+", " ", c["summary"] or c["title"])[:260], status=status_of(text, c["source"]),
                         cves=c["cves"], url=c["url"], x=c["source"] == "X" or c["source"].startswith("r/")))
    merged = {}
    for it in cand:
        merged.setdefault(it["topic"], []).append(it)
    out = {}
    for topic, its in merged.items():
        # representative: prefer non-social sources, then newest
        its.sort(key=lambda i: (i["x"], -(parse(i["date"] or "") or datetime(1970, 1, 1, tzinfo=timezone.utc)).timestamp()))
        b = dict(its[0])
        b["cves"] = sorted({c for i in its for c in i["cves"]})
        if any(i["status"] == "exploited" for i in its) and not b["x"]:
            b["status"] = "exploited"
        g = TOPIC_GROUP.get(topic) or group_of([i["g"] for i in its])
        out.setdefault(g, []).append(b)
    groups = {k: [{f: b[f] for f in ("title", "date", "summary", "status", "cves", "url", "source")} for b in out.get(k, [])] for k in LABELS}
    for k in groups:
        groups[k].sort(key=lambda i: i["date"] or "", reverse=True)
    counts = {KEYS[k]: len(v) for k, v in groups.items()}
    last48 = sum(1 for g in groups.values() for i in g if (parse(i["date"] or "") or cutoff) >= now - timedelta(hours=48))
    total = sum(counts.values())
    return {
        "overview": "DRAFT - rewrite by judgment. %d AI-related exploit/attack items in the last %d days: %d where AI was the cause, %d AI products exploited, %d AI impact / AI-key items." % (total, days, *counts.values()),
        "counts": counts,
        "groups": [{"label": LABELS[k], "items": groups[k]} for k in ("cause", "product", "impact")],
        "trend_note": "DRAFT - %d of %d items are dated within the last 48 hours." % (last48, total),
    }


def main():
    a = sys.argv[1:]
    path = a[a.index("--data") + 1] if "--data" in a else os.path.join(HERE, "docs", "data.json")
    days = int(a[a.index("--days") + 1]) if "--days" in a else 7
    block = build(json.load(open(path, encoding="utf-8")), days)
    if "--merge" in a:
        sp = os.path.join(HERE, "summary.json")
        s = json.load(open(sp, encoding="utf-8"))
        s["ai_activity"] = block
        json.dump(s, open(sp, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        print("merged DRAFT ai_activity into summary.json - edit it before publishing")
    else:
        print(json.dumps(block, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
