#!/usr/bin/env python3
"""Save the CURRENT summary.json into summary_archive/ (if its updated_at is not archived yet).

Run this BEFORE overwriting summary.json in the 4-hourly summary routine:
    python3 archive_summary.py            # archive current summary.json
    python3 archive_summary.py --backfill # also recover earlier committed versions from git history
Files are named summary_archive/<updated_at UTC>.json, e.g. 2026-10-23T1241Z.json. Standard library only.
"""
import json, os, re, subprocess, sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "summary.json")
ARCH = os.path.join(HERE, "summary_archive")


def parse_ts(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def archived_stamps():
    out = set()
    for fn in os.listdir(ARCH) if os.path.isdir(ARCH) else []:
        if fn.endswith(".json"):
            try:
                with open(os.path.join(ARCH, fn), encoding="utf-8") as f:
                    t = parse_ts(json.load(f).get("updated_at"))
                if t:
                    out.add(t)
            except (OSError, ValueError):
                pass
    return out


def archive_text(text, seen):
    """Archive one summary JSON text; returns filename or None if skipped (invalid / already archived)."""
    try:
        s = json.loads(text)
    except ValueError:
        return None
    t = parse_ts(s.get("updated_at")) if isinstance(s, dict) else None
    if not t or t in seen:
        return None
    os.makedirs(ARCH, exist_ok=True)
    name = t.strftime("%Y-%m-%dT%H%MZ")
    if os.path.exists(os.path.join(ARCH, name + ".json")):  # same minute, different second
        name = t.strftime("%Y-%m-%dT%H%M%SZ")
    with open(os.path.join(ARCH, name + ".json"), "w", encoding="utf-8") as f:
        f.write(text if text.endswith("\n") else text + "\n")
    seen.add(t)
    return name + ".json"


def main():
    seen = archived_stamps()
    done = []
    if "--backfill" in sys.argv:
        try:
            revs = subprocess.check_output(["git", "-C", HERE, "log", "--reverse", "--format=%h", "--", "summary.json"], text=True).split()
        except (OSError, subprocess.CalledProcessError) as e:
            print("git history unavailable:", e); revs = []
        for r in revs:
            try:
                txt = subprocess.check_output(["git", "-C", HERE, "show", r + ":summary.json"], text=True)
            except subprocess.CalledProcessError:
                continue
            n = archive_text(txt, seen)
            if n: done.append(n)
    if os.path.exists(SRC):
        with open(SRC, encoding="utf-8") as f:
            n = archive_text(f.read(), seen)
        if n: done.append(n)
    print("archived:", ", ".join(done) if done else "nothing new", "| total:", len(archived_stamps()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
