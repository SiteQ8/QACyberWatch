#!/usr/bin/env python3
"""Summarise the relay archive into one small file for the landing page.

Reads ``demo/feed/latest.json`` and every day file under ``demo/feed/archive``
and writes ``demo/feed/summary.json``: the window, one row per day with its
match count by level, the keyword, brand and issuer tallies, and the figures of
the latest run. The landing page fetches this file (a few kilobytes) instead of
the whole archive, so the register's figures stay current after every relay run.

Usage: python scripts/feed_summary.py [--feed demo/feed]
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

LEVELS = ["clean", "low", "medium", "high", "critical"]


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def summarise(feed_dir: Path) -> Dict[str, Any]:
    latest = _load(feed_dir / "latest.json") or {}
    archive = feed_dir / "archive"
    days: List[Dict[str, Any]] = []
    keywords: Counter = Counter()
    brands: Counter = Counter()
    issuers: Counter = Counter()
    levels: Counter = Counter()
    unique = set()
    for day_file in sorted(archive.glob("????-??-??.json")):
        day = _load(day_file) or {}
        matches = day.get("matches") or []
        by_level = Counter(m.get("level", "clean") for m in matches)
        days.append(
            {
                "date": day.get("date") or day_file.stem,
                "matches": len(matches),
                "levels": {lv: by_level.get(lv, 0) for lv in LEVELS},
            }
        )
        for m in matches:
            levels[m.get("level", "clean")] += 1
            unique.add(m.get("domain", ""))
            for k in m.get("keywords") or []:
                keywords[k] += 1
            for b in m.get("brands") or []:
                brands[b] += 1
            if m.get("issuer"):
                issuers[m["issuer"]] += 1
    total = sum(d["matches"] for d in days)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": {
            "from": days[0]["date"] if days else None,
            "to": days[-1]["date"] if days else None,
            "days": len(days),
        },
        "matches": total,
        "unique_domains": len(unique),
        "medium_or_above": sum(levels[lv] for lv in ("medium", "high", "critical")),
        "levels": {lv: levels.get(lv, 0) for lv in LEVELS},
        "days_series": days,
        "keywords": [{"keyword": k, "count": c} for k, c in keywords.most_common(12)],
        "brands": [{"brand": b, "count": c} for b, c in brands.most_common(12)],
        "issuers": [{"issuer": i, "count": c} for i, c in issuers.most_common(6)],
        "latest": {
            "generated_at": latest.get("generated_at"),
            "window_seconds": latest.get("window_seconds"),
            "entries": latest.get("entries"),
            "logs": len(latest.get("logs") or []),
            "logs_live": sum(1 for lg in latest.get("logs") or [] if lg.get("status") == "live"),
            "matches": len(latest.get("matches") or []),
            "keywords": latest.get("keywords"),
        },
        "notice": latest.get("notice"),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--feed", default="demo/feed", help="feed directory (default demo/feed)")
    args = ap.parse_args()
    feed_dir = Path(args.feed)
    summary = summarise(feed_dir)
    out = feed_dir / "summary.json"
    out.write_text(
        json.dumps(summary, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    print(
        f"wrote {out} ({out.stat().st_size} bytes): {summary['matches']} matches over "
        f"{summary['window']['days']} day(s), {summary['medium_or_above']} medium or above"
    )


if __name__ == "__main__":
    main()
