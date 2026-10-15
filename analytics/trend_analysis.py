"""
趋势分析：近 7 天 CVE 数量、高危占比、激增检测
"""
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

DB_PATH = Path("data/intel.db")
REPORT_PATH = Path("data/trend_analysis.json")


def parse_dt(s):
    if not s:
        return None
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
        "%a, %d %b %Y %H:%M:%S %z",
    ]:
        try:
            dt = datetime.strptime(str(s).strip(), fmt)
            if dt.tzinfo:
                dt = dt.replace(tzinfo=None)
            return dt
        except Exception:
            continue
    return None


def run(days=7):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM items").fetchall()]
    conn.close()

    now = datetime.now()
    cutoff = now - timedelta(days=days)

    # 按天统计
    daily = defaultdict(lambda: {"count": 0, "high": 0})
    # 按框架统计（激增检测）
    by_framework = defaultdict(lambda: {"count": 0, "recent": 0})

    for r in rows:
        dt = parse_dt(r.get("published")) or parse_dt(r.get("created_at"))
        if not dt:
            continue

        date_key = dt.date().isoformat()

        try:
            raw = json.loads(r.get("raw_json") or "{}")
        except Exception:
            raw = {}

        cvss = (raw.get("cvss") or {}).get("baseScore") if isinstance(raw.get("cvss"), dict) else None
        is_high = cvss is not None and cvss >= 7.0

        daily[date_key]["count"] += 1
        if is_high:
            daily[date_key]["high"] += 1

        # 框架
        for fw in (raw.get("assets") or {}).get("frameworks", []):
            by_framework[fw]["count"] += 1
            if dt >= cutoff:
                by_framework[fw]["recent"] += 1

    # 激增检测：近 7 天占总量 > 50% 且 >= 3 条
    surges = []
    for fw, s in by_framework.items():
        if s["count"] >= 3 and s["recent"] / s["count"] >= 0.5:
            surges.append({
                "framework": fw,
                "total": s["count"],
                "recent": s["recent"],
                "ratio": round(s["recent"] / s["count"], 2),
            })
    surges.sort(key=lambda x: x["recent"], reverse=True)

    # 近 7 天总览
    recent_total = sum(v["count"] for k, v in daily.items()
                       if parse_dt(k) and parse_dt(k) >= cutoff)
    recent_high = sum(v["high"] for k, v in daily.items()
                      if parse_dt(k) and parse_dt(k) >= cutoff)

    report = {
        "generated_at": now.isoformat(),
        "days": days,
        "daily": dict(sorted(daily.items())),
        "recent_total": recent_total,
        "recent_high": recent_high,
        "recent_high_ratio": round(recent_high / recent_total, 3) if recent_total else 0,
        "surges": surges[:10],
        "by_framework": dict(sorted(by_framework.items(),
                                    key=lambda x: -x[1]["count"])[:20]),
    }

    REPORT_PATH.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"近 {days} 天：{recent_total} 条，高危 {recent_high} 条 "
          f"({report['recent_high_ratio']*100:.1f}%)")
    print(f"激增框架：{len(surges)} 个")
    for s in surges[:5]:
        print(f"  {s['framework']}: {s['recent']}/{s['total']}")
    print(f"报告：{REPORT_PATH}")


if __name__ == "__main__":
    run()