import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path("data/intel.db")
METRICS_PATH = Path("data/metrics.json")


def parse_dt(s):
    if not s:
        return None
    s = s.strip()
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def compute_metrics(days=1):
    if not DB_PATH.exists():
        print("intel.db 不存在，先跑 main.py")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT source, published FROM items "
        "WHERE created_at >= datetime('now', ?)",
        (f"-{days} day",),
    )
    rows = cur.fetchall()
    conn.close()

    now = datetime.now(timezone.utc)
    stats = {}

    for source, published in rows:
        dt = parse_dt(published)
        if dt is None:
            continue
        delta_hours = (now - dt).total_seconds() / 3600
        if delta_hours < 0:
            continue
        s = stats.setdefault(source, {
            "count": 0, "total_hours": 0.0,
            "max_hours": 0.0, "min_hours": float("inf"),
        })
        s["count"] += 1
        s["total_hours"] += delta_hours
        s["max_hours"] = max(s["max_hours"], delta_hours)
        s["min_hours"] = min(s["min_hours"], delta_hours)

    result = {}
    for source, s in stats.items():
        if s["count"] == 0:
            continue
        result[source] = {
            "count": s["count"],
            "avg_delay_hours": round(s["total_hours"] / s["count"], 2),
            "max_delay_hours": round(s["max_hours"], 2),
            "min_delay_hours": round(s["min_hours"], 2),
        }

    METRICS_PATH.parent.mkdir(exist_ok=True)
    METRICS_PATH.write_text(json.dumps({
        "generated_at": now.isoformat(),
        "window_days": days,
        "sources": result,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"metrics 已写入 {METRICS_PATH}（窗口 {days} 天）")
    for src, m in result.items():
        print(f"  {src}: count={m['count']} avg={m['avg_delay_hours']}h "
              f"max={m['max_delay_hours']}h min={m['min_delay_hours']}h")


if __name__ == "__main__":
    compute_metrics(days=7)