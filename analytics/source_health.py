import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path("data/intel.db")
HEALTH_PATH = Path("data/source_health.json")


def compute_health():
    if not DB_PATH.exists():
        print("intel.db 不存在")
        return {}

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # 从 sync_state 读运行记录
    try:
        cur.execute("SELECT * FROM sync_state ORDER BY source")
        states = [dict(r) for r in cur.fetchall()]
    except Exception:
        states = []

    # 从 items 统计各源条数
    cur.execute("SELECT source, COUNT(*) as cnt FROM items GROUP BY source")
    counts = {r["source"]: r["cnt"] for r in cur.fetchall()}
    conn.close()

    result = {}
    for s in states:
        src = s["source"]
        result[src] = {
            "last_sync_at": s.get("last_sync_at"),
            "total_runs": s.get("total_runs", 0),
            "error_count": s.get("error_count", 0),
            "success_rate": round(
                1 - s.get("error_count", 0) / max(s.get("total_runs", 1), 1), 3
            ),
            "last_inserted": s.get("last_inserted", 0),
            "items_in_db": counts.get(src, 0),
            "status": "OK" if s.get("error_count", 0) == 0 else "WARN",
        }

    HEALTH_PATH.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": result,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"健康报告已写入 {HEALTH_PATH}")
    print(f"\n{'源':<25} {'状态':<6} {'运行':<5} {'错误':<5} {'入库':<8}")
    print("-" * 60)
    for src, h in result.items():
        print(f"{src:<25} {h['status']:<6} {h['total_runs']:<5} "
              f"{h['error_count']:<5} {h['items_in_db']:<8}")

    return result


if __name__ == "__main__":
    compute_health()