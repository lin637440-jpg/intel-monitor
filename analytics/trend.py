import json
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path("data/intel.db")
TREND_PATH = Path("data/trend.json")


def parse_dt(s):
    if not s:
        return None
    s = str(s).strip()
    # 处理带时区 +00:00
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo:
                dt = dt.replace(tzinfo=None)
            return dt
        except Exception:
            continue
    return None


def compute_trend():
    if not DB_PATH.exists():
        print("intel.db 不存在")
        return {}

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM items")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    by_date_source = {}
    high_count = 0
    total = 0
    skipped = 0

    for r in rows:
        dt = parse_dt(r.get("published"))
        if not dt:
            dt = parse_dt(r.get("created_at"))
        if not dt:
            skipped += 1
            continue

        date = dt.date().isoformat()

        cvss_score = None
        try:
            raw = json.loads(r.get("raw_json") or "{}")
            cvss = raw.get("cvss") or {}
            if isinstance(cvss, dict):
                cvss_score = cvss.get("baseScore")
        except Exception:
            pass

        key = (date, r["source"])
        entry = by_date_source.setdefault(key, {
            "date": date,
            "source": r["source"],
            "count": 0,
            "cvss_sum": 0.0,
            "cvss_n": 0,
            "high": 0,
        })
        entry["count"] += 1
        total += 1
        if cvss_score is not None:
            entry["cvss_sum"] += cvss_score
            entry["cvss_n"] += 1
            if cvss_score >= 7.0:
                entry["high"] += 1
                high_count += 1

    series = []
    for (date, source), e in sorted(by_date_source.items()):
        avg_cvss = round(e["cvss_sum"] / e["cvss_n"], 2) if e["cvss_n"] else None
        series.append({
            "date": date,
            "source": source,
            "count": e["count"],
            "avg_cvss": avg_cvss,
            "high_count": e["high"],
        })

    result = {
        "generated_at": datetime.utcnow().isoformat(),
        "total": total,
        "skipped": skipped,
        "high_count": high_count,
        "high_ratio": round(high_count / total, 3) if total else 0,
        "series": series,
    }

    TREND_PATH.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"共 {len(series)} 条日/源组合，总 {total} 条情报（跳过 {skipped} 条无日期）")
    print(f"高危（CVSS>=7）占比：{result['high_ratio'] * 100:.1f}%")
    print(f"已写入 {TREND_PATH}")

    return result


if __name__ == "__main__":
    compute_trend()