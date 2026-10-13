import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DB_PATH = ROOT / "data" / "intel.db"
REPORT_PATH = ROOT / "data" / "enrichment_coverage.json"


def run():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM items").fetchall()]
    conn.close()

    total = len(rows)
    stats = {
        "total": total,
        "with_cvss": 0,
        "with_poc": 0,
        "with_paper": 0,
        "with_asset": 0,
        "with_chain": 0,
        "with_risk_score": 0,
    }

    for r in rows:
        try:
            raw = json.loads(r.get("raw_json") or "{}")
        except Exception:
            continue

        if raw.get("cvss") or raw.get("cvss_full"):
            stats["with_cvss"] += 1
        if raw.get("pocs"):
            stats["with_poc"] += 1
        if raw.get("related_papers"):
            stats["with_paper"] += 1
        if (raw.get("assets") or {}).get("frameworks"):
            stats["with_asset"] += 1
        if (raw.get("attack_chain") or {}).get("chains"):
            stats["with_chain"] += 1
        if raw.get("risk_score") is not None:
            stats["with_risk_score"] += 1

    coverage = {}
    for k, v in stats.items():
        if k == "total":
            continue
        coverage[k] = {
            "count": v,
            "ratio": round(v / total, 3) if total else 0,
        }

    report = {
        "total": total,
        "coverage": coverage,
    }

    REPORT_PATH.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"总记录：{total}\n")
    print(f"{'维度':<20} {'覆盖数':<10} {'覆盖率':<10}")
    print("-" * 40)
    for k, v in coverage.items():
        print(f"{k:<20} {v['count']:<10} {v['ratio']*100:.1f}%")
    print(f"\n报告：{REPORT_PATH}")


if __name__ == "__main__":
    run()