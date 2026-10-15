"""
攻击面统计：按框架统计漏洞数、平均 CVSS、POC 覆盖、攻击链
"""
import json
import sqlite3
from collections import defaultdict
from pathlib import Path

DB_PATH = Path("data/intel.db")
REPORT_PATH = Path("data/attack_surface.json")


def run():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM items").fetchall()]
    conn.close()

    fw_stats = defaultdict(lambda: {
        "count": 0,
        "cvss_sum": 0.0,
        "cvss_n": 0,
        "cvss_max": 0.0,
        "with_poc": 0,
        "chains": set(),
        "cves": [],
    })

    total = 0
    for r in rows:
        try:
            raw = json.loads(r.get("raw_json") or "{}")
        except Exception:
            continue

        assets = (raw.get("assets") or {}).get("frameworks") or []
        if not assets:
            continue

        cvss = (raw.get("cvss") or {}).get("baseScore") if isinstance(raw.get("cvss"), dict) else None
        has_poc = bool(raw.get("pocs"))
        chains = [c["name"] for c in (raw.get("attack_chain") or {}).get("chains", [])]

        for fw in assets:
            total += 1
            s = fw_stats[fw]
            s["count"] += 1
            if cvss is not None:
                s["cvss_sum"] += cvss
                s["cvss_n"] += 1
                s["cvss_max"] = max(s["cvss_max"], cvss)
            if has_poc:
                s["with_poc"] += 1
            for c in chains:
                s["chains"].add(c)
            if len(s["cves"]) < 10:
                cve = raw.get("id") or r.get("uid")
                s["cves"].append(cve)

    # 组装排行
    ranking = []
    for fw, s in fw_stats.items():
        avg_cvss = round(s["cvss_sum"] / s["cvss_n"], 2) if s["cvss_n"] else 0
        ranking.append({
            "framework": fw,
            "count": s["count"],
            "avg_cvss": avg_cvss,
            "max_cvss": round(s["cvss_max"], 2),
            "no_cvss": s["count"] - s["cvss_n"],
            "with_poc": s["with_poc"],
            "poc_ratio": round(s["with_poc"] / s["count"], 2) if s["count"] else 0,
            "chains": sorted(s["chains"]),
            "sample_cves": s["cves"][:5],
            "risk_score": round(avg_cvss * s["count"] ** 0.5, 2),  # 综合排序分
        })

    ranking.sort(key=lambda x: -x["risk_score"])

    result = {
        "total_framework_mentions": total,
        "frameworks": len(ranking),
        "ranking": ranking,
    }

    REPORT_PATH.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"涉及 {len(ranking)} 个框架，共 {total} 次提及\n")
    print(f"{'框架':<20} {'漏洞数':<8} {'平均CVSS':<10} {'POC':<6} {'链':<6}")
    print("-" * 60)
    for r in ranking[:15]:
        print(f"{r['framework']:<20} {r['count']:<8} {r['avg_cvss']:<10} "
              f"{r['with_poc']:<6} {len(r['chains']):<6}")
    print(f"\n报告：{REPORT_PATH}")


if __name__ == "__main__":
    run()