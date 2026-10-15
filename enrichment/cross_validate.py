"""
多源交叉验证
按 CVE 号聚合多源记录，检测冲突，计算可信度
"""
import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path

DB_PATH = Path("data/intel.db")
REPORT_PATH = Path("data/cross_validate_report.json")

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# 来源权威性权重
SOURCE_TRUST = {
    "NVD": 1.0,
    "GitHub Advisories": 0.9,
    "OSV.dev": 0.85,
    "Exploit-DB": 0.7,
    "Seebug Paper": 0.6,
    "安全客": 0.6,
    "Hacker News": 0.5,
    "ArXiv": 0.7,
    "Hugging Face Blog": 0.6,
}


def extract_cve(item):
    """从记录里提取 CVE 号"""
    for key in ("id", "cve_id", "uid", "title"):
        v = item.get(key)
        if v:
            m = CVE_PATTERN.search(str(v))
            if m:
                return m.group(0).upper()
    raw = item.get("raw_json")
    if raw:
        m = CVE_PATTERN.search(str(raw))
        if m:
            return m.group(0).upper()
    return None


def extract_cvss(item):
    """提取 CVSS 分数"""
    try:
        raw = item.get("raw_json")
        if raw:
            d = json.loads(raw) if isinstance(raw, str) else raw
            cvss = d.get("cvss") or {}
            if isinstance(cvss, dict):
                return cvss.get("baseScore")
    except Exception:
        pass
    return None


def aggregate_by_cve():
    """按 CVE 号聚合所有源"""
    if not DB_PATH.exists():
        print("intel.db 不存在")
        return {}

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM items").fetchall()]
    conn.close()

    cve_map = defaultdict(list)
    for r in rows:
        cve = extract_cve(r)
        if cve:
            cve_map[cve].append(r)

    return cve_map


def detect_conflicts(items):
    """检测多源冲突"""
    cvss_values = []
    versions = set()
    sources = []

    for it in items:
        cvss = extract_cvss(it)
        if cvss is not None:
            cvss_values.append(cvss)
        sources.append(it.get("source"))

    conflicts = {}

    # CVSS 冲突：最大值 - 最小值 > 1.0
    if len(cvss_values) >= 2:
        if max(cvss_values) - min(cvss_values) > 1.0:
            conflicts["cvss"] = {
                "values": cvss_values,
                "spread": round(max(cvss_values) - min(cvss_values), 2),
            }

    return conflicts, {
        "cvss_values": cvss_values,
        "sources": sources,
    }


def compute_confidence(items, conflicts):
    """计算可信度"""
    # 基础分：最高来源权重
    trust_scores = [SOURCE_TRUST.get(it.get("source"), 0.4) for it in items]
    base = max(trust_scores) if trust_scores else 0.4

    # 多源加分
    unique_sources = len(set(it.get("source") for it in items))
    bonus = 0.05 * (unique_sources - 1)

    # 冲突扣分
    penalty = 0.1 * len(conflicts)

    confidence = min(max(base + bonus - penalty, 0.0), 1.0)
    return round(confidence, 3)


def run():
    cve_map = aggregate_by_cve()
    print(f"共 {len(cve_map)} 个 CVE")

    multi_source = {k: v for k, v in cve_map.items() if len(set(i["source"] for i in v)) > 1}
    print(f"多源命中：{len(multi_source)} 个\n")

    result = {}
    for cve, items in cve_map.items():
        conflicts, meta = detect_conflicts(items)
        confidence = compute_confidence(items, conflicts)

        result[cve] = {
            "cve_id": cve,
            "source_count": len(set(i["source"] for i in items)),
            "sources": sorted(set(i["source"] for i in items)),
            "confidence": confidence,
            "conflicts": conflicts,
            "cvss_values": meta["cvss_values"],
        }

    # 写回数据库
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    updated = 0
    for cve, data in result.items():
        for it in cve_map[cve]:
            try:
                raw = json.loads(it.get("raw_json") or "{}")
                raw["confidence"] = data["confidence"]
                raw["cross_source_count"] = data["source_count"]
                if data["conflicts"]:
                    raw["has_conflict"] = True
                cur.execute(
                    "UPDATE items SET raw_json = ? WHERE uid = ?",
                    (json.dumps(raw, ensure_ascii=False), it["uid"]),
                )
                updated += 1
            except Exception:
                pass
    conn.commit()
    conn.close()

    # 报告
    REPORT_PATH.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"更新 {updated} 条记录")
    print(f"报告：{REPORT_PATH}")

    # 打印多源命中
    if multi_source:
        print(f"\n多源命中样例：")
        for cve in list(multi_source.keys())[:5]:
            d = result[cve]
            print(f"  {cve}  conf={d['confidence']}  sources={d['sources']}")


if __name__ == "__main__":
    run()