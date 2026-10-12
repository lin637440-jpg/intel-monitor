import json
import re
import sqlite3
from pathlib import Path

DB_PATH = Path("data/intel.db")

SOURCE_WEIGHTS = {
    "NVD": 1.0,
    "GitHub Advisories": 0.9,
    "OSV.dev": 0.8,
    "ArXiv": 0.6,
    "安全客": 0.5,
    "Hugging Face Blog": 0.5,
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cve_id(item):
    if item.get("cve_id"):
        v = str(item["cve_id"]).upper()
        if CVE_PATTERN.match(v):
            return v
    if item.get("id"):
        v = str(item["id"]).upper()
        if CVE_PATTERN.match(v):
            return v
    for k in ("title", "description", "uid"):
        v = item.get(k)
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


def _extract_cwe(raw_json):
    if not raw_json:
        return []
    try:
        d = json.loads(raw_json)
    except Exception:
        return []
    cwes = d.get("cwe") or []
    if isinstance(cwes, list):
        return [c for c in cwes if isinstance(c, str)]
    return []


def _extract_cvss(raw_json):
    if not raw_json:
        return None
    try:
        d = json.loads(raw_json)
    except Exception:
        return None
    cvss = d.get("cvss") or {}
    if isinstance(cvss, dict):
        return cvss.get("baseScore")
    return None


def compute_confidence():
    """按 CWE 类型聚合，输出情报主题分布"""
    if not DB_PATH.exists():
        print("intel.db 不存在")
        return {}

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM items")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    cve_map = {}
    for r in rows:
        cve = extract_cve_id(r)
        if cve:
            cve_map.setdefault(cve, []).append(r)

    cve_result = {}
    for cve, items in cve_map.items():
        sources = sorted({it["source"] for it in items})
        weights = [SOURCE_WEIGHTS.get(s, 0.4) for s in sources]
        base = max(weights) if weights else 0.4
        bonus = 0.1 * (len(sources) - 1)
        confidence = min(round(base + bonus, 3), 1.0)
        cve_result[cve] = {
            "cve_id": cve,
            "sources": sources,
            "source_count": len(sources),
            "confidence": confidence,
            "items_count": len(items),
        }

    cwe_map = {}
    for r in rows:
        cwes = _extract_cwe(r.get("raw_json"))
        cvss = _extract_cvss(r.get("raw_json"))
        for c in cwes:
            e = cwe_map.setdefault(c, {
                "cwe": c,
                "count": 0,
                "cvss_sum": 0.0,
                "cvss_n": 0,
                "cvss_max": 0.0,
                "sources": set(),
                "sample_titles": [],
            })
            e["count"] += 1
            e["sources"].add(r["source"])
            if cvss is not None:
                e["cvss_sum"] += cvss
                e["cvss_n"] += 1
                e["cvss_max"] = max(e["cvss_max"], cvss)
            if len(e["sample_titles"]) < 3:
                e["sample_titles"].append(r.get("title") or "")

    cwe_result = []
    for c, e in sorted(cwe_map.items(), key=lambda x: -x[1]["count"]):
        cwe_result.append({
            "cwe": c,
            "count": e["count"],
            "avg_cvss": round(e["cvss_sum"] / e["cvss_n"], 2) if e["cvss_n"] else None,
            "max_cvss": round(e["cvss_max"], 2) if e["cvss_n"] else None,
            "sources": sorted(e["sources"]),
            "sample_titles": e["sample_titles"],
        })

    return {
        "cve_stats": cve_result,
        "cwe_stats": cwe_result,
        "total_cve": len(cve_result),
        "total_cwe": len(cwe_result),
        "multi_source_cve": sum(1 for v in cve_result.values() if v["source_count"] > 1),
    }


def save_confidence(path="data/confidence.json"):
    result = compute_confidence()
    Path(path).write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"总 CVE：{result['total_cve']}，多源命中：{result['multi_source_cve']}")
    print(f"总 CWE 类型：{result['total_cwe']}")
    print("\nTOP 10 漏洞类型：")
    for e in result["cwe_stats"][:10]:
        print(f"  {e['cwe']}: {e['count']} 条, avg_cvss={e['avg_cvss']}, "
              f"sources={e['sources']}")


if __name__ == "__main__":
    save_confidence()