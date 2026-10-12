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
    """从 item 的 uid/title/description/raw_json 里找 CVE 号"""
    for k in ("id", "cve_id", "uid", "title", "description"):
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

    # GitHub Advisories 的 cve_id 字段
    if item.get("cve_id"):
        return item["cve_id"].upper()

    return None


def compute_confidence():
    """扫描 items 表，按 CVE 分组，计算每个 CVE 的置信度"""
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
        if not cve:
            continue
        cve_map.setdefault(cve, []).append(r)

    result = {}
    for cve, items in cve_map.items():
        sources = list({it["source"] for it in items})
        weights = [SOURCE_WEIGHTS.get(s, 0.4) for s in sources]

        # 多源加权：置信度 = 最高权重 + 额外源 * 0.1（封顶 1.0）
        base = max(weights) if weights else 0.4
        bonus = 0.1 * (len(sources) - 1)
        confidence = min(round(base + bonus, 3), 1.0)

        result[cve] = {
            "cve_id": cve,
            "sources": sources,
            "source_count": len(sources),
            "confidence": confidence,
            "items_count": len(items),
        }

    return result


def save_confidence(path="data/confidence.json"):
    result = compute_confidence()
    Path(path).write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"共 {len(result)} 个 CVE，已写入 {path}")
    # 打印多源命中的
    multi = {k: v for k, v in result.items() if v["source_count"] > 1}
    print(f"其中多源命中的有 {len(multi)} 个：")
    for k, v in list(multi.items())[:10]:
        print(f"  {k}  conf={v['confidence']}  sources={v['sources']}")


if __name__ == "__main__":
    save_confidence()