import json
import re
import sqlite3
from pathlib import Path

DB_PATH = Path("data/intel.db")
MERGED_PATH = Path("data/merged_cve.json")

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

SOURCE_PRIORITY = {
    "NVD": 10,
    "GitHub Advisories": 9,
    "OSV.dev": 8,
    "Exploit-DB": 7,
    "ArXiv": 6,
    "安全客": 5,
    "Hugging Face Blog": 4,
    "Seebug Paper": 3,
    "Hacker News": 2,
}


def extract_cve(item):
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


def merge():
    if not DB_PATH.exists():
        print("intel.db 不存在")
        return {}

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM items")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    # 按 CVE 分组
    cve_map = {}
    for r in rows:
        cve = extract_cve(r)
        if cve:
            cve_map.setdefault(cve, []).append(r)

    merged = {}
    multi_source_count = 0

    for cve, items in cve_map.items():
        if len(items) == 1:
            merged[cve] = {
                "cve_id": cve,
                "primary_source": items[0]["source"],
                "primary_title": items[0].get("title"),
                "primary_url": items[0].get("url"),
                "cross_refs": [],
                "source_count": 1,
                "items_count": 1,
            }
            continue

        # 按源优先级排序
        items_sorted = sorted(
            items,
            key=lambda x: -SOURCE_PRIORITY.get(x["source"], 0),
        )
        primary = items_sorted[0]
        cross_refs = []
        for other in items_sorted[1:]:
            cross_refs.append({
                "source": other["source"],
                "title": other.get("title"),
                "url": other.get("url"),
            })

        merged[cve] = {
            "cve_id": cve,
            "primary_source": primary["source"],
            "primary_title": primary.get("title"),
            "primary_url": primary.get("url"),
            "cross_refs": cross_refs,
            "source_count": len({x["source"] for x in items}),
            "items_count": len(items),
            "sources": sorted({x["source"] for x in items}),
        }

        if len({x["source"] for x in items}) > 1:
            multi_source_count += 1

    MERGED_PATH.write_text(
        json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"总 CVE：{len(merged)}")
    print(f"多源命中：{multi_source_count}")
    print(f"已写入 {MERGED_PATH}")

    multi = {k: v for k, v in merged.items() if v["source_count"] > 1}
    if multi:
        print("\n多源合并样例：")
        for k, v in list(multi.items())[:5]:
            print(f"  {k}  sources={v['sources']}  refs={len(v['cross_refs'])}")

    return merged


if __name__ == "__main__":
    merge()