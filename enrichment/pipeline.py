from enrichment.paper_link import link_papers
from enrichment.cvss_enrich import fetch_cvss
from enrichment.poc_search import search_poc


def enrich(item):
    """对单条情报做富化，返回新字典"""
    result = dict(item)

    cve_id = item.get("id") or item.get("cve_id")
    description = item.get("description") or item.get("title") or ""

    # 1. 论文关联（只对 NVD 做，避免浪费）
    if item.get("source") == "NVD" and description:
        try:
            result["related_papers"] = link_papers(description, threshold=0.3)
        except Exception as e:
            result["related_papers"] = []
            result["paper_error"] = str(e)

    # 2. CVSS 补充（只对 NVD）
    if item.get("source") == "NVD" and cve_id:
        try:
            extra = fetch_cvss(cve_id)
            if extra:
                result["cvss_full"] = extra
        except Exception as e:
            result["cvss_error"] = str(e)

    # 3. POC 检索（只对 NVD 且有 CVE 号）
    if item.get("source") == "NVD" and cve_id:
        try:
            result["pocs"] = search_poc(cve_id)
        except Exception as e:
            result["pocs"] = []
            result["poc_error"] = str(e)

    return result


if __name__ == "__main__":
    import json
    from pathlib import Path

    items = json.loads(Path("data/cve_latest.json").read_text(encoding="utf-8"))
    sample = items[:3]

    enriched = [enrich(it) for it in sample]
    for e in enriched:
        print(f"\n[{e.get('id')}] {e.get('title')[:60]}")
        print(f"  论文 {len(e.get('related_papers', []))} 篇")
        print(f"  cvss_full: {'有' if e.get('cvss_full') else '无'}")
        print(f"  POC {len(e.get('pocs', []))} 个")