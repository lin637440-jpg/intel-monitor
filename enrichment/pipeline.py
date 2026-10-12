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
from enrichment.paper_link import link_papers
from enrichment.cvss_enrich import fetch_cvss
from enrichment.poc_search import search_poc
from enrichment.asset_extract import extract_assets
from enrichment.attack_chain import infer_chain
from enrichment.risk_score import compute_risk_score
from enrichment.chain_viz import render_chain


def enrich(item):
    """对单条情报做富化，返回新字典"""
    result = dict(item)
    cve_id = item.get("id") or item.get("cve_id")
    description = item.get("description") or item.get("title") or ""

    # 1. 论文关联
    if item.get("source") == "NVD" and description:
        try:
            result["related_papers"] = link_papers(description, threshold=0.3)
        except Exception as e:
            result["related_papers"] = []
            result["paper_error"] = str(e)

    # 2. CVSS 补充
    if item.get("source") == "NVD" and cve_id:
        try:
            extra = fetch_cvss(cve_id)
            if extra:
                result["cvss_full"] = extra
        except Exception as e:
            result["cvss_error"] = str(e)

    # 3. POC 检索
    if item.get("source") == "NVD" and cve_id:
        try:
            result["pocs"] = search_poc(cve_id)
        except Exception as e:
            result["pocs"] = []
            result["poc_error"] = str(e)

    # 4. 资产识别
    result["assets"] = extract_assets(description)

    # 5. 攻击链推理
    result["attack_chain"] = infer_chain(description)

    # 6. 评分卡（依赖前 5 维的结果）
    result.update(compute_risk_score(result))

    # 7. 攻击链可视化（只对有攻击链的）
    try:
        result["chain_files"] = render_chain(result)
    except Exception as e:
        result["chain_files"] = []
        result["chain_viz_error"] = str(e)

    return result


if __name__ == "__main__":
    import json
    from pathlib import Path

    items = json.loads(Path("data/cve_latest.json").read_text(encoding="utf-8"))
    sample = items[:3]

    enriched = [enrich(it) for it in sample]

    Path("data/enriched_sample.json").write_text(
        json.dumps(enriched, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    for e in enriched:
        print(f"\n[{e.get('id')}] {e.get('title')[:60]}")
        print(f"  论文: {len(e.get('related_papers', []))} 篇")
        print(f"  CVSS: {'有' if e.get('cvss_full') else '无'}")
        print(f"  POC: {len(e.get('pocs', []))} 个")
        print(f"  资产: {e.get('assets', {}).get('frameworks')}")
        print(f"  攻击链: {e.get('attack_chain', {}).get('matched_count')} 条")
        print(f"  评分: {e.get('risk_score')} ({e.get('risk_level')})")
        print(f"  可视化文件: {len(e.get('chain_files', []))} 个")

    print("\n已保存 data/enriched_sample.json")

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