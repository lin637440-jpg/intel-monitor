from enrichment.paper_link import link_papers
from enrichment.cvss_enrich import fetch_cvss
from enrichment.poc_search import search_poc
from enrichment.asset_extract import extract_assets
from enrichment.attack_chain import infer_chain
from enrichment.risk_score import compute_risk_score
from enrichment.chain_viz import render_chain


def _normalize_fields(item):
    """字段归一化：统一 published / description / cvss"""
    item = dict(item)

    # 统一 published
    if not item.get("published"):
        item["published"] = (
            item.get("published_at")
            or item.get("pubDate")
            or item.get("date")
        )

    # 统一 description
    if not item.get("description"):
        item["description"] = (
            item.get("summary")
            or item.get("selftext")
            or item.get("title")
            or ""
        )

    # GitHub Advisories 从 severity 映射 CVSS
    if not item.get("cvss") and item.get("severity"):
        sev_map = {
            "critical": 9.5,
            "high": 8.0,
            "moderate": 5.5,
            "medium": 5.5,
            "low": 2.5,
        }
        sev = str(item["severity"]).lower()
        if sev in sev_map:
            item["cvss"] = {
                "baseScore": sev_map[sev],
                "baseSeverity": sev.upper(),
                "source": "severity_map",
            }

    return item


def enrich(item):
    """对单条情报做富化，返回新字典"""
    item = _normalize_fields(item)
    result = dict(item)

    cve_id = item.get("id") or item.get("cve_id")
    description = item.get("description") or item.get("title") or ""
    source = item.get("source")

    # 1. 论文关联（仅 NVD）
    if source == "NVD" and description:
        try:
            result["related_papers"] = link_papers(description, threshold=0.3)
        except Exception as e:
            result["related_papers"] = []
            result["paper_error"] = str(e)

    # 2. CVSS 补充（仅 NVD）
    if source == "NVD" and cve_id:
        try:
            extra = fetch_cvss(cve_id)
            if extra:
                result["cvss_full"] = extra
        except Exception as e:
            result["cvss_error"] = str(e)

    # 3. POC 检索（仅 NVD）
    if source == "NVD" and cve_id:
        try:
            result["pocs"] = search_poc(cve_id)
        except Exception as e:
            result["pocs"] = []
            result["poc_error"] = str(e)

    # 4. 资产识别
    result["assets"] = extract_assets(description)

    # 5. 攻击链推理
    result["attack_chain"] = infer_chain(description)

    # 6. 评分卡
    result.update(compute_risk_score(result))

    # 7. 攻击链可视化
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
    sample = items[:1]

    enriched = []
    for it in sample:
        print(f"\n处理 [{it.get('id')}] ...")
        r = enrich(it)
        print(f"  risk_score: {r.get('risk_score')}")
        print(f"  risk_level: {r.get('risk_level')}")
        print(f"  assets: {r.get('assets')}")
        enriched.append(r)

    Path("data/enriched_sample.json").write_text(
        json.dumps(enriched, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("\n已保存 data/enriched_sample.json")