from collectors import (
    cve_collector,
    github_advisories_collector,
    hf_blog_collector,
    anquanke_collector,
    arxiv_collector,
    osv_collector,
)
from storage.db import insert_items


def normalize(source, items):
    """把各源的字段统一成 uid/source/title/description/url/published"""
    out = []
    for it in items:
        if source == "NVD":
            uid = f"NVD:{it.get('id')}"
        elif source == "GitHub Advisories":
            uid = f"GH:{it.get('ghsa_id') or it.get('cve_id')}"
        elif source == "Hugging Face Blog":
            uid = f"HF:{it.get('slug')}"
        elif source == "安全客":
            uid = f"AQ:{it.get('title') or it.get('url')}"
        elif source == "ArXiv":
            uid = f"ARX:{it.get('id')}"
        elif source == "OSV.dev":
            uid = f"OSV:{it.get('id')}"
        else:
            uid = f"{source}:{it.get('url') or it.get('title')}"

        it["uid"] = uid
        out.append(it)
    return out


def _safe_nvd():
    """NVD API 挂了就吃本地缓存"""
    try:
        raw = cve_collector.fetch_cves(days=1, results_per_page=20)
        return [cve_collector.parse_cve(v) for v in raw.get("vulnerabilities", [])]
    except Exception as e:
        print(f"  [NVD] API 失败，用缓存：{type(e).__name__}")
        return cve_collector.load_cached()


def run():
    tasks = [
        ("NVD", lambda: _safe_nvd()),
        (
            "GitHub Advisories",
            lambda: [
                github_advisories_collector.parse_advisory(x)
                for x in github_advisories_collector.fetch_advisories(20)
            ],
        ),
        (
            "Hugging Face Blog",
            lambda: [
                hf_blog_collector.parse_item(b)
                for b in hf_blog_collector.fetch_list(50).get("allBlogs", [])
            ],
        ),
        (
            "安全客",
            lambda: anquanke_collector.parse(anquanke_collector.fetch()),
        ),
        (
            "ArXiv",
            lambda: arxiv_collector.parse(
                arxiv_collector.fetch(query="all:AI security", max_results=25)
            ),
        ),
        (
            "OSV.dev",
            lambda: osv_collector.parse(osv_collector.fetch("requests", "PyPI")),
        ),
    ]

    grand_inserted = 0
    for source, fn in tasks:
        try:
            items = fn()
            items = normalize(source, items)
            inserted, total = insert_items(items)
            grand_inserted += inserted
            print(f"[{source}] 抓到 {len(items)} 条，新入库 {inserted} 条，累计 {total}")
        except Exception as e:
            print(f"[{source}] 失败：{type(e).__name__}: {e}")

    print(f"\n本次共新入库 {grand_inserted} 条")


if __name__ == "__main__":
    run()