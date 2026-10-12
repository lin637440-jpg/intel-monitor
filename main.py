from collectors import (
    cve_collector,
    github_advisories_collector,
    hf_blog_collector,
    anquanke_collector,
    arxiv_collector,
    osv_collector,
    seebug_collector,
    exploitdb_collector,
    hn_collector,
)
from storage.db import insert_items
from storage.sync_state import update_sync, record_error


def normalize(source, items):
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
        elif source == "Seebug Paper":
            uid = f"SB:{it.get('url') or it.get('title')}"
        elif source == "Exploit-DB":
            uid = f"EDB:{it.get('url') or it.get('title')}"
        elif source == "Hacker News":
            uid = f"HN:{it.get('url') or it.get('title')}"
        else:
            uid = f"{source}:{it.get('url') or it.get('title')}"
        it["uid"] = uid
        out.append(it)
    return out


def _safe_nvd():
    try:
        raw = cve_collector.fetch_cves(days=1, results_per_page=20)
        return [cve_collector.parse_cve(v) for v in raw.get("vulnerabilities", [])]
    except Exception as e:
        print(f"  [NVD] API 失败，用缓存：{type(e).__name__}")
        return cve_collector.load_cached()


def collect_nvd():
    return _safe_nvd()


def collect_github():
    return [github_advisories_collector.parse_advisory(x)
            for x in github_advisories_collector.fetch_advisories(20)]


def collect_hf():
    return [hf_blog_collector.parse_item(b)
            for b in hf_blog_collector.fetch_list(50).get("allBlogs", [])]


def collect_anquanke():
    return anquanke_collector.parse(anquanke_collector.fetch())


def collect_arxiv():
    return arxiv_collector.parse(
        arxiv_collector.fetch(query="all:AI security", max_results=25)
    )


def collect_osv():
    return osv_collector.parse(osv_collector.fetch("requests", "PyPI"))


def collect_seebug():
    return seebug_collector.parse(seebug_collector.fetch())


def collect_exploitdb():
    return exploitdb_collector.parse(exploitdb_collector.fetch())


def collect_hn():
    return hn_collector.parse(hn_collector.fetch())


COLLECTORS = {
    "NVD": collect_nvd,
    "GitHub Advisories": collect_github,
    "Hugging Face Blog": collect_hf,
    "安全客": collect_anquanke,
    "ArXiv": collect_arxiv,
    "OSV.dev": collect_osv,
    "Seebug Paper": collect_seebug,
    "Exploit-DB": collect_exploitdb,
    "Hacker News": collect_hn,
}


def collect_source(source):
    """采集单个源，去重入库，返回 (新入库条数, 累计条数)"""
    fn = COLLECTORS.get(source)
    if not fn:
        print(f"未知源：{source}")
        return 0, 0
    try:
        items = fn()
        items = normalize(source, items)
        inserted, total = insert_items(items)
        update_sync(source, len(items), inserted)
        print(f"[{source}] 抓到 {len(items)} 条，新入库 {inserted} 条，累计 {total}")
        return inserted, total
    except Exception as e:
        record_error(source)
        print(f"[{source}] 失败：{type(e).__name__}: {e}")
        return 0, 0


def collect_all():
    total_inserted = 0
    for source in COLLECTORS:
        inserted, _ = collect_source(source)
        total_inserted += inserted
    print(f"\n本次共新入库 {total_inserted} 条")


if __name__ == "__main__":
    collect_all()