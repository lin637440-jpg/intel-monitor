import json
import sqlite3

from main import COLLECTORS, collect_source
from storage.db import DB_PATH
from enrichment.pipeline import enrich
from common.exceptions import NotFoundError, IntelMonitorError
from enrichment.merge_cve import merge

def collect_vulnerabilities() -> list[dict]:
    """
    执行采集、去重、富化和存储，返回本次新增的情报记录。
    """
    new_items = []
    for source in COLLECTORS:
        try:
            inserted, _ = collect_source(source)
            if inserted > 0:
                fresh = _fetch_recent(source, limit=inserted)
                for it in fresh:
                    try:
                        enriched = enrich(it)
                        new_items.append(enriched)
                    except Exception:
                        new_items.append(it)
        except Exception:
            continue
    return new_items


def search_vulnerabilities(keyword: str) -> list[dict]:
    """按关键词查询已有情报。"""
    if not keyword:
        return []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    like = f"%{keyword}%"
    cur.execute(
        "SELECT * FROM items "
        "WHERE title LIKE ? OR description LIKE ? "
        "ORDER BY created_at DESC LIMIT 100",
        (like, like),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    out = []
    for r in rows:
        try:
            raw = json.loads(r.get("raw_json") or "{}")
            raw.update({k: v for k, v in r.items() if k != "raw_json"})
            out.append(raw)
        except Exception:
            out.append(r)
    return out


def enrich_vulnerability(cve_id: str) -> dict:
    """对指定 CVE 进行富化，返回更新后的记录。"""
    if not cve_id:
        raise NotFoundError("cve_id 不能为空")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM items WHERE uid LIKE ? LIMIT 1", (f"%{cve_id}%",))
    row = cur.fetchone()
    conn.close()

    if row is None:
        raise NotFoundError(f"未找到 {cve_id}")

    item = dict(row)
    try:
        raw = json.loads(item.get("raw_json") or "{}")
        raw.update({k: v for k, v in item.items() if k != "raw_json"})
    except Exception:
        raw = item

    try:
        return enrich(raw)
    except Exception as e:
        raise IntelMonitorError(f"富化失败：{e}") from e


def _fetch_recent(source, limit=20):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM items WHERE source = ? ORDER BY created_at DESC LIMIT ?",
        (source, limit),
    )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    out = []
    for r in rows:
        try:
            raw = json.loads(r.get("raw_json") or "{}")
            raw.update({k: v for k, v in r.items() if k != "raw_json"})
            out.append(raw)
        except Exception:
            out.append(r)
    return out


if __name__ == "__main__":
    print("=== search_vulnerabilities('WordPress') ===")
    r = search_vulnerabilities("WordPress")
    print(f"找到 {len(r)} 条")
    if r:
        print(f"  第一条: {r[0].get('title', '')[:60]}")

    print("\n=== enrich_vulnerability('CVE-2026-13144') ===")
    try:
        r = enrich_vulnerability("CVE-2026-13144")
        print(f"  {r.get('id')} 评分={r.get('risk_score')} 等级={r.get('risk_level')}")
    except Exception as e:
        print(f"  {type(e).__name__}: {e}")
    print("\n=== merge() 跨源归并 ===")
    m = merge()
    print(f"  归并后 CVE 数：{len(m)}")
def _pick_url(item):
    """智能提取 URL，兼容 9 个源的字段差异"""
    # 1. 直接 url
    if item.get("url"):
        return str(item["url"])
    # 2. html_url（GitHub）
    if item.get("html_url"):
        return str(item["html_url"])
    # 3. link（RSS）
    if item.get("link"):
        return str(item["link"])
    # 4. id 是 URL（ArXiv）
    id_val = item.get("id") or ""
    if isinstance(id_val, str) and id_val.startswith("http"):
        return id_val
    # 5. references 列表（NVD / OSV）
    refs = item.get("references") or []
    if isinstance(refs, list) and refs:
        first = refs[0]
        if isinstance(first, dict):
            u = first.get("url") or first.get("href") or ""
            if u:
                return str(u)
        elif isinstance(first, str):
            return first
    # 6. NVD 特殊：用官方 CVE 页
    cve = item.get("id") or item.get("cve_id") or ""
    if isinstance(cve, str) and cve.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{cve}"
    # 7. GHSA 特殊：用 GitHub 公告页
    ghsa = item.get("ghsa_id") or ""
    if isinstance(ghsa, str) and ghsa.startswith("GHSA-"):
        return f"https://github.com/advisories/{ghsa}"
    return ""


def to_chroma_record(item):
    """把 A 的 record 转成 B 要的 Chroma 格式"""
    title = item.get("title") or ""
    desc = item.get("description") or ""

    assets = item.get("assets", {}).get("frameworks", [])
    chains = item.get("attack_chain", {}).get("chains", [])
    chain_names = ", ".join(c["name"] for c in chains)

    document = f"{title}\n\n{desc}"
    if assets:
        document += f"\n\n资产: {', '.join(assets)}"
    if chain_names:
        document += f"\n\n攻击链: {chain_names}"

    cvss_obj = item.get("cvss") or {}
    cvss_score = cvss_obj.get("baseScore") if isinstance(cvss_obj, dict) else None

    return {
        "id": item.get("uid"),
        "document": document,
        "metadata": {
            "source": item.get("source") or "",
            "cve_id": item.get("id") or item.get("cve_id") or "",
            "cvss": cvss_score if cvss_score is not None else 0.0,
            "risk_score": item.get("risk_score") or 0.0,
            "risk_level": item.get("risk_level") or "",
            "cwe": ",".join(item.get("cwe") or []),
            "url": _pick_url(item),
            "published": item.get("published") or "",
        },
    }
def export_for_chroma(path="data/chroma_records.json"):
    """导出全部 items 为 Chroma 格式，给 B 用"""
    import json as _json
    import sqlite3 as _sqlite
    from storage.db import DB_PATH
    from pathlib import Path as _Path

    if not DB_PATH.exists():
        print("intel.db 不存在")
        return []

    conn = _sqlite.connect(DB_PATH)
    conn.row_factory = _sqlite.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM items").fetchall()]
    conn.close()

    out = []
    for r in rows:
        try:
            raw = _json.loads(r.get("raw_json") or "{}")
            raw.update({k: v for k, v in r.items() if k != "raw_json"})
        except Exception:
            raw = r
        out.append(to_chroma_record(raw))

    _Path(path).write_text(
        _json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"导出 {len(out)} 条 -> {path}")
    return out