import json
import sqlite3

from main import COLLECTORS, collect_source
from storage.db import DB_PATH
from enrichment.pipeline import enrich
from common.exceptions import NotFoundError, IntelMonitorError


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