"""
从 items 表抽取实体和关系，写入 entities / relations 表
"""
import json
import re
import sqlite3
from pathlib import Path

from storage.graph_db import init_graph_tables, upsert_entity, upsert_relation

DB_PATH = Path("data/intel.db")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _eid(etype, name):
    """统一实体 ID 格式"""
    safe = re.sub(r'[^\w\-.]', '_', str(name))[:80]
    return f"{etype}::{safe}"


def build():
    init_graph_tables()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM items").fetchall()]
    conn.close()

    entity_count = 0
    relation_count = 0

    for r in rows:
        uid = r["uid"]
        source = r["source"]

        try:
            raw = json.loads(r.get("raw_json") or "{}")
        except Exception:
            raw = {}

        # 1. CVE 实体
        cve_id = raw.get("id") or ""
        m = CVE_PATTERN.search(str(cve_id)) if cve_id else None
        if not m:
            m = CVE_PATTERN.search(str(r.get("title") or ""))
        cve_eid = None
        if m:
            cve_id = m.group(0).upper()
            cve_eid = _eid("cve", cve_id)
            upsert_entity(cve_eid, "cve", cve_id, {"source": source})
            entity_count += 1

        # 2. 框架实体
        frameworks = (raw.get("assets") or {}).get("frameworks") or []
        for fw in frameworks:
            fw_eid = _eid("framework", fw)
            upsert_entity(fw_eid, "framework", fw)
            entity_count += 1
            if cve_eid:
                upsert_relation(cve_eid, fw_eid, "affects")
                relation_count += 1

        # 3. CWE 实体
        for cwe in raw.get("cwe") or []:
            cwe_eid = _eid("cwe", cwe)
            upsert_entity(cwe_eid, "cwe", cwe)
            entity_count += 1
            if cve_eid:
                upsert_relation(cve_eid, cwe_eid, "belongs_to_cwe")
                relation_count += 1

        # 4. 论文实体
        for paper in (raw.get("related_papers") or [])[:5]:
            title = (paper.get("title") or "")[:60]
            if not title:
                continue
            paper_eid = _eid("paper", title)
            upsert_entity(paper_eid, "paper", title,
                          {"url": paper.get("url"), "score": paper.get("score")})
            entity_count += 1
            if cve_eid:
                upsert_relation(cve_eid, paper_eid, "described_in",
                                weight=paper.get("score", 1.0))
                relation_count += 1

        # 5. POC 实体
        for poc in (raw.get("pocs") or [])[:3]:
            name = poc.get("name") or ""
            if not name:
                continue
            poc_eid = _eid("poc", name)
            upsert_entity(poc_eid, "poc", name, {"url": poc.get("url")})
            entity_count += 1
            if cve_eid:
                upsert_relation(cve_eid, poc_eid, "has_poc")
                relation_count += 1

        # 6. 攻击链实体
        for chain in (raw.get("attack_chain") or {}).get("chains", []):
            name = chain["name"]
            chain_eid = _eid("chain", name)
            upsert_entity(chain_eid, "chain", name,
                          {"steps": chain.get("steps", [])})
            entity_count += 1
            if cve_eid:
                upsert_relation(cve_eid, chain_eid, "belongs_to_chain")
                relation_count += 1

        # 7. 数据源实体
        src_eid = _eid("source", source)
        upsert_entity(src_eid, "source", source)
        if cve_eid:
            upsert_relation(cve_eid, src_eid, "reported_by")

    # 统计
    conn = sqlite3.connect(DB_PATH)
    total_e = conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
    total_r = conn.execute("SELECT COUNT(*) FROM relations").fetchone()[0]
    conn.close()

    print(f"实体：{total_e} 个，关系：{total_r} 条")


if __name__ == "__main__":
    build()