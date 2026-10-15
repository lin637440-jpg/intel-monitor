"""
实体关系表管理
"""
import sqlite3
from pathlib import Path

DB_PATH = Path("data/intel.db")


def init_graph_tables():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entities (
            eid TEXT PRIMARY KEY,
            type TEXT,
            name TEXT,
            properties TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS relations (
            rid INTEGER PRIMARY KEY AUTOINCREMENT,
            source_eid TEXT,
            target_eid TEXT,
            relation TEXT,
            weight REAL DEFAULT 1.0,
            UNIQUE(source_eid, target_eid, relation)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rel_src ON relations(source_eid)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_rel_tgt ON relations(target_eid)")
    conn.commit()
    conn.close()


def upsert_entity(eid, etype, name, properties=None):
    import json
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR REPLACE INTO entities (eid, type, name, properties) VALUES (?, ?, ?, ?)",
        (eid, etype, name, json.dumps(properties or {}, ensure_ascii=False)),
    )
    conn.commit()
    conn.close()


def upsert_relation(src, tgt, relation, weight=1.0):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR IGNORE INTO relations (source_eid, target_eid, relation, weight) "
        "VALUES (?, ?, ?, ?)",
        (src, tgt, relation, weight),
    )
    conn.commit()
    conn.close()


def get_neighbors(eid, depth=2):
    """返回二跳邻居"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    visited = {eid}
    frontier = [eid]
    all_nodes = {}
    all_edges = []

    for _ in range(depth):
        next_frontier = []
        for node in frontier:
            rows = conn.execute(
                "SELECT source_eid, target_eid, relation, weight FROM relations "
                "WHERE source_eid = ? OR target_eid = ?",
                (node, node),
            ).fetchall()
            for r in rows:
                other = r["target_eid"] if r["source_eid"] == node else r["source_eid"]
                all_edges.append(dict(r))
                if other not in visited:
                    visited.add(other)
                    next_frontier.append(other)
        frontier = next_frontier

    # 拿所有节点信息
    if visited:
        placeholders = ",".join("?" * len(visited))
        rows = conn.execute(
            f"SELECT * FROM entities WHERE eid IN ({placeholders})",
            list(visited),
        ).fetchall()
        for r in rows:
            all_nodes[r["eid"]] = dict(r)

    conn.close()
    return {
        "nodes": list(all_nodes.values()),
        "edges": all_edges,
    }