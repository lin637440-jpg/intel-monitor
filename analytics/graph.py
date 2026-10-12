import json
import sqlite3
from pathlib import Path

import networkx as nx

DB_PATH = Path("data/intel.db")
GRAPH_PATH = Path("data/graph.json")


def _extract_cwe(raw_json):
    if not raw_json:
        return []
    try:
        d = json.loads(raw_json)
    except Exception:
        return []
    cwes = d.get("cwe") or []
    return [c for c in cwes if isinstance(c, str)] if isinstance(cwes, list) else []


def _extract_assets(raw_json):
    if not raw_json:
        return []
    try:
        d = json.loads(raw_json)
    except Exception:
        return []
    assets = d.get("assets") or {}
    if isinstance(assets, dict):
        return assets.get("frameworks") or []
    return []


def _extract_cvss(raw_json):
    if not raw_json:
        return None
    try:
        d = json.loads(raw_json)
    except Exception:
        return None
    cvss = d.get("cvss") or {}
    if isinstance(cvss, dict):
        return cvss.get("baseScore")
    return None


def build_graph():
    if not DB_PATH.exists():
        print("intel.db 不存在")
        return None

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT uid, source, title, raw_json FROM items")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    G = nx.Graph()

    for r in rows:
        uid = r["uid"]
        title = (r.get("title") or "")[:60]
        cvss = _extract_cvss(r.get("raw_json"))
        G.add_node(
            uid,
            type="cve",
            label=title,
            source=r["source"],
            cvss=cvss,
        )

        for cwe in _extract_cwe(r.get("raw_json")):
            cwe_node = f"CWE::{cwe}"
            G.add_node(cwe_node, type="cwe", label=cwe)
            G.add_edge(uid, cwe_node, relation="has_cwe")

        for asset in _extract_assets(r.get("raw_json")):
            asset_node = f"ASSET::{asset}"
            G.add_node(asset_node, type="asset", label=asset)
            G.add_edge(uid, asset_node, relation="affects")

    nodes = []
    for n, data in G.nodes(data=True):
        nodes.append({
            "id": n,
            "type": data.get("type"),
            "label": data.get("label", n),
            "source": data.get("source"),
            "cvss": data.get("cvss"),
        })

    edges = []
    for u, v, data in G.edges(data=True):
        edges.append({
            "source": u,
            "target": v,
            "relation": data.get("relation"),
        })

    result = {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "cve_nodes": sum(1 for n in nodes if n["type"] == "cve"),
            "cwe_nodes": sum(1 for n in nodes if n["type"] == "cwe"),
            "asset_nodes": sum(1 for n in nodes if n["type"] == "asset"),
        },
    }

    GRAPH_PATH.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"图已构建：{result['stats']}")
    print(f"已写入 {GRAPH_PATH}")
    return result


if __name__ == "__main__":
    build_graph()