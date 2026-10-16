import json
import sqlite3
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer

from storage.db import DB_PATH

# 基于 __file__ 推项目根目录（app/monitor/semantic_search.py → 上两级）
BASE_DIR = Path(__file__).resolve().parents[2]
INDEX_PATH = BASE_DIR / "data" / "embeddings.npy"
META_PATH = BASE_DIR / "data" / "embeddings_meta.json"
MODEL_NAME = "all-MiniLM-L6-v2"

_model = None


def get_model():
    global _model
    if _model is None:
        print(f"加载模型 {MODEL_NAME} ...")
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def build_index(force=False):
    if not force and INDEX_PATH.exists() and META_PATH.exists():
        print(f"索引已存在：{INDEX_PATH}，跳过。force=True 强制重建")
        return

    if not DB_PATH.exists():
        print(f"intel.db 不存在：{DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT uid, source, title, description, url, published FROM items")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    if not rows:
        print("intel.db 为空，先跑 main.py")
        return

    texts = [
        f"{r.get('title', '')} {r.get('description', '') or ''}"[:600].strip()
        for r in rows
    ]

    model = get_model()
    print(f"编码 {len(texts)} 条 ...")
    emb = model.encode(texts, convert_to_numpy=True, show_progress_bar=True)
    emb = emb.astype("float32")
    norms = np.linalg.norm(emb, axis=1, keepdims=True)
    norms[norms == 0] = 1
    emb = emb / norms

    INDEX_PATH.parent.mkdir(exist_ok=True)
    np.save(INDEX_PATH, emb)
    META_PATH.write_text(
        json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"索引已保存：{INDEX_PATH}，共 {len(rows)} 条")


def semantic_search(query, top_k=10):
    if not INDEX_PATH.exists() or not META_PATH.exists():
        build_index()

    if not INDEX_PATH.exists():
        print(f"索引不存在：{INDEX_PATH}")
        return []

    emb = np.load(INDEX_PATH)
    meta = json.loads(META_PATH.read_text(encoding="utf-8"))

    model = get_model()
    q = model.encode([query], convert_to_numpy=True).astype("float32")
    norm = np.linalg.norm(q, axis=1, keepdims=True)
    norm[norm == 0] = 1
    q = q / norm

    scores = (emb @ q.T).flatten()
    top_idx = np.argsort(-scores)[:top_k]

    results = []
    for i in top_idx:
        if i < 0 or i >= len(meta):
            continue
        item = dict(meta[i])
        item["_score"] = round(float(scores[i]), 4)
        results.append(item)
    return results


if __name__ == "__main__":
    build_index(force=True)
    queries = [
        "prompt injection attack on large language models",
        "SQL injection in WordPress",
        "supply chain malicious package",
        "model stealing API abuse",
    ]
    for q in queries:
        print(f"\n=== 查询：{q} ===")
        for r in semantic_search(q, top_k=3):
            title = r.get("title") or ""
            source = r.get("source") or "?"
            score = r.get("_score", 0)
            print(f"  [{score}] [{source}] {title[:65]}")