"""
热点聚类：对漏洞描述做 Sentence-BERT + KMeans，自动发现主题
"""
import json
import sqlite3
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer

try:
    from sklearn.cluster import KMeans
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

DB_PATH = Path("data/intel.db")
REPORT_PATH = Path("data/clusters.json")
MODEL_NAME = "all-MiniLM-L6-v2"

_model = None


def get_model():
    global _model
    if _model is None:
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def run(n_clusters=8):
    if not HAS_SKLEARN:
        print("需要 pip install scikit-learn")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM items").fetchall()]
    conn.close()

    texts = []
    metas = []
    for r in rows:
        title = r.get("title") or ""
        desc = r.get("description") or ""
        text = f"{title} {desc}".strip()
        if len(text) < 20:
            continue
        texts.append(text[:500])
        metas.append({"uid": r["uid"], "source": r["source"], "title": title})

    if len(texts) < n_clusters:
        print(f"数据太少（{len(texts)} 条），无法聚类")
        return

    model = get_model()
    print(f"编码 {len(texts)} 条...")
    embeddings = model.encode(texts, convert_to_numpy=True, show_progress_bar=True)

    print(f"KMeans 聚类为 {n_clusters} 类...")
    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
    labels = kmeans.fit_predict(embeddings)

    # 聚合
    clusters = {}
    for i, label in enumerate(labels):
        label = int(label)
        clusters.setdefault(label, {
            "cluster_id": label,
            "size": 0,
            "sample_titles": [],
            "keywords": [],
        })
        clusters[label]["size"] += 1
        if len(clusters[label]["sample_titles"]) < 5:
            clusters[label]["sample_titles"].append(metas[i]["title"][:80])

    # 每个簇的关键词：用簇内样本 vs 全部样本的差异找
    all_emb = embeddings.mean(axis=0)
    for label, c in clusters.items():
        idx = [i for i, l in enumerate(labels) if int(l) == label]
        if not idx:
            continue
        cluster_emb = embeddings[idx].mean(axis=0)
        # 找距离中心最近的词（简化版：用 title 首词）
        # 更精确要 TF-IDF，这里简化
        c["keywords"] = [t.split()[0][:15] for t in c["sample_titles"][:5] if t]

    result = {
        "n_clusters": n_clusters,
        "total": len(texts),
        "clusters": list(clusters.values()),
    }

    REPORT_PATH.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"\n{len(clusters)} 个簇：")
    for c in sorted(clusters.values(), key=lambda x: -x["size"]):
        print(f"  簇 {c['cluster_id']}（{c['size']} 条）")
        for t in c["sample_titles"][:2]:
            print(f"    - {t}")
    print(f"\n报告：{REPORT_PATH}")


if __name__ == "__main__":
    run()