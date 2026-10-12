import json
from pathlib import Path

from sentence_transformers import SentenceTransformer, util

MODEL_NAME = "all-MiniLM-L6-v2"
_model = None


def get_model():
    global _model
    if _model is None:
        print(f"加载模型 {MODEL_NAME} ...")
        _model = SentenceTransformer(MODEL_NAME)
    return _model


def load_arxiv(path="data/arxiv.json"):
    p = Path(path)
    if not p.exists():
        return []
    return json.loads(p.read_text(encoding="utf-8"))


def link_papers(cve_text, arxiv_items=None, threshold=0.5):
    """返回与 cve_text 相似度 > threshold 的论文列表"""
    if arxiv_items is None:
        arxiv_items = load_arxiv()

    if not cve_text or not arxiv_items:
        return []

    model = get_model()
    cve_emb = model.encode(cve_text, convert_to_tensor=True)
    papers = []
    for p in arxiv_items:
        summary = p.get("summary") or p.get("title") or ""
        if not summary:
            continue
        p_emb = model.encode(summary, convert_to_tensor=True)
        score = float(util.cos_sim(cve_emb, p_emb)[0][0])
        if score >= threshold:
            papers.append({
                "title": p.get("title"),
                "url": p.get("id"),
                "score": round(score, 3),
            })

    papers.sort(key=lambda x: x["score"], reverse=True)
    return papers[:5]


if __name__ == "__main__":
    sample = "A memory safety vulnerability in SAP EPP allows unauthenticated attacker to cause denial of service."
    papers = link_papers(sample)
    print(f"匹配到 {len(papers)} 篇论文")
    for p in papers:
        print(f"  [{p['score']}] {p['title'][:70]}")