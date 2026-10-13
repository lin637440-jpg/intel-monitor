import json
import random
import sqlite3
from pathlib import Path

DB_PATH = Path("data/intel.db")
REPORT_PATH = Path("data/accuracy_report.json")
SAMPLE_SIZE = 20


def load_samples():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM items WHERE raw_json IS NOT NULL"
    ).fetchall()]
    conn.close()

    # 过滤出有富化字段的
    enriched = []
    for r in rows:
        try:
            raw = json.loads(r.get("raw_json") or "{}")
            if raw.get("cvss") or raw.get("pocs") or raw.get("related_papers"):
                raw["_source"] = r["source"]
                enriched.append(raw)
        except Exception:
            continue

    random.seed(42)
    return random.sample(enriched, min(SAMPLE_SIZE, len(enriched)))


def auto_check(item):
    """自动检查每项的字段完整性"""
    checks = {
        "cvss_valid": False,
        "poc_reasonable": False,
        "paper_reasonable": False,
        "asset_valid": False,
        "chain_valid": False,
    }

    # CVSS 检查：baseScore 在 0-10 之间
    cvss = item.get("cvss") or {}
    if isinstance(cvss, dict):
        score = cvss.get("baseScore")
        if score is not None and 0 <= score <= 10:
            checks["cvss_valid"] = True

    # POC 检查：URL 是 github.com 或 exploit-db
    pocs = item.get("pocs") or []
    if pocs:
        valid = sum(1 for p in pocs if "github.com" in (p.get("url") or ""))
        checks["poc_reasonable"] = valid > 0
    else:
        checks["poc_reasonable"] = True  # 无 POC 也算合格

    # 论文检查：score 在合理范围
    papers = item.get("related_papers") or []
    if papers:
        valid = sum(1 for p in papers if 0.3 <= p.get("score", 0) <= 1.0)
        checks["paper_reasonable"] = valid > 0
    else:
        checks["paper_reasonable"] = True

    # 资产检查：框架名在已知列表
    assets = item.get("assets") or {}
    frameworks = assets.get("frameworks", [])
    known = ["PyTorch", "TensorFlow", "Transformers", "LangChain",
             "vLLM", "Hugging Face", "OpenAI", "GPT", "LLaMA"]
    if frameworks:
        checks["asset_valid"] = all(f in known for f in frameworks)
    else:
        checks["asset_valid"] = True

    # 攻击链检查：chains 非空且 steps 有内容
    chain = item.get("attack_chain") or {}
    chains = chain.get("chains", [])
    if chains:
        checks["chain_valid"] = all(
            len(c.get("steps", [])) >= 2 for c in chains
        )
    else:
        checks["chain_valid"] = True

    return checks


def run():
    samples = load_samples()
    print(f"抽样 {len(samples)} 条\n")

    details = []
    for i, item in enumerate(samples, 1):
        checks = auto_check(item)
        passed = sum(checks.values())
        total = len(checks)
        rate = passed / total

        print(f"[{i}] {item.get('id', 'N/A')} - {item.get('title', '')[:60]}")
        print(f"     CVSS={checks['cvss_valid']} POC={checks['poc_reasonable']} "
              f"论文={checks['paper_reasonable']} 资产={checks['asset_valid']} "
              f"攻击链={checks['chain_valid']}")
        print(f"     准确率 {passed}/{total} = {rate:.0%}")

        details.append({
            "id": item.get("id"),
            "source": item.get("_source"),
            "checks": checks,
            "rate": round(rate, 3),
        })

    avg_rate = sum(d["rate"] for d in details) / len(details) if details else 0

    report = {
        "sample_size": len(samples),
        "avg_accuracy": round(avg_rate, 3),
        "pass_threshold": 0.95,
        "passed": avg_rate >= 0.95,
        "details": details,
    }

    REPORT_PATH.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"\n{'='*50}")
    print(f"平均准确率：{avg_rate:.1%}")
    print(f"是否达标（≥95%）：{'是' if avg_rate >= 0.95 else '否'}")
    print(f"报告已保存：{REPORT_PATH}")


if __name__ == "__main__":
    run()