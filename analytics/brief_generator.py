"""
自动情报简报：生成最新 N 条情报的 Markdown 简报
"""
import json
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path("data/intel.db")
BRIEF_DIR = Path("data/briefs")


def generate_brief(top_n=20):
    BRIEF_DIR.mkdir(parents=True, exist_ok=True)
    today_str = datetime.now().date().isoformat()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM items").fetchall()]
    conn.close()

    # 取最新 N 条（按 created_at 降序）
    rows_sorted = sorted(rows, key=lambda r: r.get("created_at") or "", reverse=True)
    top_items = []
    for r in rows_sorted[:top_n]:
        try:
            raw = json.loads(r.get("raw_json") or "{}")
            raw["_source"] = r["source"]
            raw["_created_at"] = r.get("created_at")
            top_items.append(raw)
        except Exception:
            pass

    # 统计
    high_risk = [it for it in top_items if (it.get("risk_score") or 0) >= 60]
    with_poc = [it for it in top_items if it.get("pocs")]

    # 热点攻击链
    chain_count = {}
    for it in top_items:
        for c in (it.get("attack_chain") or {}).get("chains", []):
            chain_count[c["name"]] = chain_count.get(c["name"], 0) + 1
    top_chains = sorted(chain_count.items(), key=lambda x: -x[1])[:3]

    # 重点
    focus = sorted(top_items, key=lambda x: -(x.get("risk_score") or 0))[:5]

    lines = [
        f"# AI 安全情报简报 — {today_str}",
        "",
        "## 概览",
        f"- 收录最新情报：**{len(top_items)}** 条",
        f"- 中高危（risk ≥ 60）：**{len(high_risk)}** 条",
        f"- 有公开 POC：**{len(with_poc)}** 条",
        "",
    ]

    if top_chains:
        lines.append("## 热点攻击链")
        for name, cnt in top_chains:
            lines.append(f"- **{name}**：{cnt} 条")
        lines.append("")

    if focus:
        lines.append("## 重点关注")
        for it in focus:
            cve = it.get("id") or it.get("uid")
            title = (it.get("title") or "")[:80]
            score = it.get("risk_score")
            level = it.get("risk_level")
            cvss = (it.get("cvss") or {}).get("baseScore") if isinstance(it.get("cvss"), dict) else None
            url = it.get("url") or it.get("html_url") or ""
            chains = [c["name"] for c in (it.get("attack_chain") or {}).get("chains", [])]

            lines.append(f"### {cve}")
            lines.append(f"- 标题：{title}")
            if cvss:
                lines.append(f"- CVSS：{cvss}")
            if score is not None and score >= 0:
                lines.append(f"- 综合评分：{score} ({level})")
            elif level == "UNKNOWN":
                lines.append(f"- 综合评分：无法评估")
            if chains:
                lines.append(f"- 关联攻击链：{', '.join(chains)}")
            if url:
                lines.append(f"- 链接：{url}")
            lines.append("")

    if with_poc:
        lines.append("## 有公开 POC 的漏洞")
        for it in with_poc[:5]:
            cve = it.get("id") or ""
            pocs = it.get("pocs") or []
            if pocs:
                lines.append(f"- **{cve}** → {pocs[0].get('url', '')}")
        lines.append("")

    lines.append("---")
    lines.append(f"*生成时间：{datetime.now().isoformat()}*")

    content = "\n".join(lines)
    out = BRIEF_DIR / f"{today_str}.md"
    out.write_text(content, encoding="utf-8")

    print(f"简报：{out}")
    print(f"收录 {len(top_items)} 条，中高危 {len(high_risk)} 条")
    print(f"文件大小：{out.stat().st_size} 字节")
    return str(out)


if __name__ == "__main__":
    generate_brief(top_n=20)