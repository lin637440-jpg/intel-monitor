"""
自动情报简报：每日生成 Markdown
"""
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = Path("data/intel.db")
BRIEF_DIR = Path("data/briefs")


def generate_brief(date=None):
    if date is None:
        date = datetime.now().date()

    BRIEF_DIR.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = [dict(r) for r in conn.execute("SELECT * FROM items").fetchall()]
    conn.close()

    # 今日新增（按 created_at）
    today_str = date.isoformat()
    today_items = []
    for r in rows:
        ca = r.get("created_at") or ""
        if ca.startswith(today_str):
            try:
                raw = json.loads(r.get("raw_json") or "{}")
                raw["_source"] = r["source"]
                today_items.append(raw)
            except Exception:
                pass

    # 统计
    high_risk = [it for it in today_items
                 if (it.get("risk_score") or 0) >= 80]
    with_poc = [it for it in today_items if it.get("pocs")]

    # 热点：攻击链
    chain_count = {}
    for it in today_items:
        for c in (it.get("attack_chain") or {}).get("chains", []):
            chain_count[c["name"]] = chain_count.get(c["name"], 0) + 1

    top_chains = sorted(chain_count.items(), key=lambda x: -x[1])[:3]

    # 重点关注：按 risk_score 排序前 5
    focus = sorted(today_items,
                   key=lambda x: -(x.get("risk_score") or 0))[:5]

    # 生成 Markdown
    lines = [
        f"# AI 安全情报日报 — {today_str}",
        "",
        f"## 概览",
        f"- 今日新增：**{len(today_items)}** 条",
        f"- 高危（risk ≥ 80）：**{len(high_risk)}** 条",
        f"- 有 POC：**{len(with_poc)}** 条",
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
            if score:
                lines.append(f"- 综合评分：{score} ({level})")
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
    print(f"今日新增 {len(today_items)} 条，高危 {len(high_risk)} 条")
    return str(out)


if __name__ == "__main__":
    generate_brief()