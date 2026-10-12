import json
from pathlib import Path


def chain_to_mermaid(chain):
    """把一条攻击链生成 Mermaid flowchart 文本"""
    lines = ["graph LR"]
    steps = chain.get("steps", [])
    for i, step in enumerate(steps):
        safe = step.replace('"', "'")
        lines.append(f'    S{i}["{safe}"]')
        if i > 0:
            lines.append(f"    S{i-1} --> S{i}")
    return "\n".join(lines)


def render_chain(item, out_dir="data/chains"):
    """把 item 的攻击链渲染成 .mmd 文件，返回文件路径列表"""
    chains = (item.get("attack_chain") or {}).get("chains", [])
    if not chains:
        return []

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    cve_id = (item.get("id") or "unknown").replace("/", "_")
    paths = []

    for idx, chain in enumerate(chains):
        name = chain["name"].replace(" ", "_")
        path = Path(out_dir) / f"{cve_id}_{idx}_{name}.mmd"
        path.write_text(chain_to_mermaid(chain), encoding="utf-8")
        paths.append(str(path))

    return paths


if __name__ == "__main__":
    sample = {
        "id": "CVE-2026-0001",
        "attack_chain": {
            "chains": [
                {
                    "name": "提示词注入",
                    "steps": ["构造恶意提示", "绕过对齐", "执行越权指令", "泄露敏感数据"],
                }
            ]
        },
    }
    paths = render_chain(sample)
    for p in paths:
        print(f"生成: {p}")
        print(Path(p).read_text(encoding="utf-8"))