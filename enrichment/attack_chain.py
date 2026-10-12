ATTACK_CHAINS = [
    {
        "name": "提示词注入",
        "keywords": ["prompt injection", "prompt", "注入", "jailbreak", "越狱",
                     "instruction override", "system prompt", "提示词"],
        "steps": ["构造恶意提示", "绕过对齐", "执行越权指令", "泄露敏感数据"],
    },
    {
        "name": "模型盗取",
        "keywords": ["model stealing", "model extraction", "模型盗取", "模型提取",
                     "distillation", "蒸馏", "api abuse", "query"],
        "steps": ["批量查询 API", "提取输出分布", "训练替代模型", "复制原模型"],
    },
    {
        "name": "数据投毒",
        "keywords": ["data poisoning", "poison", "投毒", "backdoor", "后门",
                     "trojan", "训练数据", "fine-tuning"],
        "steps": ["污染训练数据", "训练模型", "植入后门", "触发恶意行为"],
    },
    {
        "name": "供应链攻击",
        "keywords": ["supply chain", "供应链", "dependency", "依赖", "typosquatting",
                     "malicious package", "恶意包", "npm", "pypi", "huggingface"],
        "steps": ["发布恶意包", "被开发者安装", "窃取凭证", "横向移动"],
    },
    {
        "name": "越权访问",
        "keywords": ["privilege escalation", "越权", "authorization", "授权",
                     "rbac", "access control", "authentication bypass", "认证绕过"],
        "steps": ["伪造身份", "绕过鉴权", "提升权限", "访问敏感资源"],
    },
]


def infer_chain(text):
    """按关键词匹配攻击链模板"""
    if not text:
        return {"chains": [], "matched_count": 0}

    text_lower = text.lower()
    matched = []

    for chain in ATTACK_CHAINS:
        hits = [kw for kw in chain["keywords"] if kw.lower() in text_lower]
        if hits:
            matched.append({
                "name": chain["name"],
                "matched_keywords": hits,
                "steps": chain["steps"],
            })

    return {
        "chains": matched,
        "matched_count": len(matched),
    }


if __name__ == "__main__":
    samples = [
        "A prompt injection attack on LLM bypasses safety alignment.",
        "A malicious package on PyPI performs a supply chain attack.",
        "SQL injection in WordPress plugin leaks data.",
    ]
    for s in samples:
        r = infer_chain(s)
        print(f"输入: {s}")
        print(f"  匹配 {r['matched_count']} 条攻击链")
        for c in r["chains"]:
            print(f"    - {c['name']} (关键词: {c['matched_keywords']})")
            print(f"      步骤: {' -> '.join(c['steps'])}")
        print()