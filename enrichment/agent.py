"""
工具调用型富化 Agent
规划（规则 or LLM）→ 调工具 → 汇总
"""
import json
import time
from datetime import datetime, timezone

from enrichment.tools import TOOLS


def rule_plan(vuln):
    """规则规划：根据漏洞描述决定调哪些工具"""
    plan = []
    desc = (vuln.get("description") or vuln.get("title") or "").lower()
    cve = vuln.get("id") or vuln.get("cve_id") or ""

    # 有 CVE 编号 → 查 CVSS
    if cve and cve.startswith("CVE-"):
        plan.append("nvd_cvss")

    # 有 CVE → 搜 POC
    if cve and cve.startswith("CVE-"):
        plan.append("github_poc")

    # AI 相关关键词 → 搜论文
    ai_keywords = ["ai", "llm", "model", "prompt", "agent", "transformer",
                   "pytorch", "tensorflow", "大模型", "智能", "神经"]
    if any(kw in desc for kw in ai_keywords):
        plan.append("arxiv_search")

    # 总是做资产识别和攻击链
    plan.append("asset_extract")
    plan.append("chain_infer")

    return plan


def llm_plan(vuln, tool_names):
    """LLM 规划（需要 DeepSeek API Key 时用）"""
    # 简化版：不接 LLM，直接用规则
    return rule_plan(vuln)


def enrich_with_agent(vuln, use_llm=False):
    """
    Agent 主循环
    返回 (enriched_vuln, trace)
    """
    trace = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "plan": [],
        "calls": [],
        "errors": [],
    }

    # 规划
    if use_llm:
        plan = llm_plan(vuln, list(TOOLS.keys()))
    else:
        plan = rule_plan(vuln)

    trace["plan"] = plan

    result = dict(vuln)

    for tool_name in plan:
        if tool_name not in TOOLS:
            continue

        tool = TOOLS[tool_name]
        start = time.time()
        call_info = {
            "tool": tool_name,
            "desc": tool["desc"],
            "status": "pending",
        }

        try:
            output = tool["fn"](vuln)
            call_info["status"] = "ok"
            call_info["elapsed_ms"] = int((time.time() - start) * 1000)
            call_info["output_size"] = _size(output)

            # 写回结果
            if tool_name == "nvd_cvss" and output:
                result["cvss_full"] = output
            elif tool_name == "github_poc":
                result["pocs"] = output
            elif tool_name == "arxiv_search":
                result["related_papers"] = output
            elif tool_name == "asset_extract":
                result["assets"] = output
            elif tool_name == "chain_infer":
                result["attack_chain"] = output

        except Exception as e:
            call_info["status"] = "error"
            call_info["error"] = f"{type(e).__name__}: {e}"
            trace["errors"].append(call_info)

        trace["calls"].append(call_info)

    trace["finished_at"] = datetime.now(timezone.utc).isoformat()
    trace["total_calls"] = len(trace["calls"])
    trace["success"] = sum(1 for c in trace["calls"] if c["status"] == "ok")

    result["enrichment_trace"] = trace
    return result, trace


def _size(output):
    """估算输出大小"""
    if output is None:
        return 0
    if isinstance(output, (list, dict)):
        return len(output)
    return 1


if __name__ == "__main__":
    sample = {
        "id": "CVE-2021-44228",
        "source": "NVD",
        "title": "Log4Shell in Apache Log4j",
        "description": "A prompt injection-like RCE via JNDI in LLM pipelines using PyTorch.",
    }
    enriched, trace = enrich_with_agent(sample)
    print(json.dumps(trace, ensure_ascii=False, indent=2))