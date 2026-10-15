"""
Agent 可调用的工具集
每个工具：输入 vuln dict，输出结构化结果
"""
import time

from enrichment.cvss_enrich import fetch_cvss
from enrichment.poc_search import search_poc
from enrichment.paper_link import link_papers
from enrichment.asset_extract import extract_assets
from enrichment.attack_chain import infer_chain


def tool_nvd_cvss(vuln):
    """补 CVSS"""
    cve = vuln.get("id") or vuln.get("cve_id")
    if not cve:
        return None
    return fetch_cvss(cve)


def tool_github_poc(vuln):
    """搜 POC"""
    cve = vuln.get("id") or vuln.get("cve_id")
    if not cve:
        return []
    return search_poc(cve)


def tool_arxiv_search(vuln):
    """搜论文"""
    desc = vuln.get("description") or vuln.get("title") or ""
    if not desc:
        return []
    return link_papers(desc, threshold=0.3)


def tool_asset_extract(vuln):
    """识别框架"""
    desc = vuln.get("description") or vuln.get("title") or ""
    return extract_assets(desc)


def tool_chain_infer(vuln):
    """攻击链推理"""
    desc = vuln.get("description") or vuln.get("title") or ""
    return infer_chain(desc)


TOOLS = {
    "nvd_cvss": {
        "fn": tool_nvd_cvss,
        "desc": "从 NVD 补全 CVSS 评分",
    },
    "github_poc": {
        "fn": tool_github_poc,
        "desc": "从 GitHub 搜索 POC 仓库",
    },
    "arxiv_search": {
        "fn": tool_arxiv_search,
        "desc": "从 ArXiv 搜索相关论文",
    },
    "asset_extract": {
        "fn": tool_asset_extract,
        "desc": "正则识别 AI 框架和版本",
    },
    "chain_infer": {
        "fn": tool_chain_infer,
        "desc": "按关键词匹配攻击链模板",
    },
}