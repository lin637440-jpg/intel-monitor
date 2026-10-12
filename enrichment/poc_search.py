import json
import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
SEARCH_URL = "https://api.github.com/search/repositories"
CACHE_PATH = Path("data/poc_cache.json")

_cache = None


def _load_cache():
    global _cache
    if _cache is None:
        if CACHE_PATH.exists():
            try:
                _cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
            except Exception:
                _cache = {}
        else:
            _cache = {}
    return _cache


def _save_cache():
    if _cache is None:
        return
    CACHE_PATH.parent.mkdir(exist_ok=True)
    CACHE_PATH.write_text(
        json.dumps(_cache, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def search_poc(cve_id, max_results=3, use_cache=True):
    """在 GitHub 搜 CVE-xxxx poc 仓库，带缓存"""
    if not cve_id:
        return []

    cache = _load_cache()
    if use_cache and cve_id in cache:
        return cache[cve_id]

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "intel-monitor/0.1",
    }
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"

    params = {
        "q": f"{cve_id} poc",
        "sort": "stars",
        "order": "desc",
        "per_page": max_results,
    }

    try:
        r = requests.get(SEARCH_URL, headers=headers, params=params, timeout=8)
        if r.status_code == 200:
            data = r.json()
            items = []
            for repo in data.get("items", []):
                items.append({
                    "name": repo.get("full_name"),
                    "url": repo.get("html_url"),
                    "stars": repo.get("stargazers_count"),
                    "description": (repo.get("description") or "")[:200],
                })
            cache[cve_id] = items
            _save_cache()
            return items
        if r.status_code == 403:
            time.sleep(1)
    except Exception:
        pass

    return []


if __name__ == "__main__":
    for cve in ["CVE-2021-44228", "CVE-2026-13144"]:
        repos = search_poc(cve)
        print(f"{cve}: {len(repos)} 个 POC")
        for r in repos:
            print(f"  [{r['stars']}⭐] {r['name']}")