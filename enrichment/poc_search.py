import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
SEARCH_URL = "https://api.github.com/search/repositories"


def search_poc(cve_id, max_results=3):
    """在 GitHub 搜 CVE-xxxx poc 仓库"""
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
        r = requests.get(SEARCH_URL, headers=headers, params=params, timeout=20)
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
            return items
        if r.status_code == 403:
            time.sleep(2)
    except Exception:
        pass

    return []


if __name__ == "__main__":
    cve = "CVE-2021-44228"
    repos = search_poc(cve)
    print(f"{cve} POC 仓库 {len(repos)} 个:")
    for r in repos:
        print(f"  [{r['stars']}⭐] {r['name']} - {r['url']}")