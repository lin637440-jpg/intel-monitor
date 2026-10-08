import os
import json
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
URL = "https://api.github.com/advisories"


def fetch_advisories(per_page=20):
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "intel-monitor/0.1",
    }
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"

    resp = requests.get(URL, headers=headers, params={"per_page": per_page}, timeout=30)
    resp.raise_for_status()
    return resp.json()


def parse_advisory(item):
    return {
        "ghsa_id": item.get("ghsa_id"),
        "cve_id": item.get("cve_id"),
        "summary": item.get("summary"),
        "description": item.get("description"),
        "severity": item.get("severity"),
        "published_at": item.get("published_at"),
        "updated_at": item.get("updated_at"),
        "html_url": item.get("html_url"),
        "references": item.get("references", []),
        "vulnerabilities": item.get("vulnerabilities", []),
        "source": "GitHub Advisories",
    }


if __name__ == "__main__":
    data = fetch_advisories(per_page=20)
    items = [parse_advisory(x) for x in data]

    Path("data").mkdir(exist_ok=True)
    out = Path("data/github_advisories.json")
    out.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"采集 {len(items)} 条，保存到 {out}")
    for it in items[:3]:
        print(it["ghsa_id"], it["severity"], (it["summary"] or "")[:60])