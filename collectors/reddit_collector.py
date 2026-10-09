import json
from pathlib import Path

import requests

URL = "https://www.reddit.com/r/netsec/new.json"

HEADERS = {
    "User-Agent": "intel-monitor/0.1 (by u/intel_monitor)"
}


def fetch(limit=25):
    resp = requests.get(URL, headers=HEADERS, params={"limit": limit}, timeout=30)
    resp.raise_for_status()
    return resp.json()


def parse(item):
    d = item.get("data", {})
    return {
        "id": d.get("id"),
        "title": d.get("title"),
        "url": "https://www.reddit.com" + d.get("permalink", ""),
        "external_url": d.get("url"),
        "author": d.get("author"),
        "created_utc": d.get("created_utc"),
        "score": d.get("score"),
        "num_comments": d.get("num_comments"),
        "selftext": (d.get("selftext") or "")[:2000],
        "source": "Reddit r/netsec",
    }


if __name__ == "__main__":
    data = fetch(limit=25)
    children = data.get("data", {}).get("children", [])
    items = [parse(c) for c in children]

    Path("data").mkdir(exist_ok=True)
    out = Path("data/reddit_netsec.json")
    out.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"采集 {len(items)} 条 -> {out}")
    for it in items[:5]:
        print("-", it["title"])