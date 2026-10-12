import json
from pathlib import Path

import requests
from bs4 import BeautifulSoup

URL = "https://packetstormsecurity.com/feeds/"
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0 Safari/537.36"
    )
}


def fetch():
    resp = requests.get(URL, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    return resp.text


def parse(html):
    soup = BeautifulSoup(html, "lxml-xml")
    items = []
    for item in soup.find_all("item"):
        title = item.find("title")
        link = item.find("link")
        pub = item.find("pubDate")
        desc = item.find("description")
        items.append({
            "title": title.get_text(strip=True) if title else "",
            "url": link.get_text(strip=True) if link else "",
            "published": pub.get_text(strip=True) if pub else "",
            "description": (desc.get_text(strip=True) if desc else "")[:2000],
            "source": "PacketStorm",
        })
    return items


if __name__ == "__main__":
    html = fetch()
    items = parse(html)
    Path("data").mkdir(exist_ok=True)
    out = Path("data/packetstorm.json")
    out.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"采集 {len(items)} 条 -> {out}")
    for it in items[:5]:
        print("-", it["title"])