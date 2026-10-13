import json
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

URL = "https://api.anquanke.com/data/v1/rss"
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
    return resp.content


def parse(xml_bytes):
    root = ET.fromstring(xml_bytes)
    items = []
    for item in root.findall(".//item"):
        # 优先 link，其次 guid（安全客 RSS 没有 link 标签）
        link = item.findtext("link", default="").strip()
        guid = item.findtext("guid", default="").strip()
        url = link or guid

        items.append({
            "title": item.findtext("title", default=""),
            "url": url,
            "guid": guid,
            "published": item.findtext("pubDate", default=""),
            "description": (item.findtext("description", default="") or "")[:2000],
            "author": item.findtext("author", default="").strip(),
            "source": "安全客",
        })
    return items


if __name__ == "__main__":
    items = parse(fetch())
    Path("data").mkdir(exist_ok=True)
    out = Path("data/anquanke.json")
    out.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"采集 {len(items)} 条 -> {out}")
    for it in items[:5]:
        print(f"- {it['title'][:40]}")
        print(f"  {it['url']}")