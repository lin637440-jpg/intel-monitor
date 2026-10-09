import json
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

URL = "https://www.freebuf.com/feed"
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
        title = item.findtext("title", default="")
        link = item.findtext("link", default="")
        pub_date = item.findtext("pubDate", default="")
        description = item.findtext("description", default="")
        creator = item.findtext(
            "{http://purl.org/dc/elements/1.1/}creator", default=""
        )
        items.append({
            "title": title,
            "url": link,
            "published": pub_date,
            "author": creator,
            "description": description[:2000],
            "source": "FreeBuf",
        })
    return items


if __name__ == "__main__":
    xml_bytes = fetch()
    items = parse(xml_bytes)

    Path("data").mkdir(exist_ok=True)
    out = Path("data/freebuf.json")
    out.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"采集 {len(items)} 条 -> {out}")
    for it in items[:5]:
        print("-", it["title"])