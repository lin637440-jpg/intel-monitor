import json
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

API = "http://export.arxiv.org/api/query"
NS = {"a": "http://www.w3.org/2005/Atom"}


def fetch(query="all:AI security", max_results=25):
    import time
    params = {
        "search_query": query,
        "start": 0,
        "max_results": max_results,
        "sortBy": "submittedDate",
        "sortOrder": "descending",
    }
    headers = {"User-Agent": "intel-monitor/0.1 (contact: intel@example.com)"}

    for attempt in range(3):
        resp = requests.get(API, params=params, headers=headers, timeout=30)
        if resp.status_code == 200:
            return resp.text
        if resp.status_code == 429:
            wait = 5 * (attempt + 1)
            print(f"ArXiv 429 限流，{wait}s 后重试...")
            time.sleep(wait)
            continue
        resp.raise_for_status()
    resp.raise_for_status()


def parse(xml_text):
    root = ET.fromstring(xml_text)
    items = []
    for e in root.findall("a:entry", NS):
        items.append({
            "id": e.findtext("a:id", default="", namespaces=NS),
            "title": (e.findtext("a:title", default="", namespaces=NS) or "").strip(),
            "summary": (e.findtext("a:summary", default="", namespaces=NS) or "").strip()[:2000],
            "published": e.findtext("a:published", default="", namespaces=NS),
            "updated": e.findtext("a:updated", default="", namespaces=NS),
            "authors": [a.findtext("a:name", default="", namespaces=NS)
                        for a in e.findall("a:author", NS)],
            "source": "ArXiv",
        })
    return items


if __name__ == "__main__":
    xml_text = fetch(query="all:AI security", max_results=25)
    items = parse(xml_text)

    Path("data").mkdir(exist_ok=True)
    out = Path("data/arxiv.json")
    out.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"采集 {len(items)} 条 -> {out}")
    for it in items[:5]:
        print("-", it["title"])