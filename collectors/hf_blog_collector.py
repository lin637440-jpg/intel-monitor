import json
from pathlib import Path

import requests

BASE = "https://huggingface.co"
API_LIST = "https://huggingface.co/api/blog"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0 Safari/537.36"
    )
}


def fetch_list(limit=50):
    resp = requests.get(API_LIST, headers=HEADERS, params={"limit": limit}, timeout=30)
    resp.raise_for_status()
    return resp.json()


def parse_item(raw):
    slug = raw.get("slug")
    authors = raw.get("authorsData") or []
    author_names = [a.get("name") for a in authors if isinstance(a, dict) and a.get("name")]

    return {
        "slug": slug,
        "title": raw.get("title"),
        "authors": author_names,
        "published": raw.get("publishedAt"),
        "url": f"{BASE}/blog/{slug}" if slug else None,
        "upvotes": raw.get("upvotes"),
        "thumbnail": raw.get("thumbnail"),
        "source": "Hugging Face Blog",
    }


if __name__ == "__main__":
    data = fetch_list(limit=50)
    blogs = data.get("allBlogs", [])
    print(f"API 返回 {len(blogs)} 条博客")

    items = [parse_item(b) for b in blogs if b.get("slug")]

    Path("data").mkdir(exist_ok=True)
    out = Path("data/hf_blog.json")
    out.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"保存 {len(items)} 条 -> {out}")
    for it in items[:10]:
        print("-", it["published"], "|", it["title"])