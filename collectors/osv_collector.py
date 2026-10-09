import json
from pathlib import Path

import requests

API = "https://api.osv.dev/v1/query"
HEADERS = {"Content-Type": "application/json"}


def fetch(package="requests", ecosystem="PyPI"):
    payload = {"package": {"name": package, "ecosystem": ecosystem}}
    resp = requests.post(API, json=payload, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    return resp.json()


def parse(raw):
    items = []
    for v in raw.get("vulns", []):
        items.append({
            "id": v.get("id"),
            "aliases": v.get("aliases", []),
            "summary": v.get("summary"),
            "details": (v.get("details") or "")[:2000],
            "published": v.get("published"),
            "modified": v.get("modified"),
            "severity": v.get("severity"),
            "affected": v.get("affected"),
            "references": v.get("references"),
            "source": "OSV.dev",
        })
    return items


if __name__ == "__main__":
    raw = fetch("requests", "PyPI")
    items = parse(raw)

    Path("data").mkdir(exist_ok=True)
    out = Path("data/osv.json")
    out.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"采集 {len(items)} 条 -> {out}")
    for it in items[:5]:
        print("-", it["id"], "|", it["summary"])