import os
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cves(days=30, results_per_page=50):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": results_per_page,
        "startIndex": 0,
    }

    headers = {"User-Agent": "intel-monitor/0.1"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    last_err = None
    for attempt in range(2):
        try:
            resp = requests.get(NVD_URL, params=params, headers=headers, timeout=20)

            if resp.status_code == 200:
                return resp.json()

            if resp.status_code in (403, 429):
                wait = 6 if not NVD_API_KEY else 1
                print(f"NVD 限流/拒绝，{wait}s 后重试，status={resp.status_code}")
                time.sleep(wait)
                continue

            resp.raise_for_status()
        except Exception as e:
            last_err = e
            print(f"NVD 请求异常（第 {attempt + 1} 次）：{type(e).__name__}: {e}")
            time.sleep(1)

    if last_err:
        raise last_err
    raise RuntimeError("NVD 请求失败")


def _pick_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            return {
                "version": data.get("version"),
                "baseScore": data.get("baseScore"),
                "baseSeverity": data.get("baseSeverity") or arr[0].get("baseSeverity"),
                "vectorString": data.get("vectorString"),
            }
    return None


def _pick_cwe(weaknesses):
    out = []
    for w in weaknesses or []:
        for d in w.get("description", []):
            if d.get("lang") == "en" and d.get("value"):
                out.append(d["value"])
    return list(dict.fromkeys(out))


def _pick_affected(affected):
    vendors, products, versions = set(), set(), []
    for a in affected or []:
        for ad in a.get("affectedData", []):
            if ad.get("vendor"):
                vendors.add(ad["vendor"])
            if ad.get("product"):
                products.add(ad["product"])
            for v in ad.get("versions", []):
                ver = v.get("version")
                if ver:
                    versions.append(ver)
    return {
        "vendors": sorted(vendors),
        "products": sorted(products),
        "versions": versions[:30],
    }


def parse_cve(item):
    cve = item["cve"]

    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    return {
        "id": cve.get("id"),
        "title": desc[:120],
        "description": desc,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "cvss": _pick_cvss(cve.get("metrics", {})),
        "cwe": _pick_cwe(cve.get("weaknesses")),
        "affected": _pick_affected(cve.get("affected")),
        "references": [r.get("url") for r in cve.get("references", [])],
        "source": "NVD",
    }


def load_cached():
    """API 挂了就读本地缓存"""
    p = Path("data/cve_latest.json")
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return []


if __name__ == "__main__":
    try:
        raw = fetch_cves(days=30, results_per_page=50)
        items = [parse_cve(v) for v in raw.get("vulnerabilities", [])]

        Path("data").mkdir(exist_ok=True)
        out = Path("data/cve_latest.json")
        out.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")

        print(f"采集 {len(items)} 条，保存到 {out}")
    except Exception as e:
        print(f"NVD API 失败，使用本地缓存：{type(e).__name__}: {e}")
        items = load_cached()
        print(f"缓存条数：{len(items)}")

    for it in items[:3]:
        print(f"[{it['id']}] {it['title']}")
        print(f"  published={it['published']}")
        print(f"  cvss={it['cvss']}")
        print(f"  cwe={it['cwe']}")
        print(f"  products={it['affected']['products'][:3]}")