import json
import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = Path("data/cvss_cache.json")

_cache = None


def _load_cache():
    global _cache
    if _cache is None:
        if CACHE_PATH.exists():
            try:
                _cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
            except Exception:
                _cache = {}
        else:
            _cache = {}
    return _cache


def _save_cache():
    if _cache is None:
        return
    CACHE_PATH.parent.mkdir(exist_ok=True)
    CACHE_PATH.write_text(
        json.dumps(_cache, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def fetch_cvss(cve_id, use_cache=True):
    """按 CVE 号从 NVD 拉完整 CVSS，带本地缓存"""
    if not cve_id:
        return None

    cache = _load_cache()
    if use_cache and cve_id in cache:
        return cache[cve_id]

    headers = {"User-Agent": "intel-monitor/0.1"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {"cveId": cve_id}

    try:
        r = requests.get(NVD_URL, params=params, headers=headers, timeout=8)
        if r.status_code == 200:
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                cache[cve_id] = None
                _save_cache()
                return None
            metrics = vulns[0]["cve"].get("metrics", {})
            result = _extract(metrics)
            cache[cve_id] = result
            _save_cache()
            return result
        if r.status_code in (403, 429):
            time.sleep(1)
    except Exception:
        pass

    return None


def _extract(metrics):
    out = {}
    for key, label in [
        ("cvssMetricV31", "v31"),
        ("cvssMetricV30", "v30"),
        ("cvssMetricV2", "v2"),
    ]:
        arr = metrics.get(key)
        if arr:
            d = arr[0].get("cvssData", {})
            out[label] = {
                "baseScore": d.get("baseScore"),
                "baseSeverity": d.get("baseSeverity") or arr[0].get("baseSeverity"),
                "vectorString": d.get("vectorString"),
            }
    return out or None


if __name__ == "__main__":
    for cve in ["CVE-2021-44228", "CVE-2026-13144"]:
        print(f"{cve}: {fetch_cvss(cve)}")