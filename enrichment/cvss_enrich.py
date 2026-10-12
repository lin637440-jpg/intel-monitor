import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cvss(cve_id):
    """按 CVE 号从 NVD 拉完整 CVSS"""
    headers = {"User-Agent": "intel-monitor/0.1"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {"cveId": cve_id}
    for attempt in range(2):
        try:
            r = requests.get(NVD_URL, params=params, headers=headers, timeout=20)
            if r.status_code == 200:
                data = r.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    return None
                metrics = vulns[0]["cve"].get("metrics", {})
                return _extract(metrics)
            if r.status_code in (403, 429):
                time.sleep(6 if not NVD_API_KEY else 1)
                continue
        except Exception:
            time.sleep(1)

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
    cve = "CVE-2021-44228"
    r = fetch_cvss(cve)
    print(f"{cve} CVSS:")
    print(r)