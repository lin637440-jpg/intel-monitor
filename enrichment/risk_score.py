def compute_risk_score(item):
    """
    情报评分卡，0-100 分。
    公式：0.4 * cvss_norm + 0.2 * has_poc + 0.2 * asset_match + 0.2 * freshness
    """
    score = 0.0
    detail = {}

    # 1. CVSS 归一化（0-10 -> 0-1）
    cvss = item.get("cvss") or {}
    base = cvss.get("baseScore") if isinstance(cvss, dict) else None
    if base is None:
        full = item.get("cvss_full") or {}
        v31 = full.get("v31") or {}
        base = v31.get("baseScore")
    cvss_norm = min(max((base or 0) / 10.0, 0), 1)
    score += 0.4 * cvss_norm
    detail["cvss_norm"] = round(cvss_norm, 3)

    # 2. 是否有 POC
    pocs = item.get("pocs") or []
    has_poc = 1.0 if pocs else 0.0
    score += 0.2 * has_poc
    detail["has_poc"] = has_poc

    # 3. 是否匹配 AI 资产
    assets = item.get("assets") or {}
    frameworks = assets.get("frameworks") or []
    asset_match = 1.0 if frameworks else 0.0
    score += 0.2 * asset_match
    detail["asset_match"] = asset_match
    detail["frameworks"] = frameworks

    # 4. 新鲜度（越新分越高）
    freshness = _freshness(item.get("published"))
    score += 0.2 * freshness
    detail["freshness"] = round(freshness, 3)

    total = round(score * 100, 1)

    if total >= 80:
        level = "CRITICAL"
    elif total >= 60:
        level = "HIGH"
    elif total >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_score": total,
        "risk_level": level,
        "risk_detail": detail,
    }


def _freshness(published):
    """0-1，越新越接近 1，7 天以上为 0"""
    from datetime import datetime, timezone

    if not published:
        return 0.0

    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S",
        "%a, %d %b %Y %H:%M:%S %z",
    ]
    dt = None
    for fmt in formats:
        try:
            dt = datetime.strptime(published, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            break
        except Exception:
            continue

    if dt is None:
        return 0.0

    days = (datetime.now(timezone.utc) - dt).days
    if days <= 0:
        return 1.0
    if days >= 7:
        return 0.0
    return 1 - days / 7.0


if __name__ == "__main__":
    sample = {
        "id": "CVE-2026-0001",
        "published": "2026-10-11T00:00:00Z",
        "cvss": {"baseScore": 9.8},
        "pocs": [{"name": "x/y"}],
        "assets": {"frameworks": ["PyTorch"]},
    }
    r = compute_risk_score(sample)
    print(r)