import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path("data/intel.db")

# 支持的日期格式
DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%a, %d %b %Y %H:%M:%S %z",
    "%a, %d %b %Y %H:%M:%S %Z",
    "%a, %d %b %Y %H:%M:%S",
]


def normalize_date(s):
    """统一成 ISO 8601 UTC"""
    if not s:
        return None
    s = str(s).strip()
    if not s:
        return None
    for fmt in DATE_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            continue
    return None


def normalize_severity(s):
    if not s:
        return None
    s = str(s).upper().strip()
    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "MODERATE": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": None,
    }
    return mapping.get(s, s)


def normalize_url(u):
    if not u:
        return None
    u = str(u).strip()
    if u.startswith("http://") or u.startswith("https://"):
        return u
    return None


def run():
    if not DB_PATH.exists():
        print("intel.db 不存在")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT uid, source, title, url, published, raw_json FROM items")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    fixed = 0
    total = len(rows)
    issues = []

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    for r in rows:
        changes = {}

        # 1. published 规范化
        new_pub = normalize_date(r.get("published"))
        if new_pub and new_pub != r.get("published"):
            changes["published"] = new_pub

        # 2. url 规范化
        new_url = normalize_url(r.get("url"))
        if new_url != r.get("url"):
            changes["url"] = new_url

        # 3. raw_json 里的 severity 规范化
        try:
            raw = json.loads(r.get("raw_json") or "{}")
            raw_sev = raw.get("severity")
            if raw_sev:
                new_sev = normalize_severity(raw_sev)
                if new_sev != raw_sev:
                    raw["severity"] = new_sev
                    changes["raw_json"] = json.dumps(raw, ensure_ascii=False)
        except Exception:
            pass

        if not new_pub:
            issues.append({"uid": r["uid"], "issue": "无法解析 published"})

        if changes:
            sets = ", ".join(f"{k} = ?" for k in changes)
            vals = list(changes.values()) + [r["uid"]]
            cur.execute(f"UPDATE items SET {sets} WHERE uid = ?", vals)
            fixed += 1

    conn.commit()
    conn.close()

    print(f"总记录：{total}")
    print(f"修复：{fixed} 条")
    print(f"问题记录：{len(issues)} 条（无法解析日期）")

    # 写出报告
    report = {
        "total": total,
        "fixed": fixed,
        "issues": issues[:50],
    }
    Path("data/normalize_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"报告已写入 data/normalize_report.json")


if __name__ == "__main__":
    run()