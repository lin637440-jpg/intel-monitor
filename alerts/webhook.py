import json
import sys
from datetime import datetime, timezone
from pathlib import Path

LOG_PATH = Path("data/alerts.json")

CVSS_THRESHOLD = 9.0
RISK_SCORE_THRESHOLD = 80


def _load_log():
    if LOG_PATH.exists():
        try:
            return json.loads(LOG_PATH.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def _save_log(records):
    LOG_PATH.parent.mkdir(exist_ok=True)
    LOG_PATH.write_text(
        json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _print_alert(record):
    """终端彩色输出"""
    try:
        # Windows 10+ 支持 ANSI
        RED = "\033[91m"
        YELLOW = "\033[93m"
        BOLD = "\033[1m"
        RESET = "\033[0m"
    except Exception:
        RED = YELLOW = BOLD = RESET = ""

    print(f"\n{RED}{BOLD}🚨 高危漏洞告警{RESET}")
    print(f"  {BOLD}CVE{RESET}   : {record['cve']}")
    print(f"  {BOLD}标题{RESET}  : {record['title'][:80]}")
    if record.get("cvss") is not None:
        print(f"  {BOLD}CVSS{RESET}  : {RED}{record['cvss']}{RESET}")
    if record.get("risk_score") is not None:
        print(f"  {BOLD}评分{RESET}  : {YELLOW}{record['risk_score']} "
              f"({record.get('risk_level', '')}){RESET}")
    if record.get("url"):
        print(f"  {BOLD}链接{RESET}  : {record['url']}")
    print(f"  {BOLD}原因{RESET}  : {record['reason']}")


def check_and_alert(items, print_console=True):
    """
    检查传入的情报，满足条件的记录到 alerts.json，
    并在终端高亮输出。
    """
    log = _load_log()
    existing_keys = {a.get("cve") for a in log}
    fired = []

    for it in items:
        cvss = None
        cvss_obj = it.get("cvss")
        if isinstance(cvss_obj, dict):
            cvss = cvss_obj.get("baseScore")
        risk_score = it.get("risk_score")

        hit_cvss = cvss is not None and cvss >= CVSS_THRESHOLD
        hit_risk = risk_score is not None and risk_score >= RISK_SCORE_THRESHOLD

        if not (hit_cvss or hit_risk):
            continue

        cve = it.get("id") or it.get("cve_id") or it.get("uid")
        if cve in existing_keys:
            continue  # 已告警过，跳过

        record = {
            "fired_at": datetime.now(timezone.utc).isoformat(),
            "cve": cve,
            "title": it.get("title"),
            "cvss": cvss,
            "risk_score": risk_score,
            "risk_level": it.get("risk_level"),
            "url": it.get("url") or it.get("html_url"),
            "reason": "cvss>=9" if hit_cvss else "risk>=80",
        }
        log.append(record)
        fired.append(record)

        if print_console:
            _print_alert(record)

    if fired:
        _save_log(log)

    return fired


def alert_from_db(limit=200, print_console=True):
    """从最近入库的记录里找高危告警"""
    import sqlite3

    db = Path("data/intel.db")
    if not db.exists():
        print("intel.db 不存在")
        return []

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM items ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    items = []
    for r in rows:
        try:
            raw = json.loads(r.get("raw_json") or "{}")
            raw.update({k: v for k, v in r.items() if k != "raw_json"})
            items.append(raw)
        except Exception:
            items.append(r)

    return check_and_alert(items, print_console=print_console)


if __name__ == "__main__":
    fired = alert_from_db(limit=500)
    print(f"\n本次新增告警：{len(fired)} 条")
    print(f"告警日志：data/alerts.json")