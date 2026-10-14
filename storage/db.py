import json
import os
import sqlite3
from pathlib import Path

# 1. 环境变量优先
_env_path = os.getenv("INTEL_DB_PATH")
if _env_path:
    DB_PATH = Path(_env_path)
else:
    # 2. 从包安装位置查找（pip install -e 时即项目根目录）
    _pkg_root = Path(__file__).resolve().parent.parent
    _candidate = _pkg_root / "data" / "intel.db"
    if _candidate.exists():
        DB_PATH = _candidate
    else:
        # 3. 退回相对路径
        DB_PATH = Path("data/intel.db")


def init_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS items (
            uid TEXT PRIMARY KEY,
            source TEXT,
            title TEXT,
            description TEXT,
            url TEXT,
            published TEXT,
            raw_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn


def insert_items(items):
    conn = init_db()
    cur = conn.cursor()
    inserted = 0
    for it in items:
        try:
            cur.execute(
                "INSERT OR IGNORE INTO items "
                "(uid, source, title, description, url, published, raw_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    it.get("uid"),
                    it.get("source"),
                    it.get("title"),
                    it.get("description") or it.get("summary") or it.get("selftext"),
                    it.get("url") or it.get("html_url"),
                    it.get("published") or it.get("published_at"),
                    json.dumps(it, ensure_ascii=False),
                ),
            )
            if cur.rowcount:
                inserted += 1
        except Exception as e:
            print(f"插入失败 {it.get('uid')}: {e}")
    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]
    conn.close()
    return inserted, total