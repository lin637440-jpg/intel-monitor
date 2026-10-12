import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path("data/intel.db")


def init_sync_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sync_state (
            source TEXT PRIMARY KEY,
            last_sync_at TIMESTAMP,
            last_item_count INTEGER DEFAULT 0,
            last_inserted INTEGER DEFAULT 0,
            total_runs INTEGER DEFAULT 0,
            error_count INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


def get_last_sync(source):
    init_sync_table()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT last_sync_at FROM sync_state WHERE source = ?", (source,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


def update_sync(source, item_count, inserted):
    init_sync_table()
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO sync_state (source, last_sync_at, last_item_count, last_inserted, total_runs)
        VALUES (?, ?, ?, ?, 1)
        ON CONFLICT(source) DO UPDATE SET
            last_sync_at = excluded.last_sync_at,
            last_item_count = excluded.last_item_count,
            last_inserted = excluded.last_inserted,
            total_runs = total_runs + 1
    """, (source, now, item_count, inserted))
    conn.commit()
    conn.close()


def record_error(source):
    init_sync_table()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO sync_state (source, error_count)
        VALUES (?, 1)
        ON CONFLICT(source) DO UPDATE SET
            error_count = error_count + 1
    """, (source,))
    conn.commit()
    conn.close()


def get_all_states():
    init_sync_table()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM sync_state ORDER BY source")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


if __name__ == "__main__":
    init_sync_table()
    print("sync_state 表已创建")
    for s in get_all_states():
        print(f"  {s['source']}: last_sync={s['last_sync_at']}, runs={s['total_runs']}")