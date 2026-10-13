import json
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from enrichment.pipeline import enrich

DB_PATH = ROOT / "data" / "intel.db"
BATCH_LOG = 10


def enrich_all(limit=None, skip_enriched=True):
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT uid, source, title, raw_json FROM items")
    rows = [dict(r) for r in cur.fetchall()]

    if skip_enriched:
        to_process = []
        for r in rows:
            try:
                raw = json.loads(r.get("raw_json") or "{}")
            except Exception:
                raw = {}
            if not raw.get("risk_score"):
                to_process.append(r)
    else:
        to_process = rows

    if limit:
        to_process = to_process[:limit]

    print(f"总记录 {len(rows)}，待富化 {len(to_process)}")
    print("开始富化...\n")

    updated = 0
    failed = 0
    start = time.time()

    for i, r in enumerate(to_process, 1):
        try:
            raw = json.loads(r.get("raw_json") or "{}")
            raw["uid"] = r["uid"]
            raw["source"] = r["source"]
            raw["title"] = r["title"]

            enriched = enrich(raw)

            cur.execute(
                "UPDATE items SET raw_json = ? WHERE uid = ?",
                (json.dumps(enriched, ensure_ascii=False), r["uid"]),
            )
            updated += 1

            if i % BATCH_LOG == 0:
                conn.commit()
                elapsed = time.time() - start
                print(f"[{i}/{len(to_process)}] {r['uid']}  "
                      f"score={enriched.get('risk_score')}  "
                      f"耗时 {elapsed:.1f}s")

        except Exception as e:
            failed += 1
            print(f"[{i}] 失败 {r['uid']}: {type(e).__name__}: {e}")

    conn.commit()
    conn.close()

    elapsed = time.time() - start
    print(f"\n{'='*50}")
    print(f"完成：成功 {updated}，失败 {failed}，耗时 {elapsed:.1f}s")


if __name__ == "__main__":
    import sys as _sys
    limit = None
    if len(_sys.argv) > 1:
        limit = int(_sys.argv[1])
        print(f"限制只跑 {limit} 条\n")
    enrich_all(limit=limit)