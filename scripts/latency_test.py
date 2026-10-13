import json
import sys
import time
from datetime import datetime
from pathlib import Path

# 把项目根目录加入 sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REPORT_PATH = ROOT / "data" / "latency_test.json"
INTERVAL = 3600
DURATION = 6 * 3600


def record_once():
    from metrics import compute_metrics
    compute_metrics(days=1)
    p = ROOT / "data" / "metrics.json"
    if not p.exists():
        return None
    data = json.loads(p.read_text(encoding="utf-8"))
    return {
        "timestamp": datetime.now().isoformat(),
        "sources": data.get("sources", {}),
    }


def run():
    records = []
    start = time.time()
    while time.time() - start < DURATION:
        r = record_once()
        if r:
            records.append(r)
            print(f"[{r['timestamp'][:19]}] 已记录")
        REPORT_PATH.write_text(
            json.dumps({
                "started_at": datetime.fromtimestamp(start).isoformat(),
                "records": records,
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        time.sleep(INTERVAL)
    print(f"\n6 小时测试完成，共记录 {len(records)} 次")


if __name__ == "__main__":
    run()