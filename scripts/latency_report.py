import json
from pathlib import Path

DATA = Path("data/latency_test.json")
REPORT = Path("data/latency_report.json")


def run():
    if not DATA.exists():
        print(f"找不到 {DATA}，先跑延迟测试")
        return

    d = json.loads(DATA.read_text(encoding="utf-8"))
    latest = d["records"][-1]["sources"] if d["records"] else {}

    report = {
        "test_duration_hours": 6,
        "records_count": len(d["records"]),
        "requirement": "min_delay <= 6h",
        "meets_requirement": False,
        "evidence": [],
        "sources": latest,
    }

    for src, v in latest.items():
        if v["min_delay_hours"] <= 6:
            report["meets_requirement"] = True
            report["evidence"].append({
                "source": src,
                "min_delay_hours": v["min_delay_hours"],
            })

    REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"6 小时延迟测试")
    print(f"记录数：{len(d['records'])}")
    print(f"数据源数：{len(latest)}")
    print(f"\n各源延迟：")
    for src, v in latest.items():
        print(f"  {src}: min={v['min_delay_hours']}h "
              f"avg={v['avg_delay_hours']}h max={v['max_delay_hours']}h")

    print(f"\n符合 ≤6h 的源：")
    for e in report["evidence"]:
        print(f"  ✅ {e['source']}: {e['min_delay_hours']}h")

    if not report["meets_requirement"]:
        print("  （没有源的最小延迟 ≤6h）")

    print(f"\n报告：{REPORT}")


if __name__ == "__main__":
    run()