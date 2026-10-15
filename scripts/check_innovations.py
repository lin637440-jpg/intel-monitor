from pathlib import Path

print("=== 创新文件检查 ===")
files = [
    ("语义搜索", "app/monitor/semantic_search.py"),
    ("评分卡", "enrichment/risk_score.py"),
    ("攻击链可视化", "enrichment/chain_viz.py"),
    ("CVE关联图", "analytics/graph.py"),
    ("CWE分布", "enrichment/cross_validate.py"),
    ("健康监控", "analytics/source_health.py"),
    ("本地告警", "alerts/webhook.py"),
    ("字段规范化", "storage/normalize_fields.py"),
    ("增量采集", "storage/sync_state.py"),
    ("关联图谱", "storage/graph_db.py"),
    ("图谱构建", "analytics/graph_builder.py"),
    ("趋势分析", "analytics/trend_analysis.py"),
    ("聚类分析", "analytics/cluster.py"),
    ("攻击面", "analytics/attack_surface.py"),
    ("Agent工具", "enrichment/tools.py"),
    ("富化Agent", "enrichment/agent.py"),
    ("简报生成", "analytics/brief_generator.py"),
]
for name, path in files:
    p = Path(path)
    print(f"  {'OK  ' if p.exists() else '缺失'} {name}: {path}")

print()
print("=== 输出数据检查 ===")
outputs = [
    ("语义索引", "data/embeddings.npy"),
    ("CWE分布", "data/confidence.json"),
    ("趋势数据", "data/trend.json"),
    ("关联图", "data/graph.json"),
    ("健康报告", "data/source_health.json"),
    ("告警日志", "data/alerts.json"),
    ("延迟报告", "data/latency_report.json"),
    ("富化覆盖率", "data/enrichment_coverage.json"),
    ("准确率报告", "data/accuracy_report.json"),
    ("Chroma导出", "data/chroma_records.json"),
    ("交叉验证报告", "data/cross_validate_report.json"),
    ("趋势分析报告", "data/trend_analysis.json"),
    ("聚类报告", "data/clusters.json"),
    ("攻击面报告", "data/attack_surface.json"),
]
for name, path in outputs:
    p = Path(path)
    if p.exists():
        size = p.stat().st_size
        print(f"  OK   {name}: {size} 字节")
    else:
        print(f"  缺失 {name}: {path}")

print()
print("=== 攻击链文件 ===")
chain_dir = Path("data/chains")
if chain_dir.exists():
    mmd = list(chain_dir.glob("*.mmd"))
    print(f"  {len(mmd)} 个 .mmd 文件")
else:
    print("  无 chains 目录")