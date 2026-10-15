import json
from pathlib import Path

print("=" * 60)
print("创新点内容验证")
print("=" * 60)

# 1. 语义搜索
print("\n[1] 语义搜索")
try:
    from app.monitor.semantic_search import semantic_search
    r = semantic_search("prompt injection", top_k=3)
    print(f"  OK  返回 {len(r)} 条")
    for x in r[:3]:
        print(f"       [{x.get('_score')}] {x.get('title', '')[:50]}")
except Exception as e:
    print(f"  失败 {type(e).__name__}: {e}")

# 2. 评分卡
print("\n[2] 评分卡")
try:
    from enrichment.risk_score import compute_risk_score
    r = compute_risk_score({
        "id": "TEST", "cvss": {"baseScore": 9.8},
        "pocs": [{"url": "x"}], "assets": {"frameworks": ["PyTorch"]},
        "published": "2026-10-15T00:00:00Z",
    })
    print(f"  OK  score={r['risk_score']} level={r['risk_level']}")
except Exception as e:
    print(f"  失败 {type(e).__name__}: {e}")

# 3. CWE 分布
print("\n[3] CWE 主题分布")
try:
    d = json.loads(Path("data/confidence.json").read_text(encoding="utf-8"))
    print(f"  总 CVE: {d.get('total_cve')}")
    print(f"  总 CWE: {d.get('total_cwe')}")
    for e in d.get("cwe_stats", [])[:3]:
        print(f"    {e['cwe']}: {e['count']} 条")
except Exception as e:
    print(f"  失败 {e}")

# 4. 关联图
print("\n[4] CVE 关联图")
try:
    d = json.loads(Path("data/graph.json").read_text(encoding="utf-8"))
    s = d.get("stats", {})
    print(f"  节点：{s.get('total_nodes')}  边：{s.get('total_edges')}")
except Exception as e:
    print(f"  失败 {e}")

# 5. 健康监控
print("\n[5] 采集健康监控")
try:
    d = json.loads(Path("data/source_health.json").read_text(encoding="utf-8"))
    sources = d.get("sources", {})
    print(f"  {len(sources)} 个源")
    for k, v in list(sources.items())[:3]:
        print(f"    {k}: {v['status']} runs={v['total_runs']} errors={v['error_count']}")
except Exception as e:
    print(f"  失败 {e}")

# 6. 告警
print("\n[6] 本地告警")
try:
    d = json.loads(Path("data/alerts.json").read_text(encoding="utf-8"))
    print(f"  {len(d)} 条告警")
    for a in d[:3]:
        print(f"    {a.get('cve')} cvss={a.get('cvss')} reason={a.get('reason')}")
except Exception as e:
    print(f"  失败 {e}")

# 7. 延迟报告
print("\n[7] 延迟报告")
try:
    d = json.loads(Path("data/latency_report.json").read_text(encoding="utf-8"))
    print(f"  记录数：{d.get('records_count')}")
    print(f"  达标：{d.get('meets_requirement')}")
    for e in d.get("evidence", []):
        print(f"    {e['source']}: {e['min_delay_hours']}h")
except Exception as e:
    print(f"  失败 {e}")

# 8. 准确率
print("\n[8] 准确率报告")
try:
    d = json.loads(Path("data/accuracy_report.json").read_text(encoding="utf-8"))
    print(f"  抽样：{d.get('sample_size')} 条")
    print(f"  准确率：{d.get('avg_accuracy')*100:.1f}%")
    print(f"  达标：{d.get('passed')}")
except Exception as e:
    print(f"  失败 {e}")

# 9. 交叉验证
print("\n[9] 多源交叉验证")
try:
    d = json.loads(Path("data/cross_validate_report.json").read_text(encoding="utf-8"))
    print(f"  总 CVE：{len(d)}")
    multi = [k for k, v in d.items() if v.get("source_count", 0) > 1]
    print(f"  多源命中：{len(multi)} 个")
    conflict = [k for k, v in d.items() if v.get("conflicts")]
    print(f"  有冲突：{len(conflict)} 个")
except Exception as e:
    print(f"  失败 {e}")

# 10. 趋势分析
print("\n[10] 趋势分析")
try:
    d = json.loads(Path("data/trend_analysis.json").read_text(encoding="utf-8"))
    print(f"  近 7 天：{d.get('recent_total')} 条")
    print(f"  高危占比：{d.get('recent_high_ratio')}")
    print(f"  激增框架：{len(d.get('surges', []))}")
except Exception as e:
    print(f"  失败 {e}")

# 11. 聚类
print("\n[11] 热点聚类")
try:
    d = json.loads(Path("data/clusters.json").read_text(encoding="utf-8"))
    print(f"  聚类数：{d.get('n_clusters')}")
    print(f"  总量：{d.get('total')}")
    for c in d.get("clusters", [])[:3]:
        print(f"    簇 {c['cluster_id']}（{c['size']} 条）")
except Exception as e:
    print(f"  失败 {e}")

# 12. 攻击面
print("\n[12] 攻击面统计")
try:
    d = json.loads(Path("data/attack_surface.json").read_text(encoding="utf-8"))
    print(f"  框架数：{d.get('frameworks')}")
    for r in d.get("ranking", [])[:3]:
        print(f"    {r['framework']}: {r['count']} 条 avg={r['avg_cvss']}")
except Exception as e:
    print(f"  失败 {e}")

# 13. Agent
print("\n[13] 工具调用 Agent")
try:
    from enrichment.agent import enrich_with_agent
    sample = {
        "id": "CVE-2021-44228", "source": "NVD",
        "title": "Log4Shell", "description": "RCE in PyTorch pipeline",
    }
    _, trace = enrich_with_agent(sample)
    print(f"  OK  plan={trace['plan']}")
    print(f"      calls={trace['total_calls']} success={trace['success']}")
except Exception as e:
    print(f"  失败 {type(e).__name__}: {e}")

# 14. 简报
print("\n[14] 自动简报")
try:
    briefs = list(Path("data/briefs").glob("*.md")) if Path("data/briefs").exists() else []
    print(f"  简报数：{len(briefs)}")
    for b in briefs[:3]:
        print(f"    {b.name} ({b.stat().st_size} 字节)")
except Exception as e:
    print(f"  失败 {e}")

print()
print("=" * 60)
print("验证完成")
print("=" * 60)