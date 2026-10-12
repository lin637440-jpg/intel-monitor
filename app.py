import json
import math
import sqlite3
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

DB_PATH = Path("data/intel.db")
METRICS_PATH = Path("data/metrics.json")

st.set_page_config(page_title="情报监测与富化", layout="wide")
st.title("🛡️ 情报监测与富化仪表板")


@st.cache_data(ttl=30)
def load_items():
    if not DB_PATH.exists():
        return pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        "SELECT uid, source, title, published, created_at FROM items", conn
    )
    conn.close()
    return df


@st.cache_data(ttl=30)
def load_metrics():
    if not METRICS_PATH.exists():
        return {}
    return json.loads(METRICS_PATH.read_text(encoding="utf-8"))


df = load_items()
metrics = load_metrics()

if df.empty:
    st.error("data/intel.db 为空，先跑 python main.py")
    st.stop()

# ============ 顶部指标卡 ============
col1, col2, col3, col4 = st.columns(4)
col1.metric("情报总数", len(df))
col2.metric("数据源数", df["source"].nunique())
col3.metric("最新采集", str(df["created_at"].max())[:19])
col4.metric("覆盖天数", pd.to_datetime(df["created_at"]).dt.date.nunique())

st.divider()

# ============ 图表区 ============
left, right = st.columns(2)

with left:
    st.subheader("📊 各数据源情报数量")
    src_counts = df["source"].value_counts().reset_index()
    src_counts.columns = ["source", "count"]
    fig = px.pie(src_counts, names="source", values="count", hole=0.4)
    st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("⏱️ 采集延迟（小时）")
    st.caption("注：延迟 = 现在 - 漏洞发布时间。历史数据会拉高平均值。")
    sources = metrics.get("sources", {})
    if sources:
        mdf = pd.DataFrame([
            {"source": k, "avg": v["avg_delay_hours"]}
            for k, v in sources.items()
        ])
        mdf = mdf.sort_values("avg", ascending=True)
        fig = px.bar(
            mdf, x="avg", y="source", color="source",
            orientation="h", text="avg",
            labels={"avg": "平均延迟（小时）", "source": ""},
        )
        fig.update_traces(
            texttemplate="%{text:.0f}h",
            textposition="outside",
            cliponaxis=False,
        )
        fig.update_layout(
            showlegend=False,
            xaxis=dict(showticklabels=False),
            margin=dict(l=10, r=80, t=10, b=10),
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("先跑 python metrics.py")

st.divider()

# ============ 时间趋势 ============
st.subheader("📈 采集时间趋势")
df["date"] = pd.to_datetime(df["created_at"]).dt.date
trend_df = df.groupby(["date", "source"]).size().reset_index(name="count")
fig = px.line(trend_df, x="date", y="count", color="source", markers=True)
st.plotly_chart(fig, use_container_width=True)

st.divider()

# ============ CWE 主题分布 ============
st.subheader("🎯 CWE 漏洞类型分布")
CONF_PATH = Path("data/confidence.json")
if CONF_PATH.exists():
    conf = json.loads(CONF_PATH.read_text(encoding="utf-8"))
    c1, c2, c3 = st.columns(3)
    c1.metric("总 CVE", conf.get("total_cve", 0))
    c2.metric("多源命中", conf.get("multi_source_cve", 0))
    c3.metric("漏洞类型数", conf.get("total_cwe", 0))

    cwe_stats = conf.get("cwe_stats", [])
    if cwe_stats:
        cdf = pd.DataFrame([
            {"CWE": e["cwe"], "数量": e["count"],
             "平均 CVSS": e["avg_cvss"], "最高 CVSS": e["max_cvss"],
             "涉及源": ", ".join(e["sources"])}
            for e in cwe_stats[:20]
        ])
        st.dataframe(cdf, use_container_width=True)

        # 加个柱状图更直观
        top10 = cwe_stats[:10]
        fig = px.bar(
            pd.DataFrame(top10), x="cwe", y="count",
            labels={"cwe": "CWE 类型", "count": "数量"},
            color="avg_cvss", color_continuous_scale="Reds",
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("暂无 CWE 数据")
else:
    st.info("先跑 python -m enrichment.cross_validate")

st.divider()

# ============ 趋势分析 ============
st.subheader("📊 高危漏洞占比")
TREND_PATH = Path("data/trend.json")
if TREND_PATH.exists():
    trend = json.loads(TREND_PATH.read_text(encoding="utf-8"))
    c1, c2, c3 = st.columns(3)
    c1.metric("总情报", trend["total"])
    c2.metric("高危数（CVSS≥7）", trend["high_count"])
    c3.metric("高危占比", f"{trend['high_ratio'] * 100:.1f}%")

    if trend.get("series"):
        sdf = pd.DataFrame(trend["series"])
        fig = px.bar(
            sdf, x="date", y="count", color="source",
            labels={"count": "数量", "date": "日期"},
        )
        st.plotly_chart(fig, use_container_width=True)
else:
    st.info("先跑 python -m analytics.trend")

st.divider()

# ============ CVE 关联图 ============
st.subheader("🕸️ CVE 关联图（CWE / 资产）")
GRAPH_PATH = Path("data/graph.json")
if GRAPH_PATH.exists():
    g = json.loads(GRAPH_PATH.read_text(encoding="utf-8"))
    stats = g.get("stats", {})
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("节点总数", stats.get("total_nodes", 0))
    c2.metric("CVE 节点", stats.get("cve_nodes", 0))
    c3.metric("CWE 节点", stats.get("cwe_nodes", 0))
    c4.metric("资产节点", stats.get("asset_nodes", 0))

    nodes = g.get("nodes", [])
    edges = g.get("edges", [])

    # 筛选控件
    only_high = st.checkbox("只看高危（CVSS ≥ 7）", value=False)
    show_cve_labels = st.checkbox("显示 CVE 标签（图会变乱）", value=False)

    # 节点坐标 map
    pos = {n["id"]: (n.get("x", 0), n.get("y", 0)) for n in nodes}

    # 过滤
    if only_high:
        keep_ids = {
            n["id"] for n in nodes
            if n["type"] != "cve" or (n.get("cvss") or 0) >= 7
        }
    else:
        keep_ids = {n["id"] for n in nodes}

    filtered_edges = [
        e for e in edges
        if e["source"] in keep_ids and e["target"] in keep_ids
    ]

    edge_x, edge_y = [], []
    for e in filtered_edges:
        if e["source"] in pos and e["target"] in pos:
            x0, y0 = pos[e["source"]]
            x1, y1 = pos[e["target"]]
            edge_x += [x0, x1, None]
            edge_y += [y0, y1, None]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y, mode="lines",
        line=dict(width=0.3, color="#ccc"),
        hoverinfo="none", showlegend=False,
    ))

    for ntype, color, size in [
        ("cwe", "#EF553B", 14),
        ("asset", "#00CC96", 12),
        ("cve", "#636EFA", 5),
    ]:
        subset = [
            n for n in nodes
            if n["type"] == ntype and n["id"] in keep_ids and n["id"] in pos
        ]
        if not subset:
            continue

        if ntype == "cve" and not show_cve_labels:
            text = ["" for _ in subset]
        else:
            text = [n["label"][:20] for n in subset]

        fig.add_trace(go.Scatter(
            x=[pos[n["id"]][0] for n in subset],
            y=[pos[n["id"]][1] for n in subset],
            mode="markers+text" if any(text) else "markers",
            text=text,
            textposition="top center",
            textfont=dict(size=10),
            marker=dict(size=size, color=color),
            name=ntype,
            hovertext=[
                f"{n['label']}<br>CVSS: {n.get('cvss') or 'N/A'}"
                for n in subset
            ],
            hoverinfo="text",
        ))

    fig.update_layout(
        showlegend=True,
        height=700,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor="white",
    )
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("先跑 python -m analytics.graph")

st.divider()

# ============ 富化样本 ============
st.subheader("🔬 富化样本（最近 20 条）")
ENRICHED_PATH = Path("data/enriched_sample.json")
if ENRICHED_PATH.exists():
    enriched = json.loads(ENRICHED_PATH.read_text(encoding="utf-8"))
    for it in enriched[:20]:
        with st.expander(f"[{it.get('id', 'N/A')}] {it.get('title', '')[:80]}"):
            c1, c2, c3 = st.columns(3)
            c1.metric(
                "风险评分",
                f"{it.get('risk_score', 0)} ({it.get('risk_level', '')})"
            )
            c2.metric("POC 数", len(it.get("pocs", [])))
            c3.metric("论文数", len(it.get("related_papers", [])))

            assets = it.get("assets", {}).get("frameworks", [])
            if assets:
                st.write("**资产**：", ", ".join(assets))

            chains = it.get("attack_chain", {}).get("chains", [])
            if chains:
                st.write("**攻击链**：")
                for ch in chains:
                    st.write(f"  - {ch['name']}：{' → '.join(ch['steps'])}")
else:
    st.info("先跑 python -m enrichment.pipeline")

# ============ 攻击链文件 ============
st.divider()
st.subheader("🔗 攻击链可视化文件")
chain_dir = Path("data/chains")
if chain_dir.exists():
    files = list(chain_dir.glob("*.mmd"))
    st.write(f"共 {len(files)} 个 .mmd 文件")
    for f in files[:10]:
        with st.expander(f.name):
            st.code(f.read_text(encoding="utf-8"), language="mermaid")
else:
    st.info("暂无攻击链文件")