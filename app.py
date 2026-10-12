import json
import sqlite3
from pathlib import Path

import pandas as pd
import plotly.express as px
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
trend = df.groupby(["date", "source"]).size().reset_index(name="count")
fig = px.line(trend, x="date", y="count", color="source", markers=True)
st.plotly_chart(fig, use_container_width=True)

st.divider()

# ============ 富化结果 ============
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