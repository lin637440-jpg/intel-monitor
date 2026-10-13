# 情报监测与富化模块

AI 安全情报监测与富化系统，为 RAG 问答模块提供标准化情报数据。

## 功能特性

- **9 个数据源**：NVD、GitHub Advisories、Hugging Face、安全客、ArXiv、OSV.dev、Seebug Paper、Exploit-DB、Hacker News
- **5 维富化**：论文关联、CVSS 补充、POC 检索、资产识别、攻击链推理
- **3 个创新点**：情报评分卡、攻击链可视化、语义搜索
- **定时采集**：APScheduler，NVD 每小时，其他 4 小时
- **本地告警**：CVSS≥9 或 risk_score≥80 触发
- **Streamlit 仪表板**：10 个可视化模块
- **FastAPI 路由**：对外 4 个接口

## 数据源

| # | 源 | 协议 | 认证 |
|---|---|---|---|
| 1 | NVD | REST API | API Key |
| 2 | GitHub Advisories | REST API | Token |
| 3 | Hugging Face Blog | REST API | 无 |
| 4 | 安全客 | RSS | 无 |
| 5 | ArXiv | Atom XML | 无 |
| 6 | OSV.dev | REST API | 无 |
| 7 | Seebug Paper | RSS | 无 |
| 8 | Exploit-DB | RSS | 无 |
| 9 | Hacker News | RSS | 无 |

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/lin637440-jpg/intel-monitor.git
cd intel-monitor
```

### 2. 创建虚拟环境

Windows：

```cmd
python -m venv venv
venv\Scripts\activate
```

macOS / Linux：

```bash
python -m venv venv
source venv/bin/activate
```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```

### 4. 配置环境变量

创建 `.env` 文件：

```text
NVD_API_KEY=你的NVD_KEY
GITHUB_TOKEN=你的GITHUB_TOKEN
```

申请入口：

- NVD API Key：https://nvd.nist.gov/developers/request-an-api-key
- GitHub Token：https://github.com/settings/tokens（勾选 `public_repo`）

### 5. 运行

```bash
# 采集全部源
python main.py

# 计算采集延迟
python metrics.py

# 富化样本
python -m enrichment.pipeline

# 生成 CWE 主题分布
python -m enrichment.cross_validate

# 生成趋势分析
python -m analytics.trend

# 生成 CVE 关联图
python -m analytics.graph

# 采集质量监控
python -m analytics.source_health

# 本地告警
python -m alerts.webhook

# 启动仪表板
streamlit run app.py
```

## 对外接口

```python
from app.monitor.service import (
    collect_vulnerabilities,   # 采集+富化+入库 -> list[dict]
    search_vulnerabilities,    # 语义搜索 (keyword) -> list[dict]
    enrich_vulnerability,      # 单条富化 (cve_id) -> dict
    export_for_chroma,         # Chroma 格式导出 -> list[dict]
)
```

### 接口示例

采集：

```python
from app.monitor.service import collect_vulnerabilities
records = collect_vulnerabilities()
print(f"新增 {len(records)} 条")
```

搜索：

```python
from app.monitor.service import search_vulnerabilities
results = search_vulnerabilities("prompt injection")
for r in results[:5]:
    print(r["title"])
```

导出给 Chroma：

```python
from app.monitor.service import export_for_chroma
records = export_for_chroma()
for r in records:
    chroma_collection.upsert(
        ids=[r["id"]],
        documents=[r["document"]],
        metadatas=[r["metadata"]],
    )
```

## 目录结构

```
intel-monitor/
├── collectors/                采集器（9 个）
│   ├── cve_collector.py
│   ├── github_advisories_collector.py
│   ├── hf_blog_collector.py
│   ├── anquanke_collector.py
│   ├── arxiv_collector.py
│   ├── osv_collector.py
│   ├── seebug_collector.py
│   ├── exploitdb_collector.py
│   └── hn_collector.py
├── enrichment/                富化模块
│   ├── pipeline.py            富化管道
│   ├── paper_link.py          论文关联
│   ├── cvss_enrich.py         CVSS 补充
│   ├── poc_search.py          POC 检索
│   ├── asset_extract.py       资产识别
│   ├── attack_chain.py        攻击链推理
│   ├── risk_score.py          评分卡
│   ├── chain_viz.py           攻击链可视化
│   ├── cross_validate.py      CWE 主题分布
│   └── merge_cve.py           跨源归并
├── analytics/                 数据分析
│   ├── trend.py               趋势分析
│   ├── graph.py               CVE 关联图
│   └── source_health.py       采集质量监控
├── storage/                   存储层
│   ├── db.py                  SQLite 封装
│   ├── sync_state.py          增量同步状态
│   └── normalize_fields.py    字段规范化
├── app/
│   ├── monitor/
│   │   ├── service.py         对外接口
│   │   ├── models.py          Pydantic 模型
│   │   └── semantic_search.py 语义搜索
│   └── api/
│       └── routes.py          FastAPI 路由
├── alerts/
│   └── webhook.py             本地告警
├── scheduler/
│   └── jobs.py                定时任务
├── common/
│   └── exceptions.py          统一异常
├── tests/
│   └── test_monitor.py        单元测试
├── docs/                      技术文档
│   ├── 技术报告.md
│   ├── A模块接口说明.md
│   ├── 接口说明.md
│   └── 开发日志.md
├── data/                      数据目录
├── app.py                     Streamlit 仪表板
├── main.py                    统一入口
├── metrics.py                 延迟统计
├── setup.py                   pip install 支持
└── requirements.txt           依赖锁定
```

## 技术栈

| 类别 | 技术 |
|---|---|
| 语言 | Python 3.11 |
| 采集 | requests、BeautifulSoup、lxml |
| 存储 | SQLite、SQLAlchemy |
| 向量 | sentence-transformers（all-MiniLM-L6-v2） |
| 定时 | APScheduler |
| 可视化 | Streamlit、Plotly、Pandas |
| 图分析 | NetworkX |
| API | FastAPI |
| 数据校验 | Pydantic |
| 测试 | pytest |

## 富化维度

### 五维富化

1. **论文关联**：Sentence-BERT 匹配 ArXiv 摘要，相似度阈值 0.3
2. **CVSS 补充**：调 NVD API 补全 CVSS v3.1 / v2.0
3. **POC 检索**：GitHub Search API 搜 `{CVE} poc`，按 stars 排序
4. **资产识别**：正则匹配 40+ AI 框架（PyTorch、TensorFlow、Transformers 等）
5. **攻击链推理**：5 个模板（提示词注入、模型盗取、数据投毒、供应链攻击、越权访问）

### 三个创新

1. **情报评分卡**：`0.4 × CVSS + 0.2 × POC + 0.2 × 资产 + 0.2 × 新鲜度`
2. **攻击链可视化**：生成 Mermaid `.mmd` 文件
3. **语义搜索**：基于 Sentence-BERT 的自然语言查询

## 测试

```bash
pytest tests/ -v
```

预期输出：

```text
tests/test_monitor.py::test_search_returns_list PASSED
tests/test_monitor.py::test_search_empty_keyword PASSED
tests/test_monitor.py::test_search_no_match PASSED
tests/test_monitor.py::test_enrich_existing PASSED
tests/test_monitor.py::test_enrich_not_found PASSED
tests/test_monitor.py::test_enrich_empty PASSED

====== 6 passed ======
```

## 与下游模块对接

### RAG 问答模块（B）

调用 `export_for_chroma()` 获取情报，通过 `chroma_collection.upsert()` 写入向量库。

### LangGraph 总控

调用 `collect_vulnerabilities()` 触发采集，`search_vulnerabilities()` 做检索，`enrich_vulnerability()` 做单条深挖。

### 安装方式（一行命令）

```bash
pip install -e git+https://github.com/lin637440-jpg/intel-monitor.git#egg=intel-monitor
```

安装后即可：

```python
from app.monitor.service import collect_vulnerabilities
```

## 常见问题

### NVD API 失败怎么办？

代码内置本地缓存兜底。首次采集成功后会缓存到 `data/cve_latest.json`，后续 API 失败自动读取缓存。

### GitHub 域名解析失败？

修改 DNS 为 `223.5.5.5` 和 `119.29.29.29`，执行：

```cmd
ipconfig /flushdns
```

### ArXiv 返回 429 限流？

代码内置 3 次重试和退避等待，等待后自动恢复。

### 首次运行模型下载慢？

设置国内镜像：

```cmd
set HF_ENDPOINT=https://hf-mirror.com
```

## 文档

- [技术报告](docs/技术报告.md)
- [A 模块接口说明](docs/A模块接口说明.md)
- [三方接口约定](docs/接口说明.md)
- [开发日志](docs/开发日志.md)

## 环境要求

- Python 3.11+
- Windows / macOS / Linux
- 依赖见 `requirements.txt`

## 许可证

仅供比赛使用。