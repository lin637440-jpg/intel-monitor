\# B 对接指南



A 模块（情报监测 + 富化）与 B 模块（RAG 问答）的对接说明。



\---



\## 一、安装



```bash

pip install -e git+https://github.com/lin637440-jpg/intel-monitor.git#egg=intel-monitor

```



\---



\## 二、两种取数方式



\### 方式 A：直接读 JSON（推荐，最简单）



我发你 `chroma\_records.json`，保存到本地，直接读：



```python

import json



with open("chroma\_records.json", encoding="utf-8") as f:

&#x20;   records = json.load(f)



print(type(records))   # <class 'list'>

print(len(records))    # 326

print(records\[0])

```



\### 方式 B：pip install 后调接口



\*\*第 1 步\*\*：我发你 `intel.db`，保存到本地



\*\*第 2 步\*\*：代码里设置环境变量



```python

import os

os.environ\["INTEL\_DB\_PATH"] = r"C:\\你保存的路径\\intel.db"



from app.monitor.service import export\_for\_chroma



records = export\_for\_chroma()

print(type(records))   # <class 'list'>

print(len(records))    # 326

```



\---



\## 三、records 数据结构



```json

\[

&#x20; {

&#x20;   "id": "NVD:CVE-2026-12260",

&#x20;   "document": "SQL injection in the NetBoard CRM demo platform...\\n\\n资产: ...\\n\\n攻击链: 越权访问",

&#x20;   "metadata": {

&#x20;     "source": "NVD",

&#x20;     "cve\_id": "CVE-2026-12260",

&#x20;     "cvss": 10.0,

&#x20;     "risk\_score": 92.0,

&#x20;     "risk\_level": "CRITICAL",

&#x20;     "cwe": "CWE-89",

&#x20;     "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12260",

&#x20;     "published": "2026-10-12T07:13:54+00:00"

&#x20;   }

&#x20; }

]

```



\### 字段说明



| 字段 | 类型 | 说明 |

|---|---|---|

| `id` | str | 唯一标识，格式 `{source}:{原生ID}` |

| `document` | str | 标题 + 描述 + 资产 + 攻击链，用于向量编码 |

| `metadata.source` | str | 数据源名称（NVD / GitHub Advisories 等） |

| `metadata.cve\_id` | str | CVE 编号（如 `CVE-2026-12260`） |

| `metadata.cvss` | float | CVSS 基础分（0-10） |

| `metadata.risk\_score` | float | 综合评分（0-100） |

| `metadata.risk\_level` | str | CRITICAL / HIGH / MEDIUM / LOW |

| `metadata.cwe` | str | CWE 类型，多个用逗号分隔 |

| `metadata.url` | str | 原始链接，100% 覆盖 |

| `metadata.published` | str | 发布时间，ISO 8601 格式 |



\---



\## 四、灌入 Chroma



```python

import chromadb



client = chromadb.PersistentClient(path="./chroma\_db")

collection = client.get\_or\_create\_collection("security\_intel")



for r in records:

&#x20;   collection.upsert(

&#x20;       ids=\[r\["id"]],

&#x20;       documents=\[r\["document"]],

&#x20;       metadatas=\[r\["metadata"]],

&#x20;   )



print(f"已灌入 {len(records)} 条")

```



\### 注意



\- \*\*`upsert` 会自动覆盖同 id\*\*，重复灌不会冲突

\- \*\*Chroma 默认用 `all-MiniLM-L6-v2` 编码\*\*，和 A 模块用的模型一致

\- \*\*collection name 建议 `security\_intel`\*\*，如果想用别的告诉我



\---



\## 五、检索测试



```python

results = collection.query(

&#x20;   query\_texts=\["SQL injection vulnerability"],

&#x20;   n\_results=3,

)



for i, doc\_id in enumerate(results\["ids"]\[0]):

&#x20;   meta = results\["metadatas"]\[0]\[i]

&#x20;   print(f"\[{meta\['cve\_id']}] CVSS={meta\['cvss']} {meta\['url']}")

```



期望能检索到 `CVE-2026-12260` 等 SQL 注入相关记录。



\---



\## 六、RAG 问答示例



```python

def ask\_question(question, history=None):

&#x20;   # 1. 检索

&#x20;   results = collection.query(query\_texts=\[question], n\_results=5)



&#x20;   # 2. 拼上下文

&#x20;   context = ""

&#x20;   for i, doc in enumerate(results\["documents"]\[0]):

&#x20;       meta = results\["metadatas"]\[0]\[i]

&#x20;       context += f"\\n\\n【{meta\['cve\_id']}】CVSS {meta\['cvss']}\\n"

&#x20;       context += f"来源：{meta\['url']}\\n"

&#x20;       context += doc\[:500]



&#x20;   # 3. 调 DeepSeek

&#x20;   prompt = f"根据以下情报回答问题：\\n{context}\\n\\n问题：{question}"

&#x20;   answer = call\_deepseek(prompt)



&#x20;   return {

&#x20;       "answer": answer,

&#x20;       "sources": \[m for m in results\["metadatas"]\[0]],

&#x20;   }

```



\---



\## 七、数据资源



| 资源 | 说明 |

|---|---|

| 数据源 | 9 个（NVD / GitHub / HF / 安全客 / ArXiv / OSV / Seebug / Exploit-DB / HN） |

| 情报总数 | 326 条 |

| URL 覆盖率 | 100% |

| 富化准确率 | 100%（抽样 20 条） |

| 采集延迟 | ≤6h（Hacker News min=2.07h） |

| 向量维度 | 384（all-MiniLM-L6-v2） |



\---



\## 八、数据更新



\*\*需要新数据时\*\*：



```python

from app.monitor.service import collect\_vulnerabilities, export\_for\_chroma



\# 采集新数据（会联网，自动富化）

new\_records = collect\_vulnerabilities()

print(f"新增 {len(new\_records)} 条")



\# 再导出全量

all\_records = export\_for\_chroma()

```



\*\*建议频率\*\*：



\- 定时（每小时）：你主动调 `collect\_vulnerabilities()`

\- 或我这边后台跑 APScheduler，你只调 `export\_for\_chroma()`



\---



\## 九、接口不变承诺



A 模块保证以下接口\*\*稳定不变\*\*：



```python

from app.monitor.service import (

&#x20;   collect\_vulnerabilities,   # () -> list\[dict]

&#x20;   search\_vulnerabilities,    # (keyword: str) -> list\[dict]

&#x20;   enrich\_vulnerability,      # (cve\_id: str) -> dict

&#x20;   export\_for\_chroma,         # () -> list\[dict]

)

```



B 模块的 `update\_knowledge\_base(records)` 和 `ask\_question(question, history)` 接口，A 不干涉。



\---



\## 十、常见问题



\### Q1：`export\_for\_chroma()` 报找不到数据库



\*\*A\*\*：设置环境变量：



```python

import os

os.environ\["INTEL\_DB\_PATH"] = r"你的 intel.db 路径"

```



或者用方式 A 直接读 JSON。



\### Q2：URL 字段为空



\*\*A\*\*：已修复，326 条 URL 覆盖率 100%。如还有空，告诉我 CVE 编号。



\### Q3：Chroma 已有数据，会不会冲突



\*\*A\*\*：`upsert` 按 id 覆盖，A 的 id 格式是 `{source}:{原生ID}`，和你现有数据不冲突。



\### Q4：想过滤某些源的数据



\*\*A\*\*：



```python

records = \[r for r in export\_for\_chroma()

&#x20;          if r\["metadata"]\["source"] in \["NVD", "GitHub Advisories"]]

```



\### Q5：想按 CVSS 过滤



\*\*A\*\*：



```python

records = \[r for r in export\_for\_chroma()

&#x20;          if r\["metadata"]\["cvss"] >= 7.0]

```



\---



\## 十一、联系方式



\- GitHub：https://github.com/lin637440-jpg/intel-monitor



