\# （情报监测与富化）对外接口说明



\## 1. 对外 3 个接口



\### collect\_vulnerabilities() -> list\[dict]

采集 + 去重 + 富化 + 存储，返回本次新增情报。



\### search\_vulnerabilities(keyword: str) -> list\[dict]

语义搜索，返回相关情报 Top 20。



\### enrich\_vulnerability(cve\_id: str) -> dict

对指定 CVE 单条富化。



\## 2. 给 （RAG）的 Chroma 接口



\### to\_chroma\_record(item) -> dict

单条情报转 Chroma 格式。



\### export\_for\_chroma(path) -> list\[dict]

导出全部情报为 Chroma 格式。



返回结构：

```json

{

&#x20; "id": "NVD:CVE-2026-12260",

&#x20; "document": "标题\\n\\n描述\\n\\n资产: PyTorch\\n\\n攻击链: 提示词注入",

&#x20; "metadata": {

&#x20;   "source": "NVD",

&#x20;   "cve\_id": "CVE-2026-12260",

&#x20;   "cvss": 10.0,

&#x20;   "risk\_score": 92.0,

&#x20;   "risk\_level": "CRITICAL",

&#x20;   "cwe": "CWE-89",

&#x20;   "url": "https://nvd.nist.gov/...",

&#x20;   "published": "2026-10-12T07:13:54+00:00"

&#x20; }

}

