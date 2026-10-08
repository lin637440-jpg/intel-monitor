\# 情报监测与富化模块



\## 数据源（5 个）

1\. CVE NVD API - https://nvd.nist.gov/developers/vulnerabilities

2\. GitHub Security Advisories - https://github.com/advisories

3\. Hugging Face Blog - https://huggingface.co/blog

4\. 奇安信威胁情报中心 - https://ti.qianxin.com/

5\. ArXiv API - http://export.arxiv.org/api/query



\## Day1 完成

\- \[x] 项目结构

\- \[x] NVD CVE 采集器，50 条

\- \[x] GitHub Advisories 采集器，20 条

\- \[x] `.env` + `.gitignore`



\## 运行

python -m collectors.cve\_collector

python -m collectors.github\_advisories\_collector



\## 环境

pip install requests beautifulsoup4 lxml python-dotenv



\## 常见问题

\- GitHub 无法解析：改 DNS 为 223.5.5.5 / 119.29.29.29，执行 `ipconfig /flushdns`

\- NVD 限流：确认 `.env` 中 `NVD\_API\_KEY` 已配置

