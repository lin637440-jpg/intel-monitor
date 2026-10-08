\# 情报监测与富化模块 — 进度记录



\## 项目路径

C:\\Users\\33050\\intel-monitor



\## 环境

\- Windows 10/11

\- Python 3.9（venv）

\- Git 2.56（装于 D:\\Git）

\- 依赖：requests、beautifulsoup4、lxml、python-dotenv



\## Day1 已完成（2026-10-08）

\- \[x] 项目结构：collectors / config / storage / dedup / enrichment / scheduler / scripts / data / logs

\- \[x] `.env` + `.gitignore`，`.env` 未提交

\- \[x] NVD 采集器：collectors/cve\_collector.py，50 条 -> data/cve\_latest.json

\- \[x] GitHub Advisories 采集器：collectors/github\_advisories\_collector.py，20 条 -> data/github\_advisories.json

\- \[x] Token 验证：scripts/check\_github\_token.py，core limit = 5000

\- \[x] README.md

\- \[x] Git 提交：

&#x20; - fdc8542 Day1: NVD collector + GitHub advisories collector

&#x20; - 97318ff Day1: add README



\## 遇到的坑

\- GitHub 域名解析失败：改 DNS 为 223.5.5.5 / 119.29.29.29，`ipconfig /flushdns` 后恢复

\- NVD 无 Key 也能访问，但限流 5次/30秒，有 Key 50次/30秒



\## 待完成

\- \[ ] Hugging Face 博客采集器

\- \[ ] 奇安信威胁情报采集器

\- \[ ] 第 5 个差异化数据源（ArXiv / Reddit）

\- \[ ] Redis 去重

\- \[ ] APScheduler 定时

\- \[ ] 5 维富化（论文、CVSS、POC、资产、攻击链）

\- \[ ] 创新点

\- \[ ] 文档 + 视频

