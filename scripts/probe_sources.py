import requests

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0 Safari/537.36"
    )
}

CANDIDATES = [
    ("阿里云漏洞库AVD", "https://avd.aliyun.com/"),
    ("CNNVD国家漏洞库", "http://www.cnnvd.org.cn/"),
    ("CNVD漏洞平台", "https://www.cnvd.org.cn/"),
    ("安全客RSS", "https://api.anquanke.com/data/v1/rss"),
    ("FreeBuf RSS", "https://www.freebuf.com/feed"),
    ("OSV.dev", "https://api.osv.dev/v1/vulns/CVE-2021-44228"),
    ("VulDB RSS", "https://vuldb.com/?rss"),
    ("Exploit-DB RSS", "https://www.exploit-db.com/rss.xml"),
    ("PacketStorm RSS", "https://packetstormsecurity.com/feeds/"),
    ("Seebug Paper", "https://paper.seebug.org/rss/"),
    ("Hacker News API", "https://hacker-news.firebaseio.com/v0/topstories.json"),
    ("Hacker News RSS", "https://hnrss.org/newest?q=security"),
    ("中国国家互联网应急中心", "https://www.cert.org.cn/"),
    ("腾讯安全", "https://s.tencent.com/research/index.html"),
]

for name, url in CANDIDATES:
    try:
        r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
        print(f"[OK]  {name:20s} status={r.status_code} len={len(r.text)} {url}")
    except Exception as e:
        print(f"[FAIL] {name:20s} {type(e).__name__}: {str(e)[:60]} {url}")