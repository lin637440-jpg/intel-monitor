import os
import requests
from dotenv import load_dotenv

load_dotenv()

token = os.getenv("GITHUB_TOKEN", "").strip()

if not token:
    print("没读到 GITHUB_TOKEN，请检查 .env")
    raise SystemExit(1)

headers = {
    "Authorization": f"Bearer {token}",
    "User-Agent": "intel-monitor/0.1",
}

r = requests.get("https://api.github.com/rate_limit", headers=headers, timeout=20)
print("status:", r.status_code)
data = r.json()
print("core limit:", data["resources"]["core"]["limit"])