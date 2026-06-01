import os
import json
import urllib.request

token = os.environ.get("GH_TOKEN")
if not token:
    print("No token")
    exit(1)

req = urllib.request.Request(
    "https://api.github.com/repos/khulnasoft/email-security-pipeline/pulls",
    headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
)
with urllib.request.urlopen(req) as response:
    prs = json.loads(response.read().decode())

for pr in prs:
    print(f"PR: {pr['number']} {pr['title']} {pr['head']['ref']}")
