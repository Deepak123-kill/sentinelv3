import requests
import json
import os

with open("config.json") as f:
    key = json.load(f)["gemini_api_key"]

headers = {
    "Authorization": f"Bearer {key}",
    "Content-Type": "application/json"
}
data = {
    "model": "google/gemma-2b",
    "messages": [{"role": "user", "content": "Hello"}],
    "max_tokens": 1024
}
r = requests.post("https://integrate.api.nvidia.com/v1/chat/completions", headers=headers, json=data)
print(r.status_code)
print(r.text)
