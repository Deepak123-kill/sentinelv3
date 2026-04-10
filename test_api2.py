import requests
import json
import os

with open("config.json") as f:
    key = json.load(f)["gemini_api_key"]
print("Key valid format:", key.startswith("nvapi-"))

headers = {
    "Authorization": f"Bearer {key}",
    "Content-Type": "application/json",
    "Accept": "application/json"
}
data = {
    "model": "meta/llama-3.1-8b-instruct",
    "messages": [{"role": "user", "content": "Hello"}]
}
r = requests.post("https://integrate.api.nvidia.com/v1/chat/completions", headers=headers, json=data)
print("Status", r.status_code)
print(r.text)

r2 = requests.get("https://integrate.api.nvidia.com/v1/models", headers=headers)
print("Models status", r2.status_code)
