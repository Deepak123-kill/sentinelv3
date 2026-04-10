import requests
import json
import os

try:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, "config.json")
    with open(config_path) as f:
        config = json.load(f)
    
    headers = {
        "Authorization": f"Bearer {config['gemini_api_key']}",
        "Accept": "application/json"
    }
    response = requests.get("https://integrate.api.nvidia.com/v1/models", headers=headers)
    response.raise_for_status()
    models = response.json().get("data", [])
    
    print("Available Models:")
    for m in models:
        print(m["id"])
except Exception as e:
    print(f"Error: {e}")
