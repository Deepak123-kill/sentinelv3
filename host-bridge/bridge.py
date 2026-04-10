#!/usr/bin/env python3
import sys
import json
import struct
import subprocess
import os
import requests
import warnings

# Suppress all FutureWarnings that corrupt Native Messaging stdout
warnings.filterwarnings("ignore")

LIMA_INSTANCE = "local"
REMOTE_BINARY_PATH = os.path.expanduser("~/sentinel_v2/linux-backend/target/release/sentinel_cli")

def load_config():
    try:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, "config.json")
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        return {}
    except:
        return {}

config = load_config()
HF_TOKEN = config.get("hf_token", "")
VT_API_KEY = config.get("vt_api_key", "")
GEMINI_API_KEY = config.get("gemini_api_key", "")


def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length:
        return None
    message_length = struct.unpack('=I', raw_length)[0]
    message = sys.stdin.buffer.read(message_length).decode('utf-8')
    return json.loads(message)

def send_message(message):
    encoded_content = json.dumps(message).encode('utf-8')
    encoded_length = struct.pack('=I', len(encoded_content))
    sys.stdout.buffer.write(encoded_length)
    sys.stdout.buffer.write(encoded_content)
    sys.stdout.buffer.flush()

def run_remote_scan(payload):
    cmd = [REMOTE_BINARY_PATH]
    
    env = os.environ.copy()
    env["VT_API_KEY"] = VT_API_KEY
    env["HF_TOKEN"] = HF_TOKEN
    
def handle_message(message):
    target = message.get("target", "")
    action = message.get("action", "scan")
    
    is_url = target.startswith("http://") or target.startswith("https://")
    
    if is_url:
        result = scan_url(target)
    else:
        result = scan_file(target)
    
    send_message(result)

def scan_url(url):
    import requests
    
    # HF_TOKEN is loaded globally
    
    safe_domains = [
        'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
        'linkedin.com', 'netflix.com', 'amazon.com', 'microsoft.com', 'apple.com',
        'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org'
    ]
    
    domain = url.split('/')[2] if len(url.split('/')) > 2 else url
    is_whitelisted = any(safe in domain.lower() for safe in safe_domains)
    
    if is_whitelisted:
        return {
            "status": "ANALYZED",
            "details": f"Domain {domain} is on the trusted whitelist",
            "isolation_method": "whitelist_check",
            "threat_score": {
                "level": "LOW",
                "score": 5,
                "confidence": 0.95,
                "indicators": ["Verified legitimate domain", "On whitelist"]
            },
            "timestamp": int(__import__('time').time())
        }
    
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        prompt = f"""Analyze this URL for phishing.
URL: {url}

Task:
1. Check if the domain is legitimate.
2. Check for typosquatting.
3. Check for suspicious subdomains.

Reply with this JSON format:
{{
  "verdict": "MALICIOUS" or "SAFE" or "SUSPICIOUS",
  "reason": "Brief explanation",
  "confidence": 0.0 to 1.0
}}
"""
        response = model.generate_content(prompt)
        text = response.text.replace('```json', '').replace('```', '').strip()
        
        try:
            import json
            data = json.loads(text)
            verdict = data.get('verdict', 'UNKNOWN').upper()
            llm_reason = data.get('reason', 'No reason provided')
            confidence = data.get('confidence', 0.8)
        except Exception:
            verdict = "MALICIOUS" if "MALICIOUS" in text.upper() else "SAFE"
            llm_reason = text[:200]
            confidence = 0.6

        # Assign base scores similar to the CLI tool
        if verdict == 'MALICIOUS':
            score = 90
            level = "HIGH"
            indicators = ["🚨 AI flagged as malicious"]
        elif verdict == 'SUSPICIOUS':
            score = 60
            level = "MEDIUM"
            indicators = ["⚠️ AI flagged as suspicious"]
        else:
            score = 10
            level = "LOW"
            indicators = ["✅ AI analysis: appears safe"]
            
        # Add slight score changes for heuristic checks
        suspicious_patterns = ['verify', 'suspend', 'urgent', 'confirm', 'secure-account']
        if any(pattern in url.lower() for pattern in suspicious_patterns) and verdict != 'SAFE':
            score += 5
            indicators.append("URL contains high-risk keywords")
        
        if url.startswith('http://'):
            score += 5
            indicators.append("No HTTPS encryption")
            
        score = min(score, 100)
        
        # Ensure level matches final score just in case
        if score < 30:
            level = "LOW"
        elif score < 70:
            level = "MEDIUM"
        else:
            level = "HIGH"
        
        return {
            "status": "ANALYZED",
            "details": f"Gemini Analysis: {llm_reason}",
            "isolation_method": "gemini_analysis",
            "threat_score": {
                "level": level,
                "score": score,
                "confidence": confidence,
                "indicators": indicators
            },
            "timestamp": int(__import__('time').time())
        }
    except Exception as e:
        return {
            "status": "error",
            "details": f"URL scan error: {str(e)}"
        }

def scan_file(file_path):
    import subprocess
    
    binary_path = os.path.expanduser("~/sentinel_v2/linux-backend/target/release/sentinel_cli")
    cmd = [binary_path, "--path", file_path]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            output = result.stdout
            json_start = output.rfind('{')
            
            if json_start != -1:
                brace_count = 0
                for i in range(json_start, len(output)):
                    if output[i] == '{':
                        brace_count += 1
                    elif output[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            json_str = output[json_start:i+1]
                            return json.loads(json_str)
            
            return {
                "status": "error",
                "details": "No valid JSON in output"
            }
        else:
            return {
                "status": "error",
                "details": result.stderr or "File scan failed",
                "code": result.returncode
            }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "details": "File scan timed out"
        }
    except Exception as e:
        return {
            "status": "error",
            "details": f"Scan error: {str(e)}"
        }

def main():
    while True:
        message = read_message()
        if not message:
            break
        handle_message(message)

if __name__ == "__main__":
    main()
