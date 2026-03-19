import requests
import base64
import time
from tldextract import extract
from src.url_features import get_url_features
from src.whois_check import get_domain_age_features
from src.content_features import get_content_features

# Paste your VirusTotal API Key here
VT_API_KEY = "f2b52640bff6e91296e9b516224ae6c67be9a689795cdae38e0e23da66a0fa15"

def get_live_vt_report(url):
    """Forces VirusTotal to scan the URL right now and waits for results"""
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        # 1. Submit URL for a FRESH scan
        submit_url = "https://www.virustotal.com/api/v3/urls"
        payload = {"url": url}
        submit_res = requests.post(submit_url, data=payload, headers=headers, timeout=10)
        
        if submit_res.status_code == 200:
            analysis_id = submit_res.json()['data']['id']
            
            # 2. Wait 2 seconds for engines to finish (Real-time processing)
            time.sleep(2) 
            
            # 3. Get the latest analysis results
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            report_res = requests.get(analysis_url, headers=headers, timeout=10)
            
            if report_res.status_code == 200:
                stats = report_res.json()['data']['attributes']['stats']
                malicious = stats.get('malicious', 0)
                if malicious > 0:
                    return True, f"Live Flagged by {malicious} engines"
        
        return False, None
    except Exception as e:
        print(f"Real-time API Error: {e}")
        return False, None

def detect_phishing(url):
    # --- 1. WHITELIST (Skip live scanning for trusted giants) ---
    ext = extract(url)
    reg_domain = f"{ext.domain}.{ext.suffix}".lower()
    if reg_domain in ['google.com', 'youtube.com', 'microsoft.com', 'chatgpt.com']:
        return "SAFE (Whitelisted)", {}

    # --- 2. FORCED REAL-TIME SCAN ---
    # This calls the live API we just wrote
    is_malicious, message = get_live_vt_report(url)
    if is_malicious:
        return f"PHISHING ({message})", {"live_api_match": 1}

    # --- 3. LOCAL RULE ENGINE (Heuristics) ---
    # Runs if API is clean but site looks 'fishy'
    f1 = get_url_features(url)
    f2 = get_domain_age_features(url)
    f3 = get_content_features(url)
    all_features = {**f1, **f2, **f3}

    # Weights
    weights = {'has_ip': 6, 'has_at_symbol': 5, 'is_new_domain': 4, 'hidden_forms': 3}
    total_score = sum(weights.get(f, 1) for f, v in all_features.items() if v == 1)

    if total_score >= 7: verdict = "PHISHING"
    elif total_score >= 4: verdict = "SUSPICIOUS"
    else: verdict = "SAFE"
        
    return verdict, all_features