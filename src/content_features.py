import requests
from bs4 import BeautifulSoup

def get_content_features(url):
    features = {'hidden_forms': 0, 'iframe_redirection': 0, 'fake_status_bar': 0}
    
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. Check for suspicious form actions (e.g., submitting to a different domain)
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            if "http" in action and url not in action:
                features['hidden_forms'] = 1
        
        # 2. Check for invisible iframes
        iframes = soup.find_all('iframe')
        if len(iframes) > 0:
            features['iframe_redirection'] = 1
            
        # 3. Check if right-click is disabled (common in phishing to hide source code)
        if "event.button==2" in response.text or "oncontextmenu=\"return false\"" in response.text:
            features['fake_status_bar'] = 1
            
    except Exception:
        pass # If site is down, we ignore content checks
        
    return features