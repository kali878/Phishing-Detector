import re
from tldextract import extract

def get_url_features(url):
    features = {}

    # 1. IP Address in URL
    ip_pattern = r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
    features['has_ip'] = 1 if re.search(ip_pattern, url) else 0

    # 2. URL Length
    features['long_url'] = 1 if len(url) > 75 else 0

    # 3. Presence of "@" symbol
    features['has_at_symbol'] = 1 if "@" in url else 0

    # 4. Prefix/Suffix separator "-" in Domain
    # Phishing sites often use "google-login.com" instead of "google.com"
    domain = extract(url).domain
    features['has_hyphen_in_domain'] = 1 if '-' in domain else 0

    # 5. Number of Dots
    features['dot_count'] = 1 if url.count('.') > 3 else 0

    # 6. Shortening Service
    shortening_services = r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs'
    features['is_shortened'] = 1 if re.search(shortening_services, url) else 0

    return features