import whois
from datetime import datetime

def get_domain_age_features(url):
    features = {}
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date
        
        # Handle cases where creation_date is a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date:
            age_in_days = (datetime.now() - creation_date).days
            # Rule: If domain is less than 180 days (6 months) old
            features['is_new_domain'] = 1 if age_in_days < 180 else 0
        else:
            features['is_new_domain'] = 1 # Flag as suspicious if no date found
            
    except Exception:
        # If WHOIS lookup fails, it's often a fake or unregistered domain
        features['is_new_domain'] = 1
        
    return features