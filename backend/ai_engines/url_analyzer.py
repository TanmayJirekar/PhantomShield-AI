import re
import math
import os
import joblib
import pandas as pd
from urllib.parse import urlparse

from ai_engines.url_utils import (
    normalize_url,
    is_ip_address,
    get_registered_domain,
    looks_like_typosquat,
    SUSPICIOUS_TLDS,
    SHORTENER_DOMAINS,
)
from ai_engines.threat_intel import check_virustotal

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'url_phishing_model.pkl')
try:
    url_model = joblib.load(MODEL_PATH)
except FileNotFoundError:
    url_model = None
    print("Warning: url_phishing_model.pkl not found. URL analyzer will use enhanced heuristics.")


def extract_url_features(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    path = parsed.path

    features = {}
    features['length_url'] = len(url)
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_or'] = url.count('|')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolumn'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = url.count(' ')
    features['nb_www'] = 1 if 'www.' in url.lower() else 0
    features['nb_com'] = 1 if '.com' in url.lower() else 0
    features['nb_dslash'] = 1 if '//' in url[8:] else 0
    features['http_in_path'] = 1 if 'http' in path.lower() else 0
    features['https_token'] = 1 if parsed.scheme == 'https' else 0
    digits_count = sum(c.isdigit() for c in url)
    features['ratio_digits_url'] = digits_count / len(url) if len(url) > 0 else 0
    features['punycode'] = 1 if 'xn--' in url.lower() else 0
    return features


def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for char in set(text):
        p_x = float(text.count(char)) / len(text)
        entropy += -p_x * math.log(p_x, 2)
    return entropy


def _heuristic_penalties(url, domain, features):
    """Rule-based penalties (0-100 scale, higher = more dangerous)."""
    penalties = []
    danger = 0

    if is_ip_address(domain):
        danger += 35
        penalties.append('IP address used instead of a domain name (high risk).')

    if '@' in url:
        danger += 30
        penalties.append("Contains '@' symbol, often used to hide the real destination.")

    if not features.get('https_token'):
        danger += 15
        penalties.append('Does not use HTTPS (insecure connection).')

    if features.get('length_url', 0) > 75:
        danger += 10
        penalties.append(f"Unusually long URL ({features['length_url']} characters).")

    if features.get('nb_dots', 0) > 4:
        danger += 12
        penalties.append(f"Excessive subdomains ({features['nb_dots']} dots).")

    if features.get('nb_dslash'):
        danger += 15
        penalties.append('Suspicious double slash found in the URL path.')

    if features.get('punycode'):
        danger += 20
        penalties.append('Punycode/homograph domain detected (possible impersonation).')

    if features.get('ratio_digits_url', 0) > 0.15:
        danger += 8
        penalties.append('High ratio of digits in the URL.')

    if features.get('http_in_path'):
        danger += 18
        penalties.append('Embedded HTTP link in URL path (redirect trick).')

    registered = get_registered_domain(domain)
    tld = registered.split('.')[-1] if '.' in registered else ''
    if tld in SUSPICIOUS_TLDS:
        danger += 15
        penalties.append(f'Suspicious top-level domain (.{tld}).')

    if registered in SHORTENER_DOMAINS or any(s in domain for s in SHORTENER_DOMAINS):
        danger += 8
        penalties.append('URL shortener detected — final destination is hidden.')

    typosquat = looks_like_typosquat(domain)
    if typosquat:
        danger += 25
        penalties.append(f"Possible brand impersonation ('{typosquat}' in domain).")

    domain_entropy = calculate_entropy(domain.split('.')[0] if domain else '')
    if domain_entropy > 4.0 and len(domain) > 12:
        danger += 10
        penalties.append('Domain name has high randomness (possible auto-generated phishing).')

    if re.search(r'(login|verify|secure|account|update|confirm|banking|wallet)', url.lower()):
        if danger > 0 or tld in SUSPICIOUS_TLDS or typosquat:
            danger += 5
            penalties.append('URL contains sensitive-action keywords combined with other red flags.')

    return min(100, danger), penalties


def _ml_trust_score(url):
    features = extract_url_features(url)
    df_features = pd.DataFrame([features])
    proba = url_model.predict_proba(df_features)[0]
    legit_prob = proba[0]
    trust_score = int(legit_prob * 100)
    return trust_score, features


def _risk_level_from_trust(trust_score):
    if trust_score >= 80:
        return 'Low'
    if trust_score >= 50:
        return 'Medium'
    return 'High'


def analyze_url(url, use_virustotal=True):
    url = normalize_url(url)
    parsed = urlparse(url)
    domain = parsed.netloc
    details = []

    if url_model:
        trust_score, features = _ml_trust_score(url)
        heuristic_danger, heuristic_details = _heuristic_penalties(url, domain, features)

        # Ensemble: blend ML trust with heuristic danger (70% ML, 30% rules)
        blended_trust = int(trust_score * 0.7 + (100 - heuristic_danger) * 0.3)
        trust_score = max(0, min(100, blended_trust))
        details.extend(heuristic_details)

        if trust_score >= 80 and not details:
            details.append('AI model analysis indicates this is likely a safe, legitimate URL.')
        elif trust_score < 50:
            details.append('AI model classified this URL as phishing/scam with high confidence.')
        elif heuristic_details:
            details.append('AI model detected unusual patterns — proceed with caution.')
    else:
        features = extract_url_features(url)
        heuristic_danger, details = _heuristic_penalties(url, domain, features)
        trust_score = max(0, 100 - heuristic_danger)
        if not details:
            details.append('No major red flags detected by heuristic analysis.')

    risk_level = _risk_level_from_trust(trust_score)

    vt_result = check_virustotal(url) if use_virustotal else None
    if vt_result:
        details.append(vt_result['message'])
        if vt_result.get('malicious_count', 0) >= 1:
            trust_score = min(trust_score, 25)
            risk_level = 'High'
        elif vt_result.get('suspicious_count', 0) >= 2:
            trust_score = min(trust_score, 45)
            if risk_level == 'Low':
                risk_level = 'Medium'

    danger_score = 100 - trust_score

    return {
        'trust_score': trust_score,
        'danger_score': danger_score,
        'risk_level': risk_level,
        'details': details,
        'domain': domain,
        'registered_domain': get_registered_domain(domain),
        'ai_powered': bool(url_model),
        'virustotal': vt_result,
    }
