import re
from ai_engines.url_utils import extract_urls_from_text
from ai_engines.url_analyzer import analyze_url


def analyze_text_for_scam(text):
    if not text:
        return {
            'scam_probability': 0,
            'danger_score': 0,
            'risk_level': 'Low',
            'findings': ['No text provided.'],
        }

    text_lower = text.lower()
    findings = []
    score = 0

    urgency_words = [
        'urgent', 'immediate action required', 'account suspended', 'expires in',
        'final notice', 'action required', 'within 24 hours', 'act now',
        'limited time', 'last chance', 'verify immediately',
    ]
    financial_words = [
        'claim your prize', 'you won', 'lottery', 'guaranteed return', 'investment',
        'double your money', 'crypto', 'bonus', 'free money', 'wire transfer',
        'send money', 'western union', 'gift card', 'bitcoin', 'usdt',
    ]
    authority_words = [
        'irs', 'tax refund', 'police', 'fbi', 'government grant',
        'bank account closed', 'social security', 'customs', 'court summons',
    ]
    credential_words = [
        'verify your account', 'confirm password', 'update billing', 'login now',
        'suspended account', 'unusual activity', 'click here to verify',
        'enter your otp', 'share your otp', 'one-time password',
    ]

    for word in urgency_words:
        if word in text_lower:
            score += 18
            findings.append(f"Urgency language detected: '{word}'")

    for word in financial_words:
        if word in text_lower:
            score += 22
            findings.append(f"Suspicious financial promise: '{word}'")

    for word in authority_words:
        if word in text_lower:
            score += 28
            findings.append(f"Authority impersonation language: '{word}'")

    for word in credential_words:
        if word in text_lower:
            score += 25
            findings.append(f"Credential harvesting pattern: '{word}'")

    if len(re.findall(r'!', text)) > 3:
        score += 10
        findings.append('Excessive use of exclamation marks.')

    caps_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    if caps_ratio > 0.5 and len(text) > 20:
        score += 12
        findings.append('Excessive ALL CAPS text (common in scam messages).')

    urls = extract_urls_from_text(text)
    embedded_url_risks = []
    for url in urls[:3]:
        url_result = analyze_url(url, use_virustotal=False)
        if url_result['trust_score'] < 70:
            score += max(15, 100 - url_result['trust_score'])
            embedded_url_risks.append(
                f"Suspicious embedded URL ({url}): trust score {url_result['trust_score']}/100"
            )
    findings.extend(embedded_url_risks)

    score = min(100, score)

    if score >= 70:
        risk = 'Critical'
    elif score >= 40:
        risk = 'High'
    elif score >= 20:
        risk = 'Medium'
    else:
        risk = 'Low'

    if score == 0:
        findings.append('No common scam patterns detected.')

    return {
        'scam_probability': score,
        'danger_score': score,
        'risk_level': risk,
        'findings': findings,
        'embedded_urls': urls,
    }
