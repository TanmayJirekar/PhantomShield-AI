import re
from urllib.parse import urlparse

URL_PATTERN = re.compile(
    r'(?:https?://|www\.)[^\s<>"\'\[\]{}|\\^`]+|'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?:com|org|net|io|co|in|uk|de|fr|info|biz|xyz|top|click|link|ru|cn|tk|ml|ga|cf|gq|pw|cc|me|app|dev|site|online|shop|store|live|work|tech|pro|bid|loan|win|stream|download|party|review|accountant|date|faith|racing|science|cricket|country)(?:/[^\s<>"\'\[\]{}|\\^`]*)?',
    re.IGNORECASE,
)

SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'link', 'work',
    'party', 'review', 'accountant', 'date', 'faith', 'racing', 'science',
    'cricket', 'country', 'bid', 'loan', 'win', 'stream', 'download',
    'zip', 'mov', 'cam', 'rest', 'monster', 'sbs', 'cfd', 'bond',
}

SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'j.mp', 'cutt.ly', 'rb.gy', 'shorturl.at', 'rebrand.ly',
    'bl.ink', 'soo.gd', 'v.gd', 'clck.ru', 't.ly', 'shorte.st',
}

KNOWN_BRANDS = {
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'instagram',
    'netflix', 'whatsapp', 'telegram', 'bank', 'chase', 'wellsfargo', 'citibank',
    'hsbc', 'sbi', 'hdfc', 'icici', 'axis', 'paytm', 'phonepe', 'gpay',
}


def normalize_url(url):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


def extract_urls_from_text(text):
    """Find URL-like strings in plain text (e.g. QR payloads without scheme)."""
    if not text:
        return []
    found = URL_PATTERN.findall(text)
    cleaned = []
    for match in found:
        candidate = match.rstrip('.,;:!?)')
        if len(candidate) >= 4 and candidate not in cleaned:
            cleaned.append(candidate)
    return cleaned


def is_ip_address(domain):
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]))


def get_registered_domain(domain):
    """Return registrable domain without relying on network calls."""
    domain = domain.lower().split(':')[0]
    if domain.startswith('www.'):
        domain = domain[4:]
    parts = domain.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain


def looks_like_typosquat(domain):
    """Detect brand names embedded in suspicious domains."""
    domain_lower = domain.lower()
    registered = get_registered_domain(domain_lower)
    for brand in KNOWN_BRANDS:
        if brand in domain_lower and brand not in registered:
            return brand
    return None
