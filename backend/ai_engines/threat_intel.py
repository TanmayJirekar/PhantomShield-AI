import base64
import requests
from config import Config

VT_API_URL = 'https://www.virustotal.com/api/v3/urls'


def check_virustotal(url):
    """
    Query VirusTotal URL reputation. Returns None if no API key or on failure.
    """
    api_key = Config.VIRUSTOTAL_API_KEY
    if not api_key:
        return None

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        headers = {'x-apikey': api_key}

        response = requests.get(f'{VT_API_URL}/{url_id}', headers=headers, timeout=10)
        if response.status_code == 404:
            submit = requests.post(
                VT_API_URL,
                headers=headers,
                data={'url': url},
                timeout=10,
            )
            if submit.status_code not in (200, 201):
                return None
            analysis_id = submit.json().get('data', {}).get('id')
            if not analysis_id:
                return None
            return {
                'status': 'submitted',
                'message': 'URL submitted to VirusTotal for analysis. Re-scan in ~30 seconds for results.',
                'malicious_count': 0,
                'suspicious_count': 0,
                'harmless_count': 0,
            }

        if response.status_code != 200:
            return None

        stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        total = malicious + suspicious + harmless + undetected

        return {
            'status': 'complete',
            'malicious_count': malicious,
            'suspicious_count': suspicious,
            'harmless_count': harmless,
            'total_engines': total,
            'detection_ratio': f'{malicious + suspicious}/{total}' if total else '0/0',
            'message': _vt_message(malicious, suspicious),
        }
    except requests.RequestException:
        return None


def _vt_message(malicious, suspicious):
    if malicious >= 3:
        return f'Very dangerous: {malicious} security vendors flagged this URL as malicious.'
    if malicious >= 1:
        return f'Warning: {malicious} vendor(s) flagged this URL as malicious.'
    if suspicious >= 2:
        return f'Suspicious: {suspicious} vendor(s) marked this URL as suspicious.'
    return 'No malicious detections from VirusTotal community scanners.'
