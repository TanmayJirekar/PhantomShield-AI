import requests
import streamlit as st

BASE_URL = "http://127.0.0.1:5000/api"


def _request(method, endpoint, **kwargs):
    try:
        response = requests.request(method, f"{BASE_URL}{endpoint}", timeout=30, **kwargs)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        st.error("Cannot connect to backend. Make sure the Flask server is running on port 5000.")
        return None
    except requests.exceptions.RequestException as e:
        st.error(f"Error connecting to backend: {e}")
        return None


def get_health():
    return _request('GET', '/health')


def scan_url(url):
    return _request('POST', '/scan/url', json={'url': url})


def scan_url_batch(urls):
    return _request('POST', '/scan/url/batch', json={'urls': urls})


def scan_qr(file):
    files = {'file': (file.name, file.getvalue(), file.type)}
    return _request('POST', '/scan/qr', files=files)


def scan_text(text):
    return _request('POST', '/scan/text', json={'text': text})


def chat_with_assistant(message, api_key=None):
    payload = {'message': message}
    if api_key:
        payload['api_key'] = api_key
    return _request('POST', '/chat/ask', json=payload)


def get_scan_history(limit=10):
    return _request('GET', f'/scan/history?limit={limit}') or {'history': []}
