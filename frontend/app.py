import streamlit as st
import sys
import os

sys.path.append(os.path.dirname(__file__))
from utils.api_client import get_scan_history, get_health

st.set_page_config(
    page_title="PhantomShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for modern UI
st.markdown("""
    <style>
    .main {
        background-color: #0E1117;
        color: #FAFAFA;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 5px;
        border: none;
        padding: 10px 24px;
        font-weight: bold;
    }
    .stButton>button:hover {
        background-color: #45a049;
    }
    .metric-card {
        background-color: #1E2127;
        border-radius: 10px;
        padding: 20px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        text-align: center;
    }
    h1, h2, h3 {
        color: #00E676;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ PhantomShield AI")
st.markdown("### Detect. Verify. Protect.")

st.write("""
Welcome to **PhantomShield AI**, a next-generation cybersecurity platform.
Use the sidebar navigation to access our advanced AI-powered scanners.

### Our Capabilities:
* 🌐 **URL Scanner**: AI + heuristic ensemble detects phishing links and malicious domains.
* 📱 **QR Code Scanner**: Multi-pass decode with hidden URL and scam text detection.
* 💬 **Text Scam Scanner**: Analyze SMS, emails, and messages for scam patterns.
* 🤖 **AI Cyber Assistant**: Ask questions and learn about cybersecurity threats.
* 📊 **Analytics Dashboard**: View recent threats and scanning trends.

Select a module from the left sidebar to begin protecting your digital life.
""")

# Live stats from backend
health = get_health()
history_data = get_scan_history(limit=100)
history = history_data.get('history', [])
total_scans = len(history)
threats = len([h for h in history if h.get('risk_level') in ('High', 'Critical')])
ml_status = "AI Active" if health and health.get('ml_model_loaded') else "Heuristic"

col1, col2, col3 = st.columns(3)
with col1:
    st.markdown(f"""
    <div class="metric-card">
        <h3>{total_scans}</h3>
        <p>Scans Performed</p>
    </div>
    """, unsafe_allow_html=True)
with col2:
    st.markdown(f"""
    <div class="metric-card">
        <h3>{threats}</h3>
        <p>Threats Detected</p>
    </div>
    """, unsafe_allow_html=True)
with col3:
    st.markdown(f"""
    <div class="metric-card">
        <h3>{ml_status}</h3>
        <p>Detection Engine</p>
    </div>
    """, unsafe_allow_html=True)
