import streamlit as st
import sys
import os

# Add parent dir to path to import utils
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.api_client import scan_url

st.set_page_config(page_title="URL Scanner - PhantomShield AI", page_icon="🌐", layout="wide")

st.title("🌐 AI URL Scanner")
st.markdown("Analyze links for phishing, scams, and malicious intent.")

url_input = st.text_input("Enter URL to scan", placeholder="https://example.com/login")

if st.button("Scan URL", type="primary"):
    if url_input:
        with st.spinner("Analyzing URL with AI Engine..."):
            result = scan_url(url_input)
            
        if result:
            st.success("Scan Complete!")
            
            # Layout for results
            col1, col2 = st.columns([1, 2])
            
            with col1:
                st.subheader("Trust Score")
                score = result.get("trust_score", 0)
                risk_level = result.get("risk_level", "Unknown")
                ai_powered = result.get("ai_powered", False)
                vt = result.get("virustotal")
                
                if ai_powered:
                    st.caption("🤖 AI + Heuristic Ensemble Active")
                else:
                    st.caption("⚙️ Enhanced Heuristic Mode (train model for AI)")
                
                if vt and vt.get('detection_ratio'):
                    st.caption(f"🛡️ VirusTotal: {vt['detection_ratio']} detections")
                
                # Color code score
                if score >= 80:
                    color = "green"
                elif score >= 50:
                    color = "orange"
                else:
                    color = "red"
                    
                st.markdown(f"""
                <div style="text-align: center; padding: 20px; border-radius: 10px; border: 2px solid {color};">
                    <h1 style="color: {color}; margin: 0; font-size: 60px;">{score}/100</h1>
                    <h3 style="color: {color}; margin: 0;">Risk Level: {risk_level}</h3>
                </div>
                """, unsafe_allow_html=True)
                
            with col2:
                st.subheader("Threat Analysis Report")
                details = result.get("details", [])
                
                if not details:
                    st.info("✅ No suspicious indicators found. This URL appears to be safe.")
                else:
                    for idx, detail in enumerate(details):
                        if "High Risk" in detail or "Critical" in detail:
                            st.error(f"⚠️ {detail}")
                        elif "Medium" in detail or "suspicious" in detail.lower():
                            st.warning(f"⚠️ {detail}")
                        else:
                            st.info(f"ℹ️ {detail}")
                            
            st.divider()
            st.markdown("### Recommendation")
            if score >= 80:
                st.success("You can safely proceed to this website.")
            elif score >= 50:
                st.warning("Proceed with caution. Do not enter sensitive information unless you are certain.")
            else:
                st.error("Do not visit this link. It is highly likely to be a phishing or scam attempt.")
    else:
        st.warning("Please enter a URL to scan.")
