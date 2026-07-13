import streamlit as st
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.api_client import scan_text

st.set_page_config(page_title="Text Scam Scanner - PhantomShield AI", page_icon="💬", layout="wide")

st.title("💬 Text Scam Scanner")
st.markdown("Paste suspicious SMS, email, or message text to detect scam patterns and hidden malicious links.")

text_input = st.text_area(
    "Paste message text here",
    height=200,
    placeholder="Example: URGENT! Your bank account has been suspended. Click here to verify: http://fake-bank-login.com",
)

col1, col2 = st.columns([1, 4])
with col1:
    scan_btn = st.button("Analyze Text", type="primary", use_container_width=True)

if scan_btn:
    if text_input.strip():
        with st.spinner("Analyzing text for scam patterns..."):
            result = scan_text(text_input)

        if result:
            st.success("Analysis Complete!")

            col_score, col_report = st.columns([1, 2])

            with col_score:
                danger = result.get('danger_score', result.get('scam_probability', 0))
                risk_level = result.get('risk_level', 'Unknown')

                if danger >= 70:
                    color = 'red'
                elif danger >= 40:
                    color = 'orange'
                elif danger >= 20:
                    color = 'gold'
                else:
                    color = 'green'

                st.markdown(f"""
                <div style="text-align: center; padding: 20px; border-radius: 10px; border: 2px solid {color};">
                    <h1 style="color: {color}; margin: 0; font-size: 60px;">{danger}/100</h1>
                    <h3 style="color: {color}; margin: 0;">Threat Level: {risk_level}</h3>
                    <p style="color: #888;">Higher = more dangerous</p>
                </div>
                """, unsafe_allow_html=True)

            with col_report:
                st.subheader("Findings")
                findings = result.get('findings', [])
                if not findings:
                    st.info("No suspicious patterns detected.")
                else:
                    for finding in findings:
                        if any(w in finding.lower() for w in ['urgency', 'impersonation', 'suspicious', 'malicious']):
                            st.error(f"⚠️ {finding}")
                        elif 'detected' in finding.lower():
                            st.warning(f"⚠️ {finding}")
                        else:
                            st.info(f"ℹ️ {finding}")

            embedded = result.get('embedded_urls', [])
            if embedded:
                st.divider()
                st.subheader("Embedded URLs Detected")
                for url in embedded:
                    st.code(url)

            st.divider()
            if danger >= 70:
                st.error("This message shows strong signs of a scam. Do not respond, click links, or share personal information.")
            elif danger >= 40:
                st.warning("This message contains suspicious patterns. Verify through official channels before acting.")
            else:
                st.success("No major scam indicators found, but always stay cautious with unsolicited messages.")
    else:
        st.warning("Please paste some text to analyze.")
