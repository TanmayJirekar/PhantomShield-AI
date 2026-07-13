import streamlit as st
import sys
import os
from PIL import Image

# Add parent dir to path to import utils
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.api_client import scan_qr

st.set_page_config(page_title="QR Scanner - PhantomShield AI", page_icon="📱", layout="wide")

st.title("📱 AI QR Code Scanner")
st.markdown("Upload a QR code to decode and analyze its destination for threats.")

uploaded_file = st.file_uploader("Upload QR Code Image", type=['png', 'jpg', 'jpeg'])

if uploaded_file is not None:
    # Display the uploaded image
    st.image(uploaded_file, caption="Uploaded QR Code", width=300)
    
    if st.button("Analyze QR Code", type="primary"):
        with st.spinner("Decoding and Analyzing..."):
            result = scan_qr(uploaded_file)
            
        if result:
            if not result.get("success"):
                st.error(f"❌ {result.get('message', 'Failed to decode QR code.')}")
                st.info("💡 Make sure the image contains a clear, well-lit QR code. Cropping the image to just the QR code might help.")
            else:
                st.success("QR Code Decoded Successfully!")
                
                qr_type = result.get("type", "Unknown")
                extracted_data = result.get("extracted_data", "")
                
                st.markdown(f"**Content Type:** {qr_type}")
                st.markdown(f"**Extracted Data:** `{extracted_data}`")
                
                if "analysis" in result:
                    analysis = result["analysis"]
                    
                    st.divider()
                    st.subheader("Destination Threat Analysis")
                    
                    col1, col2 = st.columns([1, 2])
                    
                    with col1:
                        score = analysis.get("trust_score", 0)
                        risk_level = analysis.get("risk_level", "Unknown")
                        
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
                        details = analysis.get("details", [])
                        if not details:
                            st.info("✅ Destination appears to be safe.")
                        else:
                            for detail in details:
                                if "High Risk" in detail or "Critical" in detail:
                                    st.error(f"⚠️ {detail}")
                                else:
                                    st.warning(f"⚠️ {detail}")
