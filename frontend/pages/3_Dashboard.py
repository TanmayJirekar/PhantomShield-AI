import streamlit as st
import sys
import os
import pandas as pd
import plotly.express as px

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.api_client import get_scan_history, get_health

st.set_page_config(page_title="Dashboard - PhantomShield AI", page_icon="📊", layout="wide")

st.title("📊 Security Dashboard")
st.markdown("Overview of recent scanning activity and threats detected.")

col_title, col_refresh = st.columns([8, 1])
with col_refresh:
    if st.button("🔄 Refresh", use_container_width=True):
        st.rerun()

health = get_health()
if health:
    status_cols = st.columns(4)
    with status_cols[0]:
        st.metric("API Status", "Online" if health.get('status') == 'healthy' else "Offline")
    with status_cols[1]:
        st.metric("ML Model", "Loaded" if health.get('ml_model_loaded') else "Heuristic Mode")
    with status_cols[2]:
        st.metric("Groq AI", "Ready" if health.get('groq_configured') else "Not Set")
    with status_cols[3]:
        st.metric("VirusTotal", "Ready" if health.get('virustotal_configured') else "Not Set")
    st.divider()

history_data = get_scan_history(limit=50)
history = history_data.get("history", [])

if not history:
    st.info("No scan history available yet. Start scanning to see analytics here!")
else:
    df = pd.DataFrame(history)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Scans", len(df))
    with col2:
        high_risk = len(df[df['risk_level'].isin(['High', 'Critical'])])
        st.metric("Threats Detected", high_risk)
    with col3:
        avg_danger = int(df['danger_score'].mean())
        st.metric("Avg Threat Score", f"{avg_danger}/100")
    with col4:
        url_scans = len(df[df['type'] == 'URL'])
        st.metric("URL Scans", url_scans)

    st.divider()

    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.subheader("Scans by Type")
        type_counts = df['type'].value_counts().reset_index()
        type_counts.columns = ['Scan Type', 'Count']
        fig = px.pie(type_counts, values='Count', names='Scan Type', hole=0.4, color_discrete_sequence=px.colors.sequential.Teal)
        st.plotly_chart(fig, use_container_width=True)

    with col_chart2:
        st.subheader("Risk Level Distribution")
        risk_counts = df['risk_level'].value_counts().reset_index()
        risk_counts.columns = ['Risk Level', 'Count']
        color_map = {'Low': 'green', 'Medium': 'orange', 'High': 'red', 'Critical': 'darkred', 'Unknown': 'gray'}
        fig = px.bar(risk_counts, x='Risk Level', y='Count', color='Risk Level', color_discrete_map=color_map)
        st.plotly_chart(fig, use_container_width=True)

    st.divider()
    st.subheader("Recent Scan Log")
    display_df = df[['timestamp', 'type', 'target', 'danger_score', 'risk_level']].copy()
    display_df.columns = ['Timestamp', 'Type', 'Target', 'Threat Score', 'Risk Level']
    st.dataframe(display_df, use_container_width=True)
