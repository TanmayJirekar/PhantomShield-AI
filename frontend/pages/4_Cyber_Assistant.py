import streamlit as st
import sys
import os

# Add parent dir to path to import utils
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.api_client import chat_with_assistant

st.set_page_config(page_title="Cyber Assistant - PhantomShield AI", page_icon="💬", layout="wide")

st.title("💬 AI Cyber Assistant")
st.markdown("Ask questions about online security, scams, or how to identify phishing attempts.")

# Sidebar for API Key
st.sidebar.markdown("### Settings")
groq_api_key = st.sidebar.text_input("Groq API Key (Optional)", type="password", help="Enter your Groq API key if it is not set in the backend environment.")

if "messages" not in st.session_state:
    st.session_state.messages = [
        {"role": "assistant", "content": "Hello! I am PhantomShield AI. How can I help you stay safe online today?"}
    ]

# Display chat messages from history on app rerun
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# React to user input
if prompt := st.chat_input("Ask about phishing, secure passwords, or scam detection..."):
    # Display user message in chat message container
    st.chat_message("user").markdown(prompt)
    # Add user message to chat history
    st.session_state.messages.append({"role": "user", "content": prompt})

    # Get assistant response
    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            response = chat_with_assistant(prompt, api_key=groq_api_key if groq_api_key else None)
            if response and "reply" in response:
                assistant_reply = response["reply"]
            else:
                assistant_reply = "I'm having trouble connecting to my intelligence core right now."
            st.markdown(assistant_reply)
            
    # Add assistant response to chat history
    st.session_state.messages.append({"role": "assistant", "content": assistant_reply})
