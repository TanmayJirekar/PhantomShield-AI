from flask import Blueprint, request, jsonify
from config import Config
import os

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

chat_bp = Blueprint('chat', __name__)

@chat_bp.route('/ask', methods=['POST'])
def ask_assistant():
    data = request.json
    user_message = data.get('message')
    
    if not user_message:
        return jsonify({"error": "Message is required"}), 400
        
    api_key = data.get('api_key') or Config.GROQ_API_KEY
    
    if GROQ_AVAILABLE and api_key:
        try:
            client = Groq(api_key=api_key)
            completion = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are PhantomShield AI, an advanced cybersecurity assistant. You help users identify scams, phishing attempts, and provide advice on staying safe online. Keep responses concise and professional."},
                    {"role": "user", "content": user_message}
                ],
                temperature=0.5,
                max_tokens=500,
                top_p=1,
                stream=False,
                stop=None,
            )
            return jsonify({"reply": completion.choices[0].message.content})
        except Exception as e:
            return jsonify({"error": str(e), "reply": "I am currently offline or experiencing issues connecting to the brain module. Please try again later."})
    else:
        # Fallback response if no Groq API Key
        return jsonify({"reply": "Hello! I am PhantomShield AI. I currently cannot connect to my intelligence engine because the GROQ_API_KEY is not set. However, I can still tell you that you should always check the URL carefully before entering any personal information!"})
