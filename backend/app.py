from flask import Flask, request, jsonify
from flask_cors import CORS
from models import db
from config import Config
import os

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    CORS(app)
    db.init_app(app)
    
    with app.app_context():
        db.create_all()

    # Register Blueprints / Routes
    from routes.scan_routes import scan_bp
    from routes.chat_routes import chat_bp
    
    app.register_blueprint(scan_bp, url_prefix='/api/scan')
    app.register_blueprint(chat_bp, url_prefix='/api/chat')

    @app.route('/api/health', methods=['GET'])
    def health_check():
        from ai_engines.url_analyzer import url_model
        from config import Config
        return jsonify({
            'status': 'healthy',
            'message': 'PhantomShield API is running',
            'ml_model_loaded': url_model is not None,
            'groq_configured': bool(Config.GROQ_API_KEY),
            'virustotal_configured': bool(Config.VIRUSTOTAL_API_KEY),
        })

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000)
