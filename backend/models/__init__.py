from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    scans = db.relationship('ScanHistory', backref='author', lazy='dynamic')

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50)) # 'URL', 'QR', 'TEXT', 'CV'
    target = db.Column(db.String(500)) # The URL, text, or filename
    risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(20)) # 'Low', 'Medium', 'High', 'Critical'
    details = db.Column(db.Text) # JSON string of detailed analysis
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class ThreatReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_domain = db.Column(db.String(200), index=True)
    threat_type = db.Column(db.String(50)) # 'Phishing', 'Malware', 'Scam'
    source = db.Column(db.String(50)) # 'Community', 'AI', 'External'
    reported_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=False)
