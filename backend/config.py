import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'super-secret-key-phantomshield'
    
    # SQLite Database configuration for MVP
    basedir = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'phantomshield.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # External API Keys (Can be set in .env)
    GROQ_API_KEY = os.environ.get('GROQ_API_KEY')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
