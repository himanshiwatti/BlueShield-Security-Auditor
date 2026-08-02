import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'blueshield-auditor-secure-key-2026')
    DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database', 'blueshield.db')
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'exports')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
