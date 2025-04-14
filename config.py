import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
dotenv_path = os.path.join(basedir, '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)

class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-default-fallback-secret-key-for-dev-only'
    FLASK_APP = os.environ.get('FLASK_APP') or 'wsgi.py'
    FLASK_ENV = os.environ.get('FLASK_ENV') or 'development'
    DEBUG = FLASK_ENV == 'development'
    
    # Mail Configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
    
    # Frontend URL Configuration
    FRONTEND_URL = os.environ.get('FRONTEND_URL')
    if not FRONTEND_URL:
        FRONTEND_URL = 'http://localhost:5000' if FLASK_ENV == 'development' else 'https://aarogya-pretu.vercel.app/'
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    if not SQLALCHEMY_DATABASE_URI:
        # Only use SQLite for development
        if FLASK_ENV == 'development':
            INSTANCE_FOLDER_PATH = os.path.join(basedir, 'instance')
            if not os.path.exists(INSTANCE_FOLDER_PATH):
                try:
                    os.makedirs(INSTANCE_FOLDER_PATH)
                    print(f"Created instance folder at: {INSTANCE_FOLDER_PATH}")
                except OSError as e:
                    print(f"Error creating instance folder {INSTANCE_FOLDER_PATH}: {e}")
            SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(INSTANCE_FOLDER_PATH, 'app.db')
        else:
            # For production, we must have a DATABASE_URL set
            raise ValueError("DATABASE_URL must be set for production environment")
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or Config.SQLALCHEMY_DATABASE_URI
    FRONTEND_URL = 'https://aarogya-pretu.vercel.app/'
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}