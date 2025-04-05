import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
# This is useful for local development
basedir = os.path.abspath(os.path.dirname(__file__))
dotenv_path = os.path.join(basedir, '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)


class Config:
    """Set Flask configuration variables from environment variables."""

    # General Config
    # IMPORTANT: Set a strong SECRET_KEY in your production environment variables!
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-default-fallback-secret-key-for-dev-only'
    FLASK_APP = os.environ.get('FLASK_APP') or 'wsgi.py'
    # Set FLASK_ENV=production in your production environment
    FLASK_ENV = os.environ.get('FLASK_ENV') or 'development'
    DEBUG = FLASK_ENV == 'development' # Enable debug mode only if FLASK_ENV is 'development'

    # Database
    # Use DATABASE_URL from environment if available (for production PostgreSQL)
    # Otherwise use a default SQLite database in an 'instance' folder for local development
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    if not SQLALCHEMY_DATABASE_URI:
        INSTANCE_FOLDER_PATH = os.path.join(basedir, 'instance')
        # Ensure the instance folder exists for SQLite
        if not os.path.exists(INSTANCE_FOLDER_PATH):
            try:
                os.makedirs(INSTANCE_FOLDER_PATH)
                print(f"Created instance folder at: {INSTANCE_FOLDER_PATH}")
            except OSError as e:
                print(f"Error creating instance folder {INSTANCE_FOLDER_PATH}: {e}")
        SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(INSTANCE_FOLDER_PATH, 'app.db')

    SQLALCHEMY_TRACK_MODIFICATIONS = False

# You could add other configurations like TestingConfig, ProductionConfig
# inheriting from this base Config if needed for more complex setups.
# Example:
# class ProductionConfig(Config):
#     FLASK_ENV = 'production'
#     DEBUG = False
#     # Add production specific settings here if any