from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from dotenv import load_dotenv
from flask_bootstrap import Bootstrap
from flask_mail import Mail

# Load environment variables from .env file FIRST
load_dotenv()

from config import config

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
bootstrap = Bootstrap()

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    bootstrap.init_app(app)
    login_manager.login_view = 'auth.login'

    # Initialize Flask-Mail
    mail = Mail(app)

    # Import models after db is initialized with app
    from app import models

    # Register blueprints
    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    from app.doctor import bp as doctor_bp
    app.register_blueprint(doctor_bp)

    # Register Medical History blueprint
    from app.medical_history import bp as medical_history_bp
    app.register_blueprint(medical_history_bp)

        # Configure logging
    if not app.debug:
        import logging
        from logging.handlers import RotatingFileHandler
        
        file_handler = RotatingFileHandler('app.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        
        app.logger.setLevel(logging.INFO)
        app.logger.info('Aarogya Pretu startup')
    
    return app