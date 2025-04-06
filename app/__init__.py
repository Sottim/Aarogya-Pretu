from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from dotenv import load_dotenv
from flask_bootstrap import Bootstrap

# Load environment variables from .env file FIRST
load_dotenv()

from config import Config

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
bootstrap = Bootstrap()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    bootstrap.init_app(app)
    login_manager.login_view = 'auth.login'

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

    return app
