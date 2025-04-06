from flask import Blueprint

bp = Blueprint('medical_history', __name__, url_prefix='/medical_history')

# Import routes after blueprint creation to avoid circular imports
from app.medical_history import routes
