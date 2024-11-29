from flask import Blueprint

bp = Blueprint('doctor', __name__)

from . import routes  # Import at the bottom to avoid circular imports
