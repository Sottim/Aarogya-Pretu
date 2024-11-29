from flask import Blueprint

bp = Blueprint('main', __name__)

from . import routes  # Import at the bottom to avoid circular imports
