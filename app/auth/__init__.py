from flask import Blueprint

bp = Blueprint('auth', __name__)

from .routes import bp