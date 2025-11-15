from flask import Blueprint

manager = Blueprint('manager', __name__, url_prefix='/manager')

from app.manager import routes, forms
