from flask import Blueprint

worklog_bp = Blueprint('worklog', __name__)

from app.worklog import routes
