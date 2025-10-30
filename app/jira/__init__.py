from flask import Blueprint

jira_bp = Blueprint('jira', __name__)

from app.jira import routes