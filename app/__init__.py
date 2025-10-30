from flask import Flask, redirect, url_for, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_required, current_user
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)

    # Import inside create_app to avoid circular imports
    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from app.auth.routes import auth
    app.register_blueprint(auth)

    from app.jira.routes import jira_bp
    app.register_blueprint(jira_bp, url_prefix='/jira')

    from app.worklog.routes import worklog_bp
    app.register_blueprint(worklog_bp, url_prefix='/worklog')

    from app.reports.routes import reports_bp
    app.register_blueprint(reports_bp, url_prefix='/reports')

    # Add basic routes
    @app.route('/')
    def index():
        return redirect(url_for('auth.login'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        from app.models import JiraInstance
        instances = JiraInstance.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard.html', instances=instances)

    return app