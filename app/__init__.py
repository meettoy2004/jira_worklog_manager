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

    from app.admin import admin
    app.register_blueprint(admin)

    from app.manager import manager
    app.register_blueprint(manager)

    # Add basic routes
    @app.route('/')
    def index():
        return redirect(url_for('auth.login'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        from app.models import JiraInstance, TeamInvite
        instances = JiraInstance.query.filter_by(user_id=current_user.id).all()
        pending_invites = current_user.get_pending_invites()
        return render_template('dashboard.html', instances=instances, pending_invites=pending_invites)

    @app.route('/accept-invite/<int:invite_id>')
    @login_required
    def accept_invite(invite_id):
        from app.models import TeamInvite
        from flask import flash
        from datetime import datetime

        invite = TeamInvite.query.get_or_404(invite_id)

        # Verify this invite is for the current user
        if invite.member_id != current_user.id:
            flash('You do not have permission to accept this invite.', 'danger')
            return redirect(url_for('dashboard'))

        if invite.status != 'pending':
            flash('This invite has already been processed.', 'info')
            return redirect(url_for('dashboard'))

        invite.status = 'accepted'
        invite.responded_at = datetime.utcnow()
        db.session.commit()

        flash(f'You have accepted the team invite from {invite.manager.username}.', 'success')
        return redirect(url_for('dashboard'))

    @app.route('/reject-invite/<int:invite_id>')
    @login_required
    def reject_invite(invite_id):
        from app.models import TeamInvite
        from flask import flash
        from datetime import datetime

        invite = TeamInvite.query.get_or_404(invite_id)

        # Verify this invite is for the current user
        if invite.member_id != current_user.id:
            flash('You do not have permission to reject this invite.', 'danger')
            return redirect(url_for('dashboard'))

        if invite.status != 'pending':
            flash('This invite has already been processed.', 'info')
            return redirect(url_for('dashboard'))

        invite.status = 'rejected'
        invite.responded_at = datetime.utcnow()
        db.session.commit()

        flash(f'You have rejected the team invite from {invite.manager.username}.', 'info')
        return redirect(url_for('dashboard'))

    return app