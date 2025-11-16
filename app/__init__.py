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
        from datetime import datetime, timedelta
        import requests
        import base64
        import logging

        logger = logging.getLogger(__name__)

        instances = JiraInstance.query.filter_by(user_id=current_user.id).all()
        pending_invites = current_user.get_pending_invites()

        # Fetch worklog statistics for the last 30 days
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=30)

        weekly_stats = {
            'total_time_seconds': 0,
            'total_worklogs': 0,
            'days_logged': 0,
            'daily_breakdown': {},
            'project_breakdown': {}
        }

        # Fetch worklogs from all active instances
        for instance in instances:
            if not instance.is_active:
                continue

            try:
                # Build JQL query
                jql = f'worklogAuthor = currentUser() AND worklogDate >= "{start_date}" AND worklogDate <= "{end_date}"'

                url = f"{instance.base_url}/rest/api/3/search/jql"
                params = {
                    'jql': jql,
                    'fields': 'summary,project,worklog',
                    'maxResults': 1000
                }

                auth_string = f"{instance.jira_username}:{instance.get_jira_password()}"
                auth_bytes = base64.b64encode(auth_string.encode()).decode()

                headers = {
                    'Authorization': f'Basic {auth_bytes}',
                    'Content-Type': 'application/json'
                }

                response = requests.get(url, params=params, headers=headers, verify=False, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    issues = data.get('issues', [])

                    for issue in issues:
                        worklog_data = issue['fields'].get('worklog', {})
                        worklogs = worklog_data.get('worklogs', [])
                        project_key = issue['fields']['project']['key']

                        for wl in worklogs:
                            started = wl.get('started', '')
                            worklog_date = started.split('T')[0]

                            # Check if within date range
                            if start_date.isoformat() <= worklog_date <= end_date.isoformat():
                                time_seconds = wl.get('timeSpentSeconds', 0)
                                weekly_stats['total_time_seconds'] += time_seconds
                                weekly_stats['total_worklogs'] += 1

                                # Daily breakdown
                                if worklog_date not in weekly_stats['daily_breakdown']:
                                    weekly_stats['daily_breakdown'][worklog_date] = 0
                                weekly_stats['daily_breakdown'][worklog_date] += time_seconds

                                # Project breakdown
                                if project_key not in weekly_stats['project_breakdown']:
                                    weekly_stats['project_breakdown'][project_key] = 0
                                weekly_stats['project_breakdown'][project_key] += time_seconds

            except Exception as e:
                logger.error(f"Error fetching worklogs from {instance.alias}: {str(e)}")
                continue

        # Calculate days logged
        weekly_stats['days_logged'] = len(weekly_stats['daily_breakdown'])

        # Format time
        total_hours = weekly_stats['total_time_seconds'] // 3600
        total_minutes = (weekly_stats['total_time_seconds'] % 3600) // 60
        weekly_stats['total_time_formatted'] = f"{total_hours}h {total_minutes}m"

        # Calculate average per day
        if weekly_stats['days_logged'] > 0:
            avg_seconds = weekly_stats['total_time_seconds'] / weekly_stats['days_logged']
            avg_hours = int(avg_seconds // 3600)
            avg_minutes = int((avg_seconds % 3600) // 60)
            weekly_stats['avg_per_day'] = f"{avg_hours}h {avg_minutes}m"
        else:
            weekly_stats['avg_per_day'] = "0h 0m"

        return render_template('dashboard.html',
                             instances=instances,
                             pending_invites=pending_invites,
                             weekly_stats=weekly_stats,
                             start_date=start_date,
                             end_date=end_date)

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