from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from app.manager import manager
from app import db
from app.models import User, TeamInvite, JiraInstance
from app.decorators import manager_required
from app.manager.forms import InviteMemberForm
import logging
import requests
from requests.auth import HTTPBasicAuth
import base64
import json

logger = logging.getLogger(__name__)


@manager.route('/dashboard')
@login_required
@manager_required
def dashboard():
    """Manager dashboard showing team members and pending invites"""
    # Get all team members (accepted invites)
    team_members = current_user.get_team_members()

    # Get pending invites sent by this manager
    pending_invites = TeamInvite.query.filter_by(
        manager_id=current_user.id,
        status='pending'
    ).all()

    # Get rejected invites
    rejected_invites = TeamInvite.query.filter_by(
        manager_id=current_user.id,
        status='rejected'
    ).all()

    # Get accepted invites
    accepted_invites = TeamInvite.query.filter_by(
        manager_id=current_user.id,
        status='accepted'
    ).all()

    # Create invite form
    form = InviteMemberForm()

    # Get all users except current user, admins, and already invited users
    existing_member_ids = [invite.member_id for invite in TeamInvite.query.filter_by(manager_id=current_user.id).all()]
    available_users = User.query.filter(
        User.id != current_user.id,
        User.id.notin_(existing_member_ids)
    ).all()

    form.member_id.choices = [(user.id, user.username) for user in available_users]

    return render_template('manager/dashboard.html',
                          team_members=team_members,
                          pending_invites=pending_invites,
                          rejected_invites=rejected_invites,
                          accepted_invites=accepted_invites,
                          form=form)


@manager.route('/invite-member', methods=['POST'])
@login_required
@manager_required
def invite_member():
    """Send team invite to a user"""
    form = InviteMemberForm()

    # Populate choices
    existing_member_ids = [invite.member_id for invite in TeamInvite.query.filter_by(manager_id=current_user.id).all()]
    available_users = User.query.filter(
        User.id != current_user.id,
        User.id.notin_(existing_member_ids)
    ).all()
    form.member_id.choices = [(user.id, user.username) for user in available_users]

    if form.validate_on_submit():
        member_id = form.member_id.data

        # Check if invite already exists
        existing_invite = TeamInvite.query.filter_by(
            manager_id=current_user.id,
            member_id=member_id
        ).first()

        if existing_invite:
            flash('You have already sent an invite to this user.', 'warning')
        else:
            invite = TeamInvite(
                manager_id=current_user.id,
                member_id=member_id
            )
            db.session.add(invite)
            db.session.commit()

            member = User.query.get(member_id)
            flash(f'Team invite sent to {member.username}.', 'success')

    return redirect(url_for('manager.dashboard'))


@manager.route('/remove-member/<int:invite_id>')
@login_required
@manager_required
def remove_member(invite_id):
    """Remove a team member"""
    invite = TeamInvite.query.get_or_404(invite_id)

    # Verify this invite belongs to the current manager
    if invite.manager_id != current_user.id:
        flash('You do not have permission to remove this member.', 'danger')
        return redirect(url_for('manager.dashboard'))

    member_username = invite.member.username
    db.session.delete(invite)
    db.session.commit()

    flash(f'{member_username} has been removed from your team.', 'success')
    return redirect(url_for('manager.dashboard'))


@manager.route('/team-reports')
@login_required
@manager_required
def team_reports():
    """View team member worklogs and reports"""
    # Get filter parameters
    filter_type = request.args.get('filter', 'today')
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    selected_member_id = request.args.get('member_id', type=int)

    # Calculate date range
    today = datetime.now().date()
    if filter_type == 'today':
        start_date = today
        end_date = today
    elif filter_type == 'yesterday':
        start_date = today - timedelta(days=1)
        end_date = today - timedelta(days=1)
    elif filter_type == '7days':
        start_date = today - timedelta(days=7)
        end_date = today
    elif filter_type == '30days':
        start_date = today - timedelta(days=30)
        end_date = today
    elif filter_type == '90days':
        start_date = today - timedelta(days=90)
        end_date = today
    elif filter_type == 'custom' and start_date_str and end_date_str:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
    else:
        start_date = today
        end_date = today

    # Get team members
    team_members = current_user.get_team_members()

    if not team_members:
        flash('You do not have any team members yet.', 'info')
        return render_template('manager/team_reports.html',
                             team_members=[],
                             worklogs=[],
                             daily_totals={},
                             project_totals={},
                             instance_totals={},
                             grand_total_seconds=0,
                             start_date=start_date,
                             end_date=end_date,
                             filter_type=filter_type,
                             selected_member_id=selected_member_id)

    # Filter by selected member if specified
    if selected_member_id:
        members_to_query = [member for member in team_members if member.id == selected_member_id]
        if not members_to_query:
            flash('Selected member is not in your team.', 'warning')
            members_to_query = team_members
    else:
        members_to_query = team_members

    # Collect all worklogs
    all_worklogs = []

    for member in members_to_query:
        # Get all active Jira instances for this member
        jira_instances = JiraInstance.query.filter_by(user_id=member.id, is_active=True).all()

        for instance in jira_instances:
            try:
                # Fetch worklogs from Jira for this member
                worklogs = fetch_member_worklogs(instance, member.username, start_date, end_date)
                all_worklogs.extend(worklogs)
            except Exception as e:
                logger.error(f"Error fetching worklogs from {instance.alias}: {str(e)}")

    # Sort worklogs by date (newest first)
    all_worklogs.sort(key=lambda x: x['started'], reverse=True)

    # Calculate totals
    daily_totals = {}
    project_totals = {}
    instance_totals = {}
    grand_total_seconds = 0

    for worklog in all_worklogs:
        date_key = worklog['started'].split('T')[0]
        project_key = worklog.get('project_key', 'Unknown')
        instance_name = worklog.get('instance_alias', 'Unknown')
        time_seconds = worklog.get('timeSpentSeconds', 0)

        # Daily totals
        daily_totals[date_key] = daily_totals.get(date_key, 0) + time_seconds

        # Project totals
        project_totals[project_key] = project_totals.get(project_key, 0) + time_seconds

        # Instance totals
        instance_totals[instance_name] = instance_totals.get(instance_name, 0) + time_seconds

        # Grand total
        grand_total_seconds += time_seconds

    return render_template('manager/team_reports.html',
                         team_members=team_members,
                         worklogs=all_worklogs,
                         daily_totals=daily_totals,
                         project_totals=project_totals,
                         instance_totals=instance_totals,
                         grand_total_seconds=grand_total_seconds,
                         start_date=start_date,
                         end_date=end_date,
                         filter_type=filter_type,
                         selected_member_id=selected_member_id)


def fetch_member_worklogs(instance, member_username, start_date, end_date):
    """Fetch worklogs for a team member from a Jira instance"""
    worklogs = []

    try:
        # Build JQL query for the date range and specific user
        jql = f'worklogAuthor = "{member_username}" AND worklogDate >= "{start_date}" AND worklogDate <= "{end_date}"'

        # Search for issues
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

        response = requests.get(url, params=params, headers=headers, verify=False)
        response.raise_for_status()

        data = response.json()
        issues = data.get('issues', [])

        for issue in issues:
            issue_key = issue['key']
            issue_summary = issue['fields']['summary']
            project_key = issue['fields']['project']['key']

            # Get worklogs for this issue
            worklog_data = issue['fields'].get('worklog', {})
            issue_worklogs = worklog_data.get('worklogs', [])

            # Filter worklogs by author and date
            for wl in issue_worklogs:
                author = wl.get('author', {}).get('displayName', '')
                started = wl.get('started', '')
                worklog_date = started.split('T')[0]

                # Check if worklog is within date range and by the member
                if (start_date.isoformat() <= worklog_date <= end_date.isoformat() and
                    wl.get('author', {}).get('emailAddress', '').startswith(member_username)):

                    # Extract comment text
                    comment_text = extract_comment_text(wl.get('comment', {}))

                    worklogs.append({
                        'issue_key': issue_key,
                        'issue_summary': issue_summary,
                        'project_key': project_key,
                        'started': started,
                        'timeSpentSeconds': wl.get('timeSpentSeconds', 0),
                        'timeSpent': wl.get('timeSpent', ''),
                        'comment': comment_text,
                        'author': author,
                        'instance_alias': instance.alias,
                        'member_username': member_username
                    })

    except Exception as e:
        logger.error(f"Error fetching worklogs for {member_username} from {instance.alias}: {str(e)}")

    return worklogs


def extract_comment_text(comment_obj):
    """Extract plain text from Atlassian Document Format"""
    if not comment_obj:
        return ''

    text_parts = []

    def extract_text(node):
        if isinstance(node, dict):
            if node.get('type') == 'text':
                text_parts.append(node.get('text', ''))
            if 'content' in node:
                for child in node['content']:
                    extract_text(child)

    extract_text(comment_obj)
    return ' '.join(text_parts)
