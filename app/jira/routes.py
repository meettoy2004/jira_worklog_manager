from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models import JiraInstance
from app.jira.forms import JiraInstanceForm
from app.jira import jira_bp
import requests
import urllib3
import base64
import logging

logger = logging.getLogger(__name__)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def make_jira_api_call(instance, endpoint, method='GET', data=None):
    """Make direct API calls to Jira REST API v3 with username/password authentication"""
    try:
        # Prepare authentication with username/password
        auth_string = f"{instance.jira_username}:{instance.get_jira_password()}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()

        headers = {
            'Authorization': f'Basic {encoded_auth}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        url = f"{instance.base_url}/rest/api/3{endpoint}"

        logger.info(f"Making {method} request to: {url}")

        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=30, verify=False)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data, timeout=30, verify=False)
        else:
            response = requests.get(url, headers=headers, timeout=30, verify=False)

        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"API call failed: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        logger.error(f"API call error: {e}")
        return None


@jira_bp.route('/jira-instances')
@login_required
def jira_instances():
    instances = JiraInstance.query.filter_by(user_id=current_user.id).all()
    return render_template('jira_instances.html', instances=instances)


@jira_bp.route('/add-jira-instance', methods=['GET', 'POST'])
@login_required
def add_jira_instance():
    form = JiraInstanceForm()
    if form.validate_on_submit():
        # Check if alias already exists for this user
        existing = JiraInstance.query.filter_by(
            user_id=current_user.id,
            alias=form.alias.data
        ).first()
        if existing:
            flash('An instance with this name already exists.', 'error')
            return render_template('add_jira_instance.html', form=form)

        # Create new Jira instance with password
        jira_instance = JiraInstance(
            user_id=current_user.id,
            alias=form.alias.data,
            base_url=form.base_url.data.rstrip('/'),
            jira_username=form.jira_username.data,
            is_active=form.is_active.data
        )
        jira_instance.set_jira_password(form.jira_password.data)

        db.session.add(jira_instance)
        db.session.commit()
        flash('Jira instance added successfully!', 'success')
        return redirect(url_for('jira.jira_instances'))

    return render_template('add_jira_instance.html', form=form)


@jira_bp.route('/edit-jira-instance/<int:instance_id>', methods=['GET', 'POST'])
@login_required
def edit_jira_instance(instance_id):
    instance = JiraInstance.query.filter_by(
        id=instance_id,
        user_id=current_user.id
    ).first_or_404()

    form = JiraInstanceForm(obj=instance)

    if form.validate_on_submit():
        instance.alias = form.alias.data
        instance.base_url = form.base_url.data.rstrip('/')
        instance.jira_username = form.jira_username.data
        instance.is_active = form.is_active.data

        # Only update password if a new one was provided
        if form.jira_password.data and form.jira_password.data != "********":
            instance.set_jira_password(form.jira_password.data)

        db.session.commit()
        flash('Jira instance updated successfully!', 'success')
        return redirect(url_for('jira.jira_instances'))

    # Set a placeholder for the password field
    form.jira_password.data = "********"
    return render_template('edit_jira_instance.html', form=form, instance=instance)


@jira_bp.route('/delete-jira-instance/<int:instance_id>')
@login_required
def delete_jira_instance(instance_id):
    instance = JiraInstance.query.filter_by(
        id=instance_id,
        user_id=current_user.id
    ).first_or_404()

    db.session.delete(instance)
    db.session.commit()
    flash('Jira instance deleted successfully!', 'success')
    return redirect(url_for('jira.jira_instances'))


@jira_bp.route('/test-connection/<int:instance_id>')
@login_required
def test_connection(instance_id):
    """Test Jira connection for debugging with username/password"""
    instance = JiraInstance.query.filter_by(
        id=instance_id,
        user_id=current_user.id
    ).first_or_404()

    try:
        # Test with API v3
        server_info = make_jira_api_call(instance, '/serverInfo')

        if server_info:
            return f"""
            ✅ Connection successful (Username/Password)<br>
            ✅ Jira Server: {server_info.get('serverTitle', 'Unknown')}<br>
            ✅ Version: {server_info.get('version', 'Unknown')}<br>
            ✅ API Version: 3<br>
            <br>
            <strong>Note:</strong> Connected using username/password authentication.
            """
        else:
            return f"❌ Connection failed - could not reach Jira API v3<br>"

    except Exception as e:
        return f"❌ Connection test failed: {str(e)}<br>"


@jira_bp.route('/import-worklogs/<int:instance_id>')
@login_required
def import_worklogs(instance_id):
    """Import worklogs from Jira instance using API v3"""
    instance = JiraInstance.query.filter_by(
        id=instance_id,
        user_id=current_user.id
    ).first_or_404()

    try:
        from datetime import datetime, timedelta

        # Get worklogs from the last 30 days
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        start_str = start_date.strftime('%Y-%m-%d')

        logger.info(f"Importing worklogs from {instance.alias} since {start_str}")

        # Use API v3 to search for issues with worklogs
        jql = f'updated >= "{start_str}" ORDER BY updated DESC'

        search_data = {
            'jql': jql,
            'maxResults': 100,
            'fields': ['key', 'summary', 'project']
        }

        result = make_jira_api_call(instance, '/search/jql', 'POST', search_data)

        if not result:
            flash(f'Failed to import worklogs from {instance.alias}. Could not connect to Jira API.', 'error')
            logger.error(f"API call failed for {instance.alias}")
            return redirect(url_for('jira.jira_instances'))

        total_issues = result.get('total', 0)
        issues = result.get('issues', [])

        logger.info(f"Found {total_issues} issues from {instance.alias}")

        worklog_count = 0
        for issue_data in issues:
            issue_key = issue_data['key']

            # Get worklogs for this issue
            worklogs_result = make_jira_api_call(instance, f'/issue/{issue_key}/worklog')
            if worklogs_result:
                worklogs = worklogs_result.get('worklogs', [])
                for worklog in worklogs:
                    author_email = worklog['author'].get('emailAddress', '')
                    if author_email.lower() == instance.jira_username.lower():
                        worklog_count += 1

        flash(f'Successfully imported {worklog_count} worklogs from {total_issues} issues in {instance.alias}!',
              'success')
        logger.info(f"Import complete: {worklog_count} worklogs from {instance.alias}")

    except Exception as e:
        logger.error(f"Error importing worklogs: {str(e)}")
        flash(f'Error importing worklogs from {instance.alias}: {str(e)}', 'error')

    return redirect(url_for('jira.jira_instances'))