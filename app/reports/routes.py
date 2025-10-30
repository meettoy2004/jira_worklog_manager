from flask import render_template, request, jsonify
from flask_login import login_required, current_user
from app.models import JiraInstance
from app.reports import reports_bp
from datetime import datetime, timedelta
import requests
import logging
import base64
import urllib3

logger = logging.getLogger(__name__)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def make_jira_api_call(instance, endpoint, method='GET', data=None):
    """Make direct API calls to Jira REST API v3 with SSL handling"""
    try:
        # Prepare authentication
        auth_string = f"{instance.jira_username}:{instance.get_api_token()}"
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


def get_worklogs_for_period(instance, start_date, end_date):
    """Get worklogs for a specific instance within a date range using direct API v3"""
    try:
        # Format dates for JQL
        start_str = start_date.strftime('%Y-%m-%d')
        end_str = end_date.strftime('%Y-%m-%d')

        # Build JQL query to find worklogs in date range
        jql = f'worklogDate >= "{start_str}" AND worklogDate <= "{end_str}" AND worklogAuthor = currentUser()'

        logger.info(f"Searching worklogs with JQL: {jql}")

        # Use the search/jql endpoint with POST
        search_data = {
            'jql': jql,
            'maxResults': 100,
            'fields': ['key', 'summary', 'project']
        }

        result = make_jira_api_call(instance, '/search/jql', 'POST', search_data)

        if not result:
            return [], 0

        worklogs_data = []
        total_seconds = 0

        logger.info(f"Found {result.get('total', 0)} issues with worklogs in date range")

        for issue_data in result.get('issues', []):
            issue_key = issue_data['key']
            issue_summary = issue_data['fields']['summary']
            project_key = issue_data['fields']['project']['key']

            # Get worklogs for this issue
            worklogs_result = make_jira_api_call(instance, f'/issue/{issue_key}/worklog')
            if not worklogs_result:
                continue

            worklogs = worklogs_result.get('worklogs', [])
            logger.info(f"Found {len(worklogs)} worklogs for issue {issue_key}")

            for worklog in worklogs:
                worklog_date_str = worklog['started'][:10]
                worklog_date = datetime.strptime(worklog_date_str, '%Y-%m-%d').date()

                # Convert our search dates to date objects for comparison
                search_start_date = start_date.date() if isinstance(start_date, datetime) else start_date
                search_end_date = end_date.date() if isinstance(end_date, datetime) else end_date

                # Check if worklog is within our date range and by current user
                if search_start_date <= worklog_date <= search_end_date:
                    worklog_author_email = worklog['author'].get('emailAddress', '')

                    if worklog_author_email.lower() == instance.jira_username.lower():
                        # Convert time spent seconds to Jira format
                        time_spent_seconds = worklog['timeSpentSeconds']
                        hours = time_spent_seconds // 3600
                        minutes = (time_spent_seconds % 3600) // 60

                        time_spent_str = ""
                        if hours > 0:
                            time_spent_str += f"{hours}h"
                        if minutes > 0:
                            if time_spent_str:
                                time_spent_str += " "
                            time_spent_str += f"{minutes}m"

                        worklog_info = {
                            'instance': instance.alias,
                            'issue_key': issue_key,
                            'issue_summary': issue_summary,
                            'project': project_key,
                            'time_spent': time_spent_str,
                            'time_spent_seconds': time_spent_seconds,
                            'comment': worklog.get('comment', {}).get('content', [{}])[0].get('text',
                                                                                              'No description') if worklog.get(
                                'comment') else 'No description',
                            'date': worklog_date_str,
                            'started': worklog['started'],
                            'author': worklog_author_email
                        }

                        worklogs_data.append(worklog_info)
                        total_seconds += time_spent_seconds
                        logger.info(f"Found matching worklog: {issue_key} - {time_spent_str} on {worklog_date_str}")

        logger.info(f"Total worklogs found for {instance.alias}: {len(worklogs_data)}")
        return worklogs_data, total_seconds

    except Exception as e:
        logger.error(f"Error getting worklogs for {instance.alias}: {e}")
        return [], 0


def get_recent_worklogs_alternative(instance, days=7):
    """Alternative method: Get recent worklogs by checking recently updated issues"""
    try:
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        start_str = start_date.strftime('%Y-%m-%d')

        # Search for issues updated recently that might have worklogs
        jql = f'updated >= "{start_str}" AND reporter = currentUser()'

        search_data = {
            'jql': jql,
            'maxResults': 50,
            'fields': ['key', 'summary', 'project', 'updated']
        }

        result = make_jira_api_call(instance, '/search/jql', 'POST', search_data)

        if not result:
            return [], 0

        worklogs_data = []
        total_seconds = 0

        for issue_data in result.get('issues', []):
            issue_key = issue_data['key']

            # Get worklogs for this issue
            worklogs_result = make_jira_api_call(instance, f'/issue/{issue_key}/worklog')
            if not worklogs_result:
                continue

            worklogs = worklogs_result.get('worklogs', [])

            for worklog in worklogs:
                worklog_author_email = worklog['author'].get('emailAddress', '')
                if worklog_author_email.lower() == instance.jira_username.lower():
                    time_spent_seconds = worklog['timeSpentSeconds']
                    hours = time_spent_seconds // 3600
                    minutes = (time_spent_seconds % 3600) // 60

                    time_spent_str = ""
                    if hours > 0:
                        time_spent_str += f"{hours}h"
                    if minutes > 0:
                        if time_spent_str:
                            time_spent_str += " "
                        time_spent_str += f"{minutes}m"

                    worklog_info = {
                        'instance': instance.alias,
                        'issue_key': issue_key,
                        'issue_summary': issue_data['fields']['summary'],
                        'project': issue_data['fields']['project']['key'],
                        'time_spent': time_spent_str,
                        'time_spent_seconds': time_spent_seconds,
                        'comment': worklog.get('comment', {}).get('content', [{}])[0].get('text',
                                                                                          'No description') if worklog.get(
                            'comment') else 'No description',
                        'date': worklog['started'][:10],
                        'started': worklog['started']
                    }

                    worklogs_data.append(worklog_info)
                    total_seconds += time_spent_seconds

        return worklogs_data, total_seconds

    except Exception as e:
        logger.error(f"Alternative worklog search failed: {e}")
        return [], 0


@reports_bp.route('/reports')
@login_required
def reports_dashboard():
    # Get date range from request or default to last 7 days
    date_range = request.args.get('range', '7days')

    end_date = datetime.now()
    if date_range == 'today':
        start_date = end_date.replace(hour=0, minute=0, second=0, microsecond=0)
    elif date_range == 'yesterday':
        start_date = end_date - timedelta(days=1)
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = start_date.replace(hour=23, minute=59, second=59)
    elif date_range == '7days':
        start_date = end_date - timedelta(days=7)
    elif date_range == '30days':
        start_date = end_date - timedelta(days=30)
    elif date_range == '90days':
        start_date = end_date - timedelta(days=90)
    else:
        # Custom date range
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        if start_date_str and end_date_str:
            try:
                start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
            except ValueError:
                start_date = end_date - timedelta(days=7)
        else:
            start_date = end_date - timedelta(days=7)

    # Ensure we're working with datetime objects at start of day
    if isinstance(start_date, datetime):
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
    if isinstance(end_date, datetime):
        end_date = end_date.replace(hour=23, minute=59, second=59, microsecond=0)

    logger.info(f"Searching worklogs from {start_date} to {end_date}")

    # Get all active Jira instances for the user
    instances = JiraInstance.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).all()

    # Collect worklogs from all instances
    all_worklogs = []
    instance_totals = {}
    grand_total_seconds = 0

    for instance in instances:
        logger.info(f"Getting worklogs for instance: {instance.alias}")

        # Try the main worklog search
        worklogs, total_seconds = get_worklogs_for_period(instance, start_date, end_date)

        # If no worklogs found, try alternative method
        if not worklogs:
            logger.info(f"No worklogs found with main method, trying alternative for {instance.alias}")
            worklogs, total_seconds = get_recent_worklogs_alternative(instance, days=30)

        all_worklogs.extend(worklogs)

        if worklogs:
            instance_totals[instance.alias] = {
                'total_seconds': total_seconds,
                'worklog_count': len(worklogs),
                'hours': total_seconds // 3600,
                'minutes': (total_seconds % 3600) // 60
            }
            grand_total_seconds += total_seconds

    # Sort worklogs by date (newest first)
    all_worklogs.sort(key=lambda x: x['started'], reverse=True)

    # Calculate daily totals
    daily_totals = {}
    for worklog in all_worklogs:
        date = worklog['date']
        if date not in daily_totals:
            daily_totals[date] = 0
        daily_totals[date] += worklog['time_spent_seconds']

    # Convert daily totals to readable format
    daily_totals_readable = {}
    for date, seconds in daily_totals.items():
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        daily_totals_readable[date] = f"{hours}h {minutes}m"

    # Calculate project totals
    project_totals = {}
    for worklog in all_worklogs:
        project = worklog['project']
        if project not in project_totals:
            project_totals[project] = 0
        project_totals[project] += worklog['time_spent_seconds']

    # Convert to readable format and sort
    project_totals_readable = {}
    for project, seconds in sorted(project_totals.items(), key=lambda x: x[1], reverse=True):
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        project_totals_readable[project] = {
            'time': f"{hours}h {minutes}m",
            'seconds': seconds
        }

    grand_total_hours = grand_total_seconds // 3600
    grand_total_minutes = (grand_total_seconds % 3600) // 60

    logger.info(f"Report summary: {len(all_worklogs)} worklogs, {grand_total_hours}h {grand_total_minutes}m total")

    return render_template('reports_dashboard.html',
                           worklogs=all_worklogs,
                           instance_totals=instance_totals,
                           daily_totals=daily_totals_readable,
                           project_totals=project_totals_readable,
                           grand_total=f"{grand_total_hours}h {grand_total_minutes}m",
                           grand_total_seconds=grand_total_seconds,
                           start_date=start_date.strftime('%Y-%m-%d'),
                           end_date=end_date.strftime('%Y-%m-%d'),
                           date_range=date_range,
                           instances=instances)


@reports_bp.route('/debug-worklogs')
@login_required
def debug_worklogs():
    """Debug endpoint to see what worklogs exist using direct API v3"""
    instance_id = request.args.get('instance_id')
    if not instance_id:
        return "Instance ID required", 400

    instance = JiraInstance.query.filter_by(
        id=instance_id,
        user_id=current_user.id
    ).first_or_404()

    try:
        debug_info = f"<h2>Debug Info for {instance.alias}</h2>"
        debug_info += f"<p>Jira User: {instance.jira_username}</p>"

        # Test basic connectivity
        server_info = make_jira_api_call(instance, '/serverInfo')
        if server_info:
            debug_info += f"<p>✅ Connected to Jira: {server_info.get('serverTitle', 'Unknown')}</p>"
        else:
            debug_info += "<p>❌ Could not connect to Jira</p>"
            return debug_info

        # Search for recent issues with worklogs
        search_data = {
            'jql': 'worklogAuthor = currentUser() AND worklogDate >= "-7d"',
            'maxResults': 20,
            'fields': ['key', 'summary', 'project']
        }

        result = make_jira_api_call(instance, '/search/jql', 'POST', search_data)

        if not result:
            debug_info += "<p>❌ Search API call failed</p>"
            return debug_info

        debug_info += f"<p>Found {result.get('total', 0)} issues with your worklogs in last 7 days:</p>"

        for issue_data in result.get('issues', []):
            issue_key = issue_data['key']
            debug_info += f"<h3>Issue: {issue_key} - {issue_data['fields']['summary']}</h3>"

            # Get worklogs for this issue
            worklogs_result = make_jira_api_call(instance, f'/issue/{issue_key}/worklog')
            if not worklogs_result:
                debug_info += "<p>❌ Could not fetch worklogs</p>"
                continue

            worklogs = worklogs_result.get('worklogs', [])
            debug_info += f"<p>Worklogs: {len(worklogs)}</p>"

            for worklog in worklogs:
                author_email = worklog['author'].get('emailAddress', 'Unknown')
                matches_user = author_email.lower() == instance.jira_username.lower()
                match_status = "✅" if matches_user else "❌"

                # Try to extract comment text from Atlassian Document Format
                comment_content = worklog.get('comment', {})
                comment_text = "No comment"
                if comment_content and 'content' in comment_content:
                    # Extract text from ADF content
                    text_parts = []
                    for content in comment_content['content']:
                        if content.get('text'):
                            text_parts.append(content['text'])
                    if text_parts:
                        comment_text = ' '.join(text_parts)

                debug_info += f"""
                <div style="border: 1px solid #ccc; margin: 10px; padding: 10px;">
                    <strong>Time:</strong> {worklog['timeSpentSeconds']} seconds<br>
                    <strong>Date:</strong> {worklog['started']}<br>
                    <strong>Author:</strong> {author_email} {match_status}<br>
                    <strong>Comment:</strong> {comment_text}<br>
                    <strong>Matches your user:</strong> {matches_user}
                </div>
                """

        return debug_info

    except Exception as e:
        return f"Error: {str(e)}", 400