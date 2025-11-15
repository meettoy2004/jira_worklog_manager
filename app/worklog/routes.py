from flask import render_template, request, jsonify
from flask_login import login_required, current_user
from app.models import JiraInstance
from app.worklog.forms import WorklogForm
from app.worklog import worklog_bp
from jira import JIRA
from jira.exceptions import JIRAError
import requests
import logging
import base64
import urllib3

# Set up logging
logging.basicConfig(level=logging.DEBUG)
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


def get_jira_client(instance):
    """Create and return a JIRA client for the given instance with username/password"""
    try:
        logger.info(f"Attempting to connect to Jira instance: {instance.alias}")
        logger.info(f"URL: {instance.base_url}, Username: {instance.jira_username}")

        # Test basic connectivity first with SSL disabled
        test_url = f"{instance.base_url}/rest/api/3/serverInfo"
        try:
            response = requests.get(test_url,
                                    auth=(instance.jira_username, instance.get_jira_password()),
                                    timeout=10,
                                    verify=False)
            logger.info(f"Connectivity test: {response.status_code}")
            if response.status_code != 200:
                logger.error(f"Connectivity test failed: {response.status_code} - {response.text}")
                return None
        except requests.exceptions.SSLError as ssl_error:
            logger.warning(f"SSL certificate warning (this is normal for internal instances): {ssl_error}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error testing connectivity: {e}")
            return None

        # Create JIRA client with username/password authentication
        jira_client = JIRA(
            server=instance.base_url,
            basic_auth=(instance.jira_username, instance.get_jira_password()),
            options={
                'verify': False,
                'timeout': 30,
            }
        )

        # Test the connection by getting server info
        server_info = jira_client.server_info()
        logger.info(f"Successfully connected to Jira: {server_info['serverTitle']}")

        return jira_client

    except JIRAError as e:
        logger.error(f"JIRA Connection Error for {instance.alias}: {e.status_code} - {e.text}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error connecting to {instance.alias}: {str(e)}")
        return None


@worklog_bp.route('/log-work')
@login_required
def log_work():
    # Get all active Jira instances for the user
    instances = JiraInstance.query.filter_by(
        user_id=current_user.id,
        is_active=True
    ).all()

    form = WorklogForm()
    return render_template('log_work.html', instances=instances, form=form)


@worklog_bp.route('/get-projects/<int:instance_id>')
@login_required
def get_projects(instance_id):
    # Verify the instance belongs to the current user
    instance = JiraInstance.query.filter_by(
        id=instance_id,
        user_id=current_user.id
    ).first_or_404()

    try:
        logger.info(f"Getting projects for instance: {instance.alias}")

        # Use direct API v3 call instead of JIRA client
        result = make_jira_api_call(instance, '/project/search')

        if not result:
            error_msg = f"Could not connect to Jira instance: {instance.alias}. Please check your URL and credentials."
            logger.error(error_msg)
            return jsonify({'error': error_msg}), 400

        # Extract projects from API response
        projects = result.get('values', [])
        logger.info(f"Retrieved {len(projects)} projects from {instance.alias}")

        # Format projects for frontend
        project_list = []
        for project in projects:
            project_list.append({
                'id': project['key'],
                'name': f"{project['key']} - {project['name']}",
                'key': project['key']
            })

        return jsonify(project_list)

    except Exception as e:
        error_msg = f'Unexpected error: {str(e)}'
        logger.error(error_msg)
        return jsonify({'error': error_msg}), 400


@worklog_bp.route('/search-issues', methods=['POST'])
@login_required
def search_issues():
    data = request.get_json()
    instance_id = data.get('instance_id')
    project_id = data.get('project_id')
    search_query = data.get('search_query', '')

    # Verify the instance belongs to the current user
    instance = JiraInstance.query.filter_by(
        id=instance_id,
        user_id=current_user.id
    ).first_or_404()

    try:
        logger.info(f"Searching issues in {instance.alias}, project: {project_id}, query: {search_query}")

        # Use direct REST API v3 (most reliable)
        return search_issues_direct_api(instance, project_id, search_query)

    except Exception as e:
        logger.error(f"Search failed: {str(e)}")
        return jsonify({'error': f'Search failed: {str(e)}'}), 400


def search_issues_direct_api(instance, project_id, search_query):
    """Search issues using direct REST API v3 calls with correct endpoint"""
    # Build JQL query
    jql_parts = []
    if project_id:
        jql_parts.append(f'project = "{project_id}"')
    if search_query:
        jql_parts.append(f'(text ~ "{search_query}" OR key ~ "{search_query}*")')

    jql = ' AND '.join(jql_parts) if jql_parts else 'order by created DESC'
    jql += ' AND status not in (Done, Closed, Resolved)'

    logger.info(f"JQL Query: {jql}")

    # Use the CORRECT REST API v3 endpoint: /rest/api/3/search/jql
    search_data = {
        'jql': jql,
        'maxResults': 50,
        'fields': ['key', 'summary', 'status']
    }

    result = make_jira_api_call(instance, '/search/jql', 'POST', search_data)

    if result:
        issue_list = []
        for issue in result.get('issues', []):
            issue_list.append({
                'key': issue['key'],
                'summary': issue['fields']['summary'],
                'status': issue['fields']['status']['name']
            })

        logger.info(f"Found {len(issue_list)} issues via direct API")
        return jsonify(issue_list)
    else:
        error_msg = "API v3 search call failed"
        logger.error(error_msg)
        return jsonify({'error': error_msg}), 400


@worklog_bp.route('/submit-worklog', methods=['POST'])
@login_required
def submit_worklog():
    data = request.get_json()

    instance_id = data.get('instance_id')
    issue_key = data.get('issue_key')
    time_spent = data.get('time_spent')
    comment = data.get('comment')
    work_date = data.get('date')

    # Verify the instance belongs to the current user
    instance = JiraInstance.query.filter_by(
        id=instance_id,
        user_id=current_user.id
    ).first_or_404()

    try:
        logger.info(f"Submitting worklog to {instance.alias}, issue: {issue_key}")

        # Use direct API v3 call to add worklog
        from datetime import datetime

        # Convert date to ISO format with time
        if work_date:
            dt = datetime.strptime(work_date, '%Y-%m-%d')
            # Set time to 9 AM
            started = dt.replace(hour=9, minute=0, second=0).strftime('%Y-%m-%dT%H:%M:%S.000+0000')
        else:
            started = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.000+0000')

        worklog_data = {
            'timeSpent': time_spent,
            'comment': {
                'type': 'doc',
                'version': 1,
                'content': [
                    {
                        'type': 'paragraph',
                        'content': [
                            {
                                'type': 'text',
                                'text': comment
                            }
                        ]
                    }
                ]
            },
            'started': started
        }

        result = make_jira_api_call(instance, f'/issue/{issue_key}/worklog', 'POST', worklog_data)

        if result:
            message = f'Worklog added successfully to {issue_key} on {instance.alias}! (Time: {time_spent})'
            logger.info(message)
            return jsonify({'success': True, 'message': message})
        else:
            error_message = 'Failed to add worklog via API'
            logger.error(error_message)
            return jsonify({'success': False, 'message': error_message}), 400

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        error_message = f'Unexpected error: {str(e)}'
        return jsonify({'success': False, 'message': error_message}), 400