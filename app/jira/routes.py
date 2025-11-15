from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.models import JiraInstance
from app.jira.forms import JiraInstanceForm
from app.jira import jira_bp


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
        import requests
        import urllib3

        # Disable SSL warnings for testing
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        test_url = f"{instance.base_url}/rest/api/3/serverInfo"

        # Try with username/password authentication
        try:
            response = requests.get(test_url,
                                    auth=(instance.jira_username, instance.get_jira_password()),
                                    timeout=10,
                                    verify=False)

            if response.status_code == 200:
                server_info = response.json()
                return f"""
                ✅ Connection successful (Username/Password)<br>
                ✅ Jira Server: {server_info.get('serverTitle', 'Unknown')}<br>
                ✅ Version: {server_info.get('version', 'Unknown')}<br>
                ✅ API Version: 3<br>
                <br>
                <strong>Note:</strong> Connected using username/password authentication.
                """
            else:
                return f"❌ Connection failed: {response.status_code} - {response.text}<br>"

        except requests.exceptions.SSLError as ssl_error:
            return f"""
            ❌ SSL Certificate Error: {ssl_error}<br>
            <br>
            <strong>This is common for internal Jira instances.</strong><br>
            The application will automatically handle this when logging work.
            """

    except Exception as e:
        return f"❌ Connection test failed: {str(e)}<br>"