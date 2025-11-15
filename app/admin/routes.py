from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app.admin import admin
from app import db
from app.models import User, AuthProvider
from app.decorators import admin_required
from app.admin.forms import AuthProviderForm
from app.auth_providers import get_auth_provider
import logging

logger = logging.getLogger(__name__)


@admin.route('/dashboard')
@login_required
@admin_required
def dashboard():
    """Admin dashboard showing all users"""
    users = User.query.all()
    return render_template('admin/dashboard.html', users=users)


@admin.route('/promote/<int:user_id>')
@login_required
@admin_required
def promote_to_manager(user_id):
    """Promote a user to manager role"""
    user = User.query.get_or_404(user_id)

    if user.is_manager:
        flash(f'{user.username} is already a manager.', 'info')
    else:
        user.is_manager = True
        db.session.commit()
        flash(f'{user.username} has been promoted to manager.', 'success')

    return redirect(url_for('admin.dashboard'))


@admin.route('/demote/<int:user_id>')
@login_required
@admin_required
def demote_from_manager(user_id):
    """Remove manager role from a user"""
    user = User.query.get_or_404(user_id)

    if not user.is_manager:
        flash(f'{user.username} is not a manager.', 'info')
    else:
        user.is_manager = False
        db.session.commit()
        flash(f'{user.username} has been demoted from manager role.', 'success')

    return redirect(url_for('admin.dashboard'))


@admin.route('/toggle-admin/<int:user_id>')
@login_required
@admin_required
def toggle_admin(user_id):
    """Toggle admin role for a user (be careful with this!)"""
    user = User.query.get_or_404(user_id)

    # Prevent removing admin from yourself
    if user.id == current_user.id:
        flash('You cannot change your own admin status.', 'warning')
        return redirect(url_for('admin.dashboard'))

    user.is_admin = not user.is_admin
    db.session.commit()

    status = 'promoted to admin' if user.is_admin else 'removed from admin'
    flash(f'{user.username} has been {status}.', 'success')

    return redirect(url_for('admin.dashboard'))


# Authentication Provider Management Routes

@admin.route('/auth-providers')
@login_required
@admin_required
def auth_providers():
    """List all authentication providers"""
    providers = AuthProvider.query.all()
    return render_template('admin/auth_providers.html', providers=providers)


@admin.route('/auth-providers/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_auth_provider():
    """Add a new authentication provider"""
    form = AuthProviderForm()

    if form.validate_on_submit():
        try:
            # Create provider configuration
            config = form.to_config()

            # Create provider instance
            provider = AuthProvider(
                name=form.name.data,
                provider_type=form.provider_type.data,
                is_enabled=form.is_enabled.data,
                is_default=form.is_default.data,
                auto_create_users=form.auto_create_users.data,
            )

            # Encrypt and store configuration
            provider.set_config(config)

            # If this is set as default, unset other defaults
            if provider.is_default:
                AuthProvider.query.filter(AuthProvider.id != provider.id).update({'is_default': False})

            db.session.add(provider)
            db.session.commit()

            flash(f'Authentication provider "{provider.name}" has been added.', 'success')
            return redirect(url_for('admin.auth_providers'))

        except Exception as e:
            logger.error(f"Error adding auth provider: {str(e)}")
            flash(f'Error adding provider: {str(e)}', 'danger')

    return render_template('admin/auth_provider_form.html', form=form, title='Add Authentication Provider')


@admin.route('/auth-providers/edit/<int:provider_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_auth_provider(provider_id):
    """Edit an existing authentication provider"""
    provider = AuthProvider.query.get_or_404(provider_id)
    form = AuthProviderForm()

    if form.validate_on_submit():
        try:
            # Update provider details
            provider.name = form.name.data
            provider.provider_type = form.provider_type.data
            provider.is_enabled = form.is_enabled.data
            provider.is_default = form.is_default.data
            provider.auto_create_users = form.auto_create_users.data

            # Update configuration
            config = form.to_config()

            # Merge with existing config to preserve passwords if not updated
            existing_config = provider.get_config()
            if not form.test_bind_password.data and 'test_bind_password' in existing_config:
                config['test_bind_password'] = existing_config['test_bind_password']
            if not form.client_secret.data and 'client_secret' in existing_config:
                config['client_secret'] = existing_config['client_secret']
            if not form.admin_password.data and 'admin_password' in existing_config:
                config['admin_password'] = existing_config['admin_password']

            provider.set_config(config)

            # If this is set as default, unset other defaults
            if provider.is_default:
                AuthProvider.query.filter(AuthProvider.id != provider.id).update({'is_default': False})

            db.session.commit()

            flash(f'Authentication provider "{provider.name}" has been updated.', 'success')
            return redirect(url_for('admin.auth_providers'))

        except Exception as e:
            logger.error(f"Error updating auth provider: {str(e)}")
            flash(f'Error updating provider: {str(e)}', 'danger')

    # Populate form with existing data
    if request.method == 'GET':
        form.name.data = provider.name
        form.provider_type.data = provider.provider_type
        form.is_enabled.data = provider.is_enabled
        form.is_default.data = provider.is_default
        form.auto_create_users.data = provider.auto_create_users

        # Populate configuration fields
        config = provider.get_config()
        form.from_config(config)

    return render_template('admin/auth_provider_form.html',
                          form=form,
                          provider=provider,
                          title=f'Edit {provider.name}')


@admin.route('/auth-providers/delete/<int:provider_id>')
@login_required
@admin_required
def delete_auth_provider(provider_id):
    """Delete an authentication provider"""
    provider = AuthProvider.query.get_or_404(provider_id)

    # Check if any users are using this provider
    users_count = User.query.filter_by(auth_provider_id=provider_id).count()

    if users_count > 0:
        flash(f'Cannot delete provider "{provider.name}": {users_count} users are using it.', 'warning')
        return redirect(url_for('admin.auth_providers'))

    try:
        name = provider.name
        db.session.delete(provider)
        db.session.commit()
        flash(f'Authentication provider "{name}" has been deleted.', 'success')

    except Exception as e:
        logger.error(f"Error deleting auth provider: {str(e)}")
        flash(f'Error deleting provider: {str(e)}', 'danger')

    return redirect(url_for('admin.auth_providers'))


@admin.route('/auth-providers/test/<int:provider_id>')
@login_required
@admin_required
def test_auth_provider(provider_id):
    """Test connection to an authentication provider"""
    provider = AuthProvider.query.get_or_404(provider_id)

    try:
        # Get provider configuration
        config = provider.get_config()

        # Create provider instance
        auth_provider = get_auth_provider(provider.provider_type, config)

        # Test connection
        success, message = auth_provider.test_connection()

        if success:
            return jsonify({
                'success': True,
                'message': message
            })
        else:
            return jsonify({
                'success': False,
                'message': message
            }), 400

    except Exception as e:
        logger.error(f"Error testing auth provider: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500


@admin.route('/auth-providers/toggle/<int:provider_id>')
@login_required
@admin_required
def toggle_auth_provider(provider_id):
    """Enable/disable an authentication provider"""
    provider = AuthProvider.query.get_or_404(provider_id)

    try:
        provider.is_enabled = not provider.is_enabled
        db.session.commit()

        status = 'enabled' if provider.is_enabled else 'disabled'
        flash(f'Authentication provider "{provider.name}" has been {status}.', 'success')

    except Exception as e:
        logger.error(f"Error toggling auth provider: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')

    return redirect(url_for('admin.auth_providers'))
