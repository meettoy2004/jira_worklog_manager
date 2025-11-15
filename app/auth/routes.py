from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
from app import db
from app.models import User, AuthProvider
from app.auth.forms import LoginForm, RegistrationForm
from app.auth import auth
from app.auth_providers import get_auth_provider
import logging

logger = logging.getLogger(__name__)


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if username already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('register.html', form=form)

        # Create new user
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html', form=form)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Try to authenticate the user
        user, auth_method = authenticate_user(username, password)

        if user:
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()

            login_user(user, remember=form.remember_me.data)

            if auth_method != 'local':
                flash(f'Logged in successfully using {auth_method}.', 'success')

            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html', form=form)


def authenticate_user(username, password):
    """
    Authenticate user against local database and external providers.

    Args:
        username: Username to authenticate
        password: Password for authentication

    Returns:
        Tuple of (User object or None, authentication method string)
    """
    # Try local authentication first
    user = User.query.filter_by(username=username).first()
    if user and user.is_local_user() and user.check_password(password):
        return user, 'local'

    # Try external authentication providers
    enabled_providers = AuthProvider.query.filter_by(is_enabled=True).all()

    for provider in enabled_providers:
        try:
            config = provider.get_config()
            auth_provider = get_auth_provider(provider.provider_type, config)

            result = auth_provider.authenticate(username, password)

            if result.success:
                # Authentication successful, get or create user
                user = get_or_create_external_user(
                    username=result.user_info.get('username', username),
                    provider=provider,
                    user_info=result.user_info
                )

                if user:
                    return user, provider.name

        except Exception as e:
            logger.error(f"Error authenticating with provider {provider.name}: {str(e)}")
            continue

    return None, None


def get_or_create_external_user(username, provider, user_info):
    """
    Get existing external user or create new one.

    Args:
        username: Username from external provider
        provider: AuthProvider instance
        user_info: Dictionary with user information from provider

    Returns:
        User object or None
    """
    # Check if user already exists
    user = User.query.filter_by(username=username).first()

    if user:
        # Update user information from provider
        if user.auth_provider_id == provider.id:
            # Update user info
            if 'email' in user_info and user_info['email']:
                user.email = user_info['email']
            if 'full_name' in user_info and user_info['full_name']:
                user.full_name = user_info['full_name']
            if 'external_id' in user_info and user_info['external_id']:
                user.external_id = user_info['external_id']

            db.session.commit()
            return user
        else:
            # User exists but with different provider
            logger.warning(f"User {username} exists with different auth provider")
            return None

    # Auto-create user if enabled
    if not provider.auto_create_users:
        logger.warning(f"Auto-create disabled for provider {provider.name}, user {username} not found")
        return None

    try:
        # Create new user
        user = User(
            username=username,
            email=user_info.get('email'),
            full_name=user_info.get('full_name'),
            auth_provider_id=provider.id,
            external_id=user_info.get('external_id', username),
        )

        db.session.add(user)
        db.session.commit()

        logger.info(f"Created new external user: {username} from provider {provider.name}")
        return user

    except Exception as e:
        logger.error(f"Error creating external user {username}: {str(e)}")
        db.session.rollback()
        return None


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))