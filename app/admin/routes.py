from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.admin import admin
from app import db
from app.models import User
from app.decorators import admin_required


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
