"""
Script to create or promote a user to admin.

Usage:
    python create_admin.py <username>
"""

import sys
from app import create_app, db
from app.models import User


def create_or_promote_admin(username):
    """Create or promote a user to admin"""
    app = create_app()

    with app.app_context():
        user = User.query.filter_by(username=username).first()

        if not user:
            print(f"Error: User '{username}' not found.")
            print("\nAvailable users:")
            users = User.query.all()
            for u in users:
                print(f"  - {u.username}")
            return False

        if user.is_admin:
            print(f"User '{username}' is already an admin.")
            return True

        user.is_admin = True
        db.session.commit()
        print(f"✓ User '{username}' has been promoted to admin.")
        print("\nYou can now:")
        print("1. Log in as this user")
        print("2. Access the Admin Dashboard to manage other users")
        print("3. Promote users to managers")
        return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python create_admin.py <username>")
        print("\nExample: python create_admin.py john")
        sys.exit(1)

    username = sys.argv[1]
    success = create_or_promote_admin(username)
    sys.exit(0 if success else 1)
