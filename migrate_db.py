"""
Database migration script to add admin/manager features.

This script adds:
- is_admin and is_manager columns to User table
- TeamInvite table for manager-member relationships

Run this script to upgrade your existing database.
"""

from app import create_app, db
from app.models import User, TeamInvite
from sqlalchemy import text

def migrate_database():
    """Migrate the database to add new admin/manager features"""
    app = create_app()

    with app.app_context():
        print("Starting database migration...")

        # Get the database connection
        conn = db.engine.connect()

        try:
            # Check if is_admin column exists in User table
            result = conn.execute(text("PRAGMA table_info(user)"))
            columns = [row[1] for row in result]

            if 'is_admin' not in columns:
                print("Adding is_admin column to User table...")
                conn.execute(text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0"))
                conn.commit()
                print("✓ is_admin column added")
            else:
                print("✓ is_admin column already exists")

            if 'is_manager' not in columns:
                print("Adding is_manager column to User table...")
                conn.execute(text("ALTER TABLE user ADD COLUMN is_manager BOOLEAN DEFAULT 0"))
                conn.commit()
                print("✓ is_manager column added")
            else:
                print("✓ is_manager column already exists")

            # Check if TeamInvite table exists
            result = conn.execute(text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='team_invite'"
            ))

            if result.fetchone() is None:
                print("Creating TeamInvite table...")
                # Create all tables (will only create missing ones)
                db.create_all()
                print("✓ TeamInvite table created")
            else:
                print("✓ TeamInvite table already exists")

            print("\n✓ Database migration completed successfully!")
            print("\nNext steps:")
            print("1. Log in to the application")
            print("2. Use SQL to make a user admin (if needed):")
            print("   UPDATE user SET is_admin = 1 WHERE username = 'your_username';")
            print("3. Admin can then promote users to managers from the Admin Dashboard")

        except Exception as e:
            print(f"\n✗ Error during migration: {str(e)}")
            conn.rollback()
            raise
        finally:
            conn.close()


if __name__ == '__main__':
    migrate_database()
