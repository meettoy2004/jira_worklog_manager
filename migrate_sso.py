"""
Database migration script to add SSO/External Authentication features.

This script adds:
- Auth Provider table for storing external authentication configurations
- New fields to User table: email, full_name, auth_provider_id, external_id, last_login, created_at

Run this script to upgrade your existing database to support SSO.
"""

from app import create_app, db
from app.models import User, AuthProvider
from sqlalchemy import text

def migrate_database():
    """Migrate the database to add SSO features"""
    app = create_app()

    with app.app_context():
        print("Starting SSO database migration...")

        # Get the database connection
        conn = db.engine.connect()

        try:
            # Check existing columns in User table
            result = conn.execute(text("PRAGMA table_info(user)"))
            existing_columns = [row[1] for row in result]

            print("\n=== Updating User table ===")

            # Add new columns to User table if they don't exist
            new_columns = {
                'email': "ALTER TABLE user ADD COLUMN email VARCHAR(120)",
                'full_name': "ALTER TABLE user ADD COLUMN full_name VARCHAR(200)",
                'auth_provider_id': "ALTER TABLE user ADD COLUMN auth_provider_id INTEGER",
                'external_id': "ALTER TABLE user ADD COLUMN external_id VARCHAR(256)",
                'last_login': "ALTER TABLE user ADD COLUMN last_login DATETIME",
                'created_at': "ALTER TABLE user ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP",
            }

            for column_name, alter_sql in new_columns.items():
                if column_name not in existing_columns:
                    print(f"Adding {column_name} column to User table...")
                    conn.execute(text(alter_sql))
                    conn.commit()
                    print(f"✓ {column_name} column added")
                else:
                    print(f"✓ {column_name} column already exists")

            # Make password_hash nullable for SSO users
            print("\nNote: password_hash column should be nullable for SSO users.")
            print("SQLite doesn't support modifying columns easily, so existing column constraints remain.")

            # Check if AuthProvider table exists
            print("\n=== Creating AuthProvider table ===")
            result = conn.execute(text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='auth_provider'"
            ))

            if result.fetchone() is None:
                print("Creating AuthProvider table...")
                # Create all tables (will only create missing ones)
                db.create_all()
                print("✓ AuthProvider table created")
            else:
                print("✓ AuthProvider table already exists")

            print("\n✓ Database migration completed successfully!")
            print("\nNext steps:")
            print("1. Install new dependencies:")
            print("   pip install -r requirements.txt")
            print("2. Log in as admin")
            print("3. Go to Admin Dashboard → Authentication Providers")
            print("4. Configure your authentication providers (LDAP, AD, FreeIPA, or Keycloak)")
            print("5. Test the connection before enabling")
            print("\nSupported authentication providers:")
            print("  - LDAP (Generic LDAP directory)")
            print("  - Active Directory (Microsoft AD)")
            print("  - FreeIPA (Identity Management)")
            print("  - Keycloak (SSO/OIDC)")

        except Exception as e:
            print(f"\n✗ Error during migration: {str(e)}")
            conn.rollback()
            raise
        finally:
            conn.close()


if __name__ == '__main__':
    migrate_database()
