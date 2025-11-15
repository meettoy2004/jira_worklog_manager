import os
from cryptography.fernet import Fernet


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'Redhat@12345_'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///jira_worklog.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # CRITICAL: Use a fixed key for encryption so passwords persist across restarts
    # In production, set this as an environment variable
    # For development, use a fixed key (generated once)
    CRYPTO_KEY = os.environ.get('CRYPTO_KEY') or b'8vHJKLMN9pQRSTUV2wXYZ3aBcDeFgHiJ4kLmNoPqRsT='