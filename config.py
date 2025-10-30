import os
from cryptography.fernet import Fernet


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'Redhat@12345_'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///jira_worklog.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # For production, set CRYPTO_KEY as environment variable
    CRYPTO_KEY = os.environ.get('CRYPTO_KEY') or Fernet.generate_key()