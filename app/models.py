from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from app import db
from config import Config


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    # Relationship to Jira instances
    jira_instances = db.relationship('JiraInstance', backref='owner', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class JiraInstance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    alias = db.Column(db.String(100), nullable=False)
    base_url = db.Column(db.String(200), nullable=False)
    jira_username = db.Column(db.String(200), nullable=False)
    jira_password_encrypted = db.Column(db.LargeBinary, nullable=False)
    is_active = db.Column(db.Boolean, default=True)

    def set_jira_password(self, password):
        fernet = Fernet(Config.CRYPTO_KEY)
        self.jira_password_encrypted = fernet.encrypt(password.encode())

    def get_jira_password(self):
        fernet = Fernet(Config.CRYPTO_KEY)
        return fernet.decrypt(self.jira_password_encrypted).decode()

    def __repr__(self):
        return f'<JiraInstance {self.alias}>'