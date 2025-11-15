from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from datetime import datetime
from app import db
from config import Config


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_manager = db.Column(db.Boolean, default=False)

    # Relationship to Jira instances
    jira_instances = db.relationship('JiraInstance', backref='owner', lazy=True, cascade='all, delete-orphan')

    # Relationship for team invites as manager
    sent_invites = db.relationship('TeamInvite', foreign_keys='TeamInvite.manager_id',
                                   backref='manager', lazy=True, cascade='all, delete-orphan')

    # Relationship for team invites as member
    received_invites = db.relationship('TeamInvite', foreign_keys='TeamInvite.member_id',
                                       backref='member', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_team_members(self):
        """Get all accepted team members for this manager"""
        accepted_invites = TeamInvite.query.filter_by(
            manager_id=self.id,
            status='accepted'
        ).all()
        return [invite.member for invite in accepted_invites]

    def get_pending_invites(self):
        """Get all pending invites for this user"""
        return TeamInvite.query.filter_by(
            member_id=self.id,
            status='pending'
        ).all()


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


class TeamInvite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    manager_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    member_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    invited_at = db.Column(db.DateTime, default=datetime.utcnow)
    responded_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<TeamInvite Manager:{self.manager_id} Member:{self.member_id} Status:{self.status}>'