"""
Forms for admin configuration including authentication providers.
"""

from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SelectField, BooleanField,
    TextAreaField, IntegerField, SubmitField
)
from wtforms.validators import DataRequired, Optional, URL, NumberRange


class AuthProviderForm(FlaskForm):
    """Form for creating/editing authentication providers"""

    name = StringField('Provider Name', validators=[DataRequired()])
    provider_type = SelectField(
        'Provider Type',
        choices=[
            ('ldap', 'LDAP'),
            ('ad', 'Active Directory'),
            ('freeipa', 'FreeIPA'),
            ('keycloak', 'Keycloak/OIDC'),
        ],
        validators=[DataRequired()]
    )
    is_enabled = BooleanField('Enabled', default=True)
    is_default = BooleanField('Default Provider', default=False)
    auto_create_users = BooleanField('Auto-create Users', default=True)

    # Common LDAP fields
    server_uri = StringField('Server URI', validators=[Optional()])
    base_dn = StringField('Base DN', validators=[Optional()])
    bind_dn_template = StringField('Bind DN Template', validators=[Optional()])
    use_ssl = BooleanField('Use SSL/TLS', default=True)
    start_tls = BooleanField('Use StartTLS', default=False)

    # Search configuration
    search_filter = StringField('Search Filter', validators=[Optional()])
    test_bind_dn = StringField('Test/Admin Bind DN', validators=[Optional()])
    test_bind_password = PasswordField('Test/Admin Password', validators=[Optional()])

    # Active Directory specific
    domain = StringField('Domain (for AD)', validators=[Optional()])

    # Keycloak specific
    realm = StringField('Realm (for Keycloak)', validators=[Optional()])
    client_id = StringField('Client ID (for Keycloak)', validators=[Optional()])
    client_secret = PasswordField('Client Secret (for Keycloak)', validators=[Optional()])
    admin_username = StringField('Admin Username (for Keycloak)', validators=[Optional()])
    admin_password = PasswordField('Admin Password (for Keycloak)', validators=[Optional()])
    verify_ssl = BooleanField('Verify SSL', default=True)

    submit = SubmitField('Save Provider')

    def to_config(self):
        """Convert form data to configuration dictionary"""
        config = {}

        # Add all fields to config if they have values
        field_mapping = {
            # Common LDAP
            'server_uri': self.server_uri.data,
            'base_dn': self.base_dn.data,
            'bind_dn_template': self.bind_dn_template.data,
            'use_ssl': self.use_ssl.data,
            'start_tls': self.start_tls.data,
            'search_filter': self.search_filter.data,
            'test_bind_dn': self.test_bind_dn.data,
            'test_bind_password': self.test_bind_password.data,
            # AD specific
            'domain': self.domain.data,
            # Keycloak specific
            'realm': self.realm.data,
            'client_id': self.client_id.data,
            'client_secret': self.client_secret.data,
            'admin_username': self.admin_username.data,
            'admin_password': self.admin_password.data,
            'verify_ssl': self.verify_ssl.data,
        }

        # Only add non-empty values
        for key, value in field_mapping.items():
            if value is not None and value != '':
                config[key] = value

        return config

    def from_config(self, config):
        """Populate form from configuration dictionary"""
        if not config:
            return

        # Populate form fields from config
        if 'server_uri' in config:
            self.server_uri.data = config['server_uri']
        if 'base_dn' in config:
            self.base_dn.data = config['base_dn']
        if 'bind_dn_template' in config:
            self.bind_dn_template.data = config['bind_dn_template']
        if 'use_ssl' in config:
            self.use_ssl.data = config['use_ssl']
        if 'start_tls' in config:
            self.start_tls.data = config['start_tls']
        if 'search_filter' in config:
            self.search_filter.data = config['search_filter']
        if 'test_bind_dn' in config:
            self.test_bind_dn.data = config['test_bind_dn']
        # Don't populate passwords for security
        if 'domain' in config:
            self.domain.data = config['domain']
        if 'realm' in config:
            self.realm.data = config['realm']
        if 'client_id' in config:
            self.client_id.data = config['client_id']
        if 'admin_username' in config:
            self.admin_username.data = config['admin_username']
        if 'verify_ssl' in config:
            self.verify_ssl.data = config['verify_ssl']
