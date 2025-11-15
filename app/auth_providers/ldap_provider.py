"""
LDAP Authentication Provider

Provides authentication against LDAP directories.
"""

from app.auth_providers.base import BaseAuthProvider, AuthenticationResult
import logging

logger = logging.getLogger(__name__)


class LDAPAuthProvider(BaseAuthProvider):
    """LDAP authentication provider"""

    def get_required_config_fields(self):
        """Required configuration fields for LDAP"""
        return [
            'server_uri',
            'bind_dn_template',
            'base_dn',
        ]

    def authenticate(self, username, password):
        """
        Authenticate user against LDAP server.

        Args:
            username: LDAP username
            password: User password

        Returns:
            AuthenticationResult with user information
        """
        try:
            from ldap3 import Server, Connection, ALL, NTLM
            from ldap3.core.exceptions import LDAPException

            server_uri = self.config['server_uri']
            use_ssl = self.config.get('use_ssl', True)
            start_tls = self.config.get('start_tls', False)

            # Create server object
            server = Server(server_uri, get_info=ALL, use_ssl=use_ssl)

            # Build bind DN from template
            bind_dn_template = self.config['bind_dn_template']
            bind_dn = bind_dn_template.format(username=username)

            # Attempt to bind (authenticate)
            conn = Connection(server, user=bind_dn, password=password)

            if start_tls and not use_ssl:
                conn.start_tls()

            if not conn.bind():
                self.logger.warning(f"LDAP bind failed for user {username}: {conn.result}")
                return AuthenticationResult(False, error="Invalid credentials")

            # Get user attributes
            user_info = self._get_user_attributes(conn, username)

            conn.unbind()

            return AuthenticationResult(True, user_info=user_info)

        except Exception as e:
            self.logger.error(f"LDAP authentication error for {username}: {str(e)}")
            return AuthenticationResult(False, error=str(e))

    def _get_user_attributes(self, conn, username):
        """
        Get user attributes from LDAP.

        Args:
            conn: Active LDAP connection
            username: Username to search for

        Returns:
            Dictionary with user information
        """
        try:
            base_dn = self.config['base_dn']
            search_filter = self.config.get('search_filter', '(uid={username})').format(username=username)
            attributes = self.config.get('attributes', ['uid', 'mail', 'cn', 'displayName'])

            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                attributes=attributes
            )

            if not conn.entries:
                return {
                    'username': username,
                    'external_id': username,
                }

            entry = conn.entries[0]

            # Extract user information
            user_info = {
                'username': username,
                'external_id': str(entry.entry_dn),
            }

            # Map LDAP attributes to user info
            attr_mapping = self.config.get('attribute_mapping', {
                'email': 'mail',
                'full_name': 'cn',
            })

            for user_field, ldap_attr in attr_mapping.items():
                if hasattr(entry, ldap_attr):
                    value = getattr(entry, ldap_attr).value
                    if value:
                        user_info[user_field] = value

            return user_info

        except Exception as e:
            self.logger.warning(f"Could not get user attributes for {username}: {str(e)}")
            return {
                'username': username,
                'external_id': username,
            }

    def test_connection(self):
        """
        Test connection to LDAP server.

        Returns:
            Tuple of (success, message)
        """
        try:
            from ldap3 import Server, Connection, ALL
            from ldap3.core.exceptions import LDAPException

            server_uri = self.config['server_uri']
            use_ssl = self.config.get('use_ssl', True)

            server = Server(server_uri, get_info=ALL, use_ssl=use_ssl)

            # Try anonymous bind if test credentials not provided
            test_bind_dn = self.config.get('test_bind_dn')
            test_bind_password = self.config.get('test_bind_password')

            if test_bind_dn and test_bind_password:
                conn = Connection(server, user=test_bind_dn, password=test_bind_password)
            else:
                conn = Connection(server)

            if not conn.bind():
                return False, f"Connection failed: {conn.result}"

            # Try a simple search
            base_dn = self.config['base_dn']
            conn.search(search_base=base_dn, search_filter='(objectClass=*)', search_scope='BASE')

            conn.unbind()

            return True, "Connection successful"

        except Exception as e:
            return False, f"Connection error: {str(e)}"

    def search_users(self, query, limit=10):
        """
        Search for users in LDAP directory.

        Args:
            query: Search query string
            limit: Maximum number of results

        Returns:
            List of user dictionaries
        """
        try:
            from ldap3 import Server, Connection, ALL

            server_uri = self.config['server_uri']
            use_ssl = self.config.get('use_ssl', True)

            server = Server(server_uri, get_info=ALL, use_ssl=use_ssl)

            # Use test credentials or anonymous
            test_bind_dn = self.config.get('test_bind_dn')
            test_bind_password = self.config.get('test_bind_password')

            if test_bind_dn and test_bind_password:
                conn = Connection(server, user=test_bind_dn, password=test_bind_password)
            else:
                conn = Connection(server)

            if not conn.bind():
                return []

            base_dn = self.config['base_dn']
            search_filter = f"(&(objectClass=person)(|(uid=*{query}*)(cn=*{query}*)(mail=*{query}*)))"
            attributes = ['uid', 'cn', 'mail', 'displayName']

            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                attributes=attributes,
                size_limit=limit
            )

            users = []
            for entry in conn.entries:
                users.append({
                    'username': str(entry.uid.value) if hasattr(entry, 'uid') else '',
                    'full_name': str(entry.cn.value) if hasattr(entry, 'cn') else '',
                    'email': str(entry.mail.value) if hasattr(entry, 'mail') else '',
                })

            conn.unbind()

            return users

        except Exception as e:
            self.logger.error(f"LDAP user search error: {str(e)}")
            return []

    def get_user_groups(self, username):
        """
        Get LDAP groups for a user.

        Args:
            username: Username to get groups for

        Returns:
            List of group names
        """
        try:
            from ldap3 import Server, Connection, ALL

            server_uri = self.config['server_uri']
            use_ssl = self.config.get('use_ssl', True)

            server = Server(server_uri, get_info=ALL, use_ssl=use_ssl)

            # Use test credentials
            test_bind_dn = self.config.get('test_bind_dn')
            test_bind_password = self.config.get('test_bind_password')

            if not test_bind_dn or not test_bind_password:
                return []

            conn = Connection(server, user=test_bind_dn, password=test_bind_password)

            if not conn.bind():
                return []

            # Search for user's groups
            base_dn = self.config['base_dn']
            search_filter = f"(&(objectClass=groupOfNames)(member=uid={username},*))"

            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                attributes=['cn']
            )

            groups = [str(entry.cn.value) for entry in conn.entries if hasattr(entry, 'cn')]

            conn.unbind()

            return groups

        except Exception as e:
            self.logger.error(f"Error getting user groups: {str(e)}")
            return []
