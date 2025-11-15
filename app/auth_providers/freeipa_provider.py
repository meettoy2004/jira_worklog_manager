"""
FreeIPA Authentication Provider

Provides authentication against FreeIPA identity management system.
"""

from app.auth_providers.ldap_provider import LDAPAuthProvider
from app.auth_providers.base import AuthenticationResult
import logging

logger = logging.getLogger(__name__)


class FreeIPAAuthProvider(LDAPAuthProvider):
    """FreeIPA authentication provider (extends LDAP)"""

    def get_required_config_fields(self):
        """Required configuration fields for FreeIPA"""
        return [
            'server_uri',
            'base_dn',
        ]

    def authenticate(self, username, password):
        """
        Authenticate user against FreeIPA.

        Args:
            username: FreeIPA username (uid)
            password: User password

        Returns:
            AuthenticationResult with user information
        """
        # FreeIPA uses standard LDAP authentication
        # Set FreeIPA-specific DN template
        if 'bind_dn_template' not in self.config:
            self.config['bind_dn_template'] = 'uid={username},cn=users,' + self.config['base_dn']

        return super().authenticate(username, password)

    def _get_user_attributes(self, conn, username):
        """
        Get user attributes from FreeIPA.

        Args:
            conn: Active LDAP connection
            username: Username to search for

        Returns:
            Dictionary with user information
        """
        try:
            base_dn = self.config['base_dn']
            # FreeIPA-specific search
            search_filter = f"(uid={username})"
            attributes = [
                'uid',
                'mail',
                'cn',
                'givenName',
                'sn',
                'displayName',
                'memberOf',
                'ipaUniqueID',
            ]

            conn.search(
                search_base=f"cn=users,{base_dn}",
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
            }

            # Get unique ID
            if hasattr(entry, 'ipaUniqueID') and entry.ipaUniqueID.value:
                user_info['external_id'] = str(entry.ipaUniqueID.value)
            else:
                user_info['external_id'] = str(entry.entry_dn)

            # Get email
            if hasattr(entry, 'mail') and entry.mail.value:
                user_info['email'] = str(entry.mail.value)

            # Get full name
            if hasattr(entry, 'displayName') and entry.displayName.value:
                user_info['full_name'] = str(entry.displayName.value)
            elif hasattr(entry, 'cn') and entry.cn.value:
                user_info['full_name'] = str(entry.cn.value)
            elif hasattr(entry, 'givenName') and hasattr(entry, 'sn'):
                given = str(entry.givenName.value) if entry.givenName.value else ''
                surname = str(entry.sn.value) if entry.sn.value else ''
                user_info['full_name'] = f"{given} {surname}".strip()

            # Get groups
            if hasattr(entry, 'memberOf') and entry.memberOf.value:
                groups = []
                for group_dn in entry.memberOf.value:
                    # Extract CN from DN
                    if 'cn=' in group_dn.lower():
                        cn = group_dn.split(',')[0].replace('cn=', '').replace('CN=', '')
                        groups.append(cn)
                user_info['groups'] = groups

            return user_info

        except Exception as e:
            self.logger.warning(f"Could not get FreeIPA user attributes for {username}: {str(e)}")
            return {
                'username': username,
                'external_id': username,
            }

    def search_users(self, query, limit=10):
        """
        Search for users in FreeIPA.

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

            # Use test credentials
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
                search_base=f"cn=users,{base_dn}",
                search_filter=search_filter,
                attributes=attributes,
                size_limit=limit
            )

            users = []
            for entry in conn.entries:
                users.append({
                    'username': str(entry.uid.value) if hasattr(entry, 'uid') else '',
                    'full_name': (str(entry.displayName.value) if hasattr(entry, 'displayName') and entry.displayName.value
                                 else str(entry.cn.value) if hasattr(entry, 'cn') else ''),
                    'email': str(entry.mail.value) if hasattr(entry, 'mail') else '',
                })

            conn.unbind()

            return users

        except Exception as e:
            self.logger.error(f"FreeIPA user search error: {str(e)}")
            return []

    def get_user_groups(self, username):
        """
        Get FreeIPA groups for a user.

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

            # Search for user and get memberOf attribute
            base_dn = self.config['base_dn']
            search_filter = f"(uid={username})"

            conn.search(
                search_base=f"cn=users,{base_dn}",
                search_filter=search_filter,
                attributes=['memberOf']
            )

            groups = []
            if conn.entries and hasattr(conn.entries[0], 'memberOf'):
                for group_dn in conn.entries[0].memberOf.value:
                    # Extract CN from DN
                    if 'cn=' in group_dn.lower():
                        cn = group_dn.split(',')[0].replace('cn=', '').replace('CN=', '')
                        groups.append(cn)

            conn.unbind()

            return groups

        except Exception as e:
            self.logger.error(f"Error getting FreeIPA user groups: {str(e)}")
            return []

    def test_connection(self):
        """
        Test connection to FreeIPA server.

        Returns:
            Tuple of (success, message)
        """
        try:
            from ldap3 import Server, Connection, ALL

            server_uri = self.config['server_uri']
            use_ssl = self.config.get('use_ssl', True)

            server = Server(server_uri, get_info=ALL, use_ssl=use_ssl)

            # Use test credentials if provided
            test_bind_dn = self.config.get('test_bind_dn')
            test_bind_password = self.config.get('test_bind_password')

            if test_bind_dn and test_bind_password:
                conn = Connection(server, user=test_bind_dn, password=test_bind_password)
            else:
                conn = Connection(server)

            if not conn.bind():
                return False, f"Connection failed: {conn.result}"

            # Try searching for users container
            base_dn = self.config['base_dn']
            conn.search(search_base=f"cn=users,{base_dn}", search_filter='(objectClass=*)', search_scope='BASE')

            conn.unbind()

            return True, "Connection successful"

        except Exception as e:
            return False, f"Connection error: {str(e)}"
