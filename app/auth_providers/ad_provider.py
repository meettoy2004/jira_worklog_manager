"""
Active Directory Authentication Provider

Provides authentication against Microsoft Active Directory.
"""

from app.auth_providers.ldap_provider import LDAPAuthProvider
from app.auth_providers.base import AuthenticationResult
import logging

logger = logging.getLogger(__name__)


class ActiveDirectoryAuthProvider(LDAPAuthProvider):
    """Active Directory authentication provider (extends LDAP)"""

    def get_required_config_fields(self):
        """Required configuration fields for Active Directory"""
        return [
            'server_uri',
            'domain',
            'base_dn',
        ]

    def authenticate(self, username, password):
        """
        Authenticate user against Active Directory.

        Args:
            username: AD username (can be UPN or sAMAccountName)
            password: User password

        Returns:
            AuthenticationResult with user information
        """
        try:
            from ldap3 import Server, Connection, ALL, NTLM
            from ldap3.core.exceptions import LDAPException

            server_uri = self.config['server_uri']
            domain = self.config['domain']
            use_ssl = self.config.get('use_ssl', True)

            # Create server object
            server = Server(server_uri, get_info=ALL, use_ssl=use_ssl)

            # Format username for AD
            # If username doesn't contain @, add domain
            if '@' not in username:
                user_principal = f"{username}@{domain}"
                sam_account = username
            else:
                user_principal = username
                sam_account = username.split('@')[0]

            # Try UPN first, then domain\username format
            try:
                conn = Connection(server, user=user_principal, password=password, authentication=NTLM)
                if not conn.bind():
                    # Try domain\username format
                    domain_user = f"{domain}\\{sam_account}"
                    conn = Connection(server, user=domain_user, password=password, authentication=NTLM)
                    if not conn.bind():
                        self.logger.warning(f"AD bind failed for user {username}: {conn.result}")
                        return AuthenticationResult(False, error="Invalid credentials")
            except:
                # Fall back to simple bind
                conn = Connection(server, user=user_principal, password=password)
                if not conn.bind():
                    self.logger.warning(f"AD bind failed for user {username}: {conn.result}")
                    return AuthenticationResult(False, error="Invalid credentials")

            # Get user attributes from AD
            user_info = self._get_ad_user_attributes(conn, sam_account)

            conn.unbind()

            return AuthenticationResult(True, user_info=user_info)

        except Exception as e:
            self.logger.error(f"AD authentication error for {username}: {str(e)}")
            return AuthenticationResult(False, error=str(e))

    def _get_ad_user_attributes(self, conn, username):
        """
        Get user attributes from Active Directory.

        Args:
            conn: Active LDAP connection
            username: sAMAccountName to search for

        Returns:
            Dictionary with user information
        """
        try:
            base_dn = self.config['base_dn']
            search_filter = f"(sAMAccountName={username})"
            attributes = [
                'sAMAccountName',
                'userPrincipalName',
                'mail',
                'displayName',
                'givenName',
                'sn',
                'memberOf',
            ]

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

            # Get email
            if hasattr(entry, 'mail') and entry.mail.value:
                user_info['email'] = str(entry.mail.value)
            elif hasattr(entry, 'userPrincipalName') and entry.userPrincipalName.value:
                user_info['email'] = str(entry.userPrincipalName.value)

            # Get full name
            if hasattr(entry, 'displayName') and entry.displayName.value:
                user_info['full_name'] = str(entry.displayName.value)
            elif hasattr(entry, 'givenName') and hasattr(entry, 'sn'):
                given = str(entry.givenName.value) if entry.givenName.value else ''
                surname = str(entry.sn.value) if entry.sn.value else ''
                user_info['full_name'] = f"{given} {surname}".strip()

            # Get groups
            if hasattr(entry, 'memberOf') and entry.memberOf.value:
                groups = []
                for group_dn in entry.memberOf.value:
                    # Extract CN from DN (e.g., "CN=Admins,OU=Groups,DC=example,DC=com" -> "Admins")
                    cn = group_dn.split(',')[0].replace('CN=', '')
                    groups.append(cn)
                user_info['groups'] = groups

            return user_info

        except Exception as e:
            self.logger.warning(f"Could not get AD user attributes for {username}: {str(e)}")
            return {
                'username': username,
                'external_id': username,
            }

    def search_users(self, query, limit=10):
        """
        Search for users in Active Directory.

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
            domain = self.config['domain']

            server = Server(server_uri, get_info=ALL, use_ssl=use_ssl)

            # Use test credentials
            test_user = self.config.get('test_bind_dn')
            test_password = self.config.get('test_bind_password')

            if test_user and test_password:
                if '@' not in test_user:
                    test_user = f"{test_user}@{domain}"
                conn = Connection(server, user=test_user, password=test_password)
            else:
                conn = Connection(server)

            if not conn.bind():
                return []

            base_dn = self.config['base_dn']
            search_filter = (
                f"(&(objectClass=user)(objectCategory=person)"
                f"(|(sAMAccountName=*{query}*)(displayName=*{query}*)(mail=*{query}*)))"
            )
            attributes = ['sAMAccountName', 'displayName', 'mail', 'userPrincipalName']

            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                attributes=attributes,
                size_limit=limit
            )

            users = []
            for entry in conn.entries:
                username = str(entry.sAMAccountName.value) if hasattr(entry, 'sAMAccountName') else ''
                users.append({
                    'username': username,
                    'full_name': str(entry.displayName.value) if hasattr(entry, 'displayName') and entry.displayName.value else '',
                    'email': str(entry.mail.value) if hasattr(entry, 'mail') and entry.mail.value else '',
                })

            conn.unbind()

            return users

        except Exception as e:
            self.logger.error(f"AD user search error: {str(e)}")
            return []

    def get_user_groups(self, username):
        """
        Get AD groups for a user.

        Args:
            username: Username to get groups for

        Returns:
            List of group names
        """
        try:
            from ldap3 import Server, Connection, ALL

            server_uri = self.config['server_uri']
            use_ssl = self.config.get('use_ssl', True)
            domain = self.config['domain']

            server = Server(server_uri, get_info=ALL, use_ssl=use_ssl)

            # Use test credentials
            test_user = self.config.get('test_bind_dn')
            test_password = self.config.get('test_bind_password')

            if not test_user or not test_password:
                return []

            if '@' not in test_user:
                test_user = f"{test_user}@{domain}"

            conn = Connection(server, user=test_user, password=test_password)

            if not conn.bind():
                return []

            # Search for user and get memberOf attribute
            base_dn = self.config['base_dn']
            search_filter = f"(sAMAccountName={username})"

            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                attributes=['memberOf']
            )

            groups = []
            if conn.entries and hasattr(conn.entries[0], 'memberOf'):
                for group_dn in conn.entries[0].memberOf.value:
                    # Extract CN from DN
                    cn = group_dn.split(',')[0].replace('CN=', '')
                    groups.append(cn)

            conn.unbind()

            return groups

        except Exception as e:
            self.logger.error(f"Error getting AD user groups: {str(e)}")
            return []
