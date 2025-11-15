"""
Keycloak/OIDC Authentication Provider

Provides authentication against Keycloak and other OIDC-compliant identity providers.
"""

from app.auth_providers.base import BaseAuthProvider, AuthenticationResult
import logging
import requests

logger = logging.getLogger(__name__)


class KeycloakAuthProvider(BaseAuthProvider):
    """Keycloak/OIDC authentication provider"""

    def get_required_config_fields(self):
        """Required configuration fields for Keycloak/OIDC"""
        return [
            'server_url',
            'realm',
            'client_id',
            'client_secret',
        ]

    def authenticate(self, username, password):
        """
        Authenticate user against Keycloak using Resource Owner Password Credentials flow.

        Note: This uses the direct access grant (password) flow, which must be enabled
        in Keycloak client settings.

        Args:
            username: Keycloak username
            password: User password

        Returns:
            AuthenticationResult with user information
        """
        try:
            server_url = self.config['server_url'].rstrip('/')
            realm = self.config['realm']
            client_id = self.config['client_id']
            client_secret = self.config['client_secret']

            # Token endpoint
            token_url = f"{server_url}/realms/{realm}/protocol/openid-connect/token"

            # Request access token
            data = {
                'grant_type': 'password',
                'client_id': client_id,
                'client_secret': client_secret,
                'username': username,
                'password': password,
                'scope': 'openid profile email',
            }

            response = requests.post(token_url, data=data, verify=self.config.get('verify_ssl', True))

            if response.status_code != 200:
                self.logger.warning(f"Keycloak authentication failed for {username}: {response.text}")
                return AuthenticationResult(False, error="Invalid credentials")

            token_data = response.json()
            access_token = token_data.get('access_token')

            # Get user info
            user_info = self._get_userinfo(access_token)

            if not user_info:
                return AuthenticationResult(False, error="Could not retrieve user information")

            # Add username if not in userinfo
            if 'username' not in user_info:
                user_info['username'] = username

            return AuthenticationResult(True, user_info=user_info)

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Keycloak authentication error for {username}: {str(e)}")
            return AuthenticationResult(False, error=f"Connection error: {str(e)}")
        except Exception as e:
            self.logger.error(f"Keycloak authentication error for {username}: {str(e)}")
            return AuthenticationResult(False, error=str(e))

    def _get_userinfo(self, access_token):
        """
        Get user information from Keycloak using access token.

        Args:
            access_token: OAuth2 access token

        Returns:
            Dictionary with user information
        """
        try:
            server_url = self.config['server_url'].rstrip('/')
            realm = self.config['realm']

            userinfo_url = f"{server_url}/realms/{realm}/protocol/openid-connect/userinfo"

            headers = {
                'Authorization': f'Bearer {access_token}',
            }

            response = requests.get(userinfo_url, headers=headers, verify=self.config.get('verify_ssl', True))

            if response.status_code != 200:
                self.logger.warning(f"Could not get userinfo: {response.text}")
                return None

            userinfo = response.json()

            # Map Keycloak userinfo to our user model
            user_data = {
                'external_id': userinfo.get('sub'),
                'username': userinfo.get('preferred_username', userinfo.get('username')),
                'email': userinfo.get('email'),
                'full_name': userinfo.get('name'),
            }

            # Get groups/roles if available
            groups = userinfo.get('groups', [])
            roles = userinfo.get('realm_access', {}).get('roles', [])
            if groups or roles:
                user_data['groups'] = list(set(groups + roles))

            return user_data

        except Exception as e:
            self.logger.error(f"Error getting userinfo: {str(e)}")
            return None

    def test_connection(self):
        """
        Test connection to Keycloak server.

        Returns:
            Tuple of (success, message)
        """
        try:
            server_url = self.config['server_url'].rstrip('/')
            realm = self.config['realm']

            # Try to get realm info
            realm_url = f"{server_url}/realms/{realm}"

            response = requests.get(realm_url, verify=self.config.get('verify_ssl', True), timeout=10)

            if response.status_code != 200:
                return False, f"Could not connect to realm: {response.status_code}"

            realm_info = response.json()

            # Verify client credentials by trying to get token endpoint
            wellknown_url = f"{server_url}/realms/{realm}/.well-known/openid-configuration"
            response = requests.get(wellknown_url, verify=self.config.get('verify_ssl', True), timeout=10)

            if response.status_code != 200:
                return False, "Could not get OIDC configuration"

            return True, f"Connection successful to realm '{realm}'"

        except requests.exceptions.Timeout:
            return False, "Connection timeout"
        except requests.exceptions.RequestException as e:
            return False, f"Connection error: {str(e)}"
        except Exception as e:
            return False, f"Error: {str(e)}"

    def search_users(self, query, limit=10):
        """
        Search for users in Keycloak.

        Note: This requires admin credentials to be configured.

        Args:
            query: Search query string
            limit: Maximum number of results

        Returns:
            List of user dictionaries
        """
        try:
            # Get admin access token
            admin_token = self._get_admin_token()
            if not admin_token:
                self.logger.warning("Cannot search users: admin credentials not configured")
                return []

            server_url = self.config['server_url'].rstrip('/')
            realm = self.config['realm']

            # Search users endpoint
            users_url = f"{server_url}/admin/realms/{realm}/users"

            headers = {
                'Authorization': f'Bearer {admin_token}',
            }

            params = {
                'search': query,
                'max': limit,
            }

            response = requests.get(
                users_url,
                headers=headers,
                params=params,
                verify=self.config.get('verify_ssl', True)
            )

            if response.status_code != 200:
                self.logger.warning(f"User search failed: {response.text}")
                return []

            users_data = response.json()

            users = []
            for user in users_data:
                users.append({
                    'username': user.get('username'),
                    'email': user.get('email'),
                    'full_name': f"{user.get('firstName', '')} {user.get('lastName', '')}".strip(),
                })

            return users

        except Exception as e:
            self.logger.error(f"Keycloak user search error: {str(e)}")
            return []

    def _get_admin_token(self):
        """
        Get admin access token for Keycloak admin API.

        Returns:
            Access token string or None
        """
        try:
            admin_username = self.config.get('admin_username')
            admin_password = self.config.get('admin_password')

            if not admin_username or not admin_password:
                return None

            server_url = self.config['server_url'].rstrip('/')
            realm = self.config['realm']

            # Get token from admin-cli client
            token_url = f"{server_url}/realms/{realm}/protocol/openid-connect/token"

            data = {
                'grant_type': 'password',
                'client_id': self.config.get('admin_client_id', 'admin-cli'),
                'username': admin_username,
                'password': admin_password,
            }

            response = requests.post(token_url, data=data, verify=self.config.get('verify_ssl', True))

            if response.status_code != 200:
                return None

            return response.json().get('access_token')

        except Exception as e:
            self.logger.error(f"Error getting admin token: {str(e)}")
            return None

    def get_user_groups(self, username):
        """
        Get Keycloak groups/roles for a user.

        Args:
            username: Username to get groups for

        Returns:
            List of group names
        """
        try:
            # Get admin access token
            admin_token = self._get_admin_token()
            if not admin_token:
                return []

            server_url = self.config['server_url'].rstrip('/')
            realm = self.config['realm']

            # Find user by username
            users_url = f"{server_url}/admin/realms/{realm}/users"

            headers = {
                'Authorization': f'Bearer {admin_token}',
            }

            params = {
                'username': username,
                'exact': 'true',
            }

            response = requests.get(
                users_url,
                headers=headers,
                params=params,
                verify=self.config.get('verify_ssl', True)
            )

            if response.status_code != 200 or not response.json():
                return []

            user_id = response.json()[0]['id']

            # Get user's groups
            groups_url = f"{server_url}/admin/realms/{realm}/users/{user_id}/groups"

            response = requests.get(
                groups_url,
                headers=headers,
                verify=self.config.get('verify_ssl', True)
            )

            if response.status_code != 200:
                return []

            groups = [group['name'] for group in response.json()]

            return groups

        except Exception as e:
            self.logger.error(f"Error getting Keycloak user groups: {str(e)}")
            return []

    def sync_user_info(self, username):
        """
        Synchronize user information from Keycloak.

        Args:
            username: Username to sync

        Returns:
            Dictionary with updated user information, or None if user not found
        """
        try:
            # Get admin access token
            admin_token = self._get_admin_token()
            if not admin_token:
                return None

            server_url = self.config['server_url'].rstrip('/')
            realm = self.config['realm']

            # Find user by username
            users_url = f"{server_url}/admin/realms/{realm}/users"

            headers = {
                'Authorization': f'Bearer {admin_token}',
            }

            params = {
                'username': username,
                'exact': 'true',
            }

            response = requests.get(
                users_url,
                headers=headers,
                params=params,
                verify=self.config.get('verify_ssl', True)
            )

            if response.status_code != 200 or not response.json():
                return None

            user_data = response.json()[0]

            return {
                'username': user_data.get('username'),
                'email': user_data.get('email'),
                'full_name': f"{user_data.get('firstName', '')} {user_data.get('lastName', '')}".strip(),
                'external_id': user_data.get('id'),
            }

        except Exception as e:
            self.logger.error(f"Error syncing user info: {str(e)}")
            return None
