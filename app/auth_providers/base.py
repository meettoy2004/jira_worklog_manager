"""
Base authentication provider class.

All authentication providers must inherit from this class and implement
the required methods.
"""

from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


class AuthenticationResult:
    """Result of an authentication attempt"""

    def __init__(self, success, user_info=None, error=None):
        """
        Initialize authentication result.

        Args:
            success: Boolean indicating if authentication succeeded
            user_info: Dictionary containing user information if successful
            error: Error message if authentication failed
        """
        self.success = success
        self.user_info = user_info or {}
        self.error = error

    def __bool__(self):
        return self.success

    def __repr__(self):
        if self.success:
            return f"<AuthenticationResult success=True user={self.user_info.get('username')}>"
        return f"<AuthenticationResult success=False error={self.error}>"


class BaseAuthProvider(ABC):
    """Base class for all authentication providers"""

    def __init__(self, config):
        """
        Initialize the authentication provider.

        Args:
            config: Configuration dictionary for this provider
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    @abstractmethod
    def authenticate(self, username, password):
        """
        Authenticate a user with username and password.

        Args:
            username: Username to authenticate
            password: Password for authentication

        Returns:
            AuthenticationResult object with success status and user info

        User info dictionary should contain:
            - username: str (required)
            - email: str (optional)
            - full_name: str (optional)
            - external_id: str (optional)
            - groups: list (optional)
        """
        pass

    @abstractmethod
    def test_connection(self):
        """
        Test the connection to the authentication provider.

        Returns:
            Tuple of (success: bool, message: str)
        """
        pass

    @abstractmethod
    def search_users(self, query, limit=10):
        """
        Search for users in the authentication provider.

        Args:
            query: Search query string
            limit: Maximum number of results to return

        Returns:
            List of user dictionaries matching the query
        """
        pass

    def get_user_groups(self, username):
        """
        Get groups/roles for a user from the authentication provider.

        Args:
            username: Username to get groups for

        Returns:
            List of group names (optional, default implementation returns empty list)
        """
        return []

    def sync_user_info(self, username):
        """
        Synchronize user information from the authentication provider.

        Args:
            username: Username to sync

        Returns:
            Dictionary with updated user information, or None if user not found
        """
        return None

    def validate_config(self):
        """
        Validate the provider configuration.

        Returns:
            Tuple of (is_valid: bool, errors: list)
        """
        errors = []

        # Subclasses should override this to add their own validation
        required_fields = self.get_required_config_fields()
        for field in required_fields:
            if field not in self.config or not self.config[field]:
                errors.append(f"Required field '{field}' is missing or empty")

        return len(errors) == 0, errors

    @abstractmethod
    def get_required_config_fields(self):
        """
        Get list of required configuration fields for this provider.

        Returns:
            List of required field names
        """
        pass

    def get_provider_info(self):
        """
        Get information about this provider type.

        Returns:
            Dictionary with provider information
        """
        return {
            'name': self.__class__.__name__,
            'type': self.config.get('type', 'unknown'),
            'description': self.__doc__ or 'No description available',
        }

    def __repr__(self):
        return f"<{self.__class__.__name__} config={self.config}>"
