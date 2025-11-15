"""
Authentication provider backends for external authentication systems.
"""

from app.auth_providers.base import BaseAuthProvider
from app.auth_providers.ldap_provider import LDAPAuthProvider
from app.auth_providers.ad_provider import ActiveDirectoryAuthProvider
from app.auth_providers.freeipa_provider import FreeIPAAuthProvider
from app.auth_providers.keycloak_provider import KeycloakAuthProvider

# Map provider types to their implementations
PROVIDER_MAP = {
    'ldap': LDAPAuthProvider,
    'ad': ActiveDirectoryAuthProvider,
    'freeipa': FreeIPAAuthProvider,
    'keycloak': KeycloakAuthProvider,
}


def get_auth_provider(provider_type, config):
    """
    Factory function to get the appropriate auth provider instance.

    Args:
        provider_type: Type of provider ('ldap', 'ad', 'freeipa', 'keycloak')
        config: Configuration dictionary for the provider

    Returns:
        Instance of the appropriate auth provider

    Raises:
        ValueError: If provider_type is not supported
    """
    provider_class = PROVIDER_MAP.get(provider_type)
    if not provider_class:
        raise ValueError(f"Unsupported provider type: {provider_type}")

    return provider_class(config)


__all__ = [
    'BaseAuthProvider',
    'LDAPAuthProvider',
    'ActiveDirectoryAuthProvider',
    'FreeIPAAuthProvider',
    'KeycloakAuthProvider',
    'get_auth_provider',
    'PROVIDER_MAP',
]
