# SSO and External Authentication Guide

This document provides comprehensive information on configuring and using external authentication providers (SSO) with the Jira Worklog Manager.

## Table of Contents

1. [Overview](#overview)
2. [Supported Authentication Providers](#supported-authentication-providers)
3. [Installation and Setup](#installation-and-setup)
4. [Configuring Authentication Providers](#configuring-authentication-providers)
5. [LDAP Configuration](#ldap-configuration)
6. [Active Directory Configuration](#active-directory-configuration)
7. [FreeIPA Configuration](#freeipa-configuration)
8. [Keycloak/OIDC Configuration](#keycloakoidc-configuration)
9. [User Management](#user-management)
10. [Troubleshooting](#troubleshooting)
11. [Security Considerations](#security-considerations)

---

## Overview

The Jira Worklog Manager supports authentication against external identity providers, allowing you to:

- **Centralize authentication** - Use your existing identity management system
- **Auto-provision users** - Automatically create users on first login
- **Maintain user information** - Sync email, full name, and other attributes
- **Support multiple providers** - Configure multiple authentication sources
- **Seamless fallback** - Falls back to local authentication if needed

### How It Works

1. User enters credentials on the login page
2. System tries local authentication first
3. If local auth fails, tries each enabled external provider in order
4. If authentication succeeds, user is logged in
5. User account is created automatically (if auto-create is enabled)
6. User information is synchronized from the provider

---

## Supported Authentication Providers

### 1. LDAP (Lightweight Directory Access Protocol)
- **Use for:** Generic LDAP directories, OpenLDAP
- **Protocol:** LDAP v3
- **Features:** User authentication, attribute sync, group membership

### 2. Active Directory (Microsoft)
- **Use for:** Microsoft Active Directory domains
- **Protocol:** LDAP with NTLM authentication
- **Features:** Domain authentication, group sync, user attributes

### 3. FreeIPA (Identity Management)
- **Use for:** FreeIPA/Red Hat Identity Management
- **Protocol:** LDAP with FreeIPA-specific attributes
- **Features:** Kerberos integration, group sync, unique ID support

### 4. Keycloak/OIDC (OpenID Connect)
- **Use for:** Keycloak, OAuth2/OIDC providers
- **Protocol:** OpenID Connect (OAuth 2.0)
- **Features:** SSO, token-based auth, role/group sync

---

## Installation and Setup

### Prerequisites

- Admin access to the Jira Worklog Manager
- Access to your authentication provider (LDAP, AD, Keycloak, etc.)
- Service account credentials for the authentication provider

### Step 1: Install Dependencies

Install the required Python libraries:

```bash
pip install -r requirements.txt
```

New dependencies include:
- `ldap3` - LDAP client library
- `python-ldap` - Additional LDAP support
- `Authlib` - OAuth/OIDC client library
- `python-keycloak` - Keycloak integration

### Step 2: Run Database Migration

Migrate your database to add SSO support:

```bash
python migrate_sso.py
```

This adds:
- `AuthProvider` table for storing provider configurations
- New User fields: `email`, `full_name`, `auth_provider_id`, `external_id`, `last_login`, `created_at`

### Step 3: Access Admin Dashboard

1. Log in as an admin user
2. Navigate to **Admin Dashboard**
3. Click on **Authentication Providers** (you'll need to add this link to the dashboard)

---

## Configuring Authentication Providers

### General Configuration Steps

1. Go to **Admin Dashboard** → **Authentication Providers**
2. Click **Add Authentication Provider**
3. Fill in the provider details:
   - **Provider Name:** Friendly name (e.g., "Company LDAP")
   - **Provider Type:** Select the type (LDAP, AD, FreeIPA, Keycloak)
   - **Enabled:** Check to enable this provider
   - **Default Provider:** Check if this should be the default
   - **Auto-create Users:** Check to auto-create users on first login
4. Configure provider-specific settings (see sections below)
5. Click **Test Connection** to verify configuration
6. **Save** the provider

### Provider Priority

Authentication attempts in this order:
1. Local database (if user exists with password)
2. Default provider (if marked as default)
3. Other enabled providers (in order of creation)

---

## LDAP Configuration

### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| Server URI | LDAP server URL | `ldap://ldap.example.com:389` or `ldaps://ldap.example.com:636` |
| Base DN | Base Distinguished Name | `dc=example,dc=com` |
| Bind DN Template | Template for user DN | `uid={username},ou=people,dc=example,dc=com` |

### Optional Fields

| Field | Description | Default |
|-------|-------------|---------|
| Use SSL | Enable SSL/TLS | True |
| Start TLS | Use StartTLS | False |
| Search Filter | User search filter | `(uid={username})` |
| Test Bind DN | Admin/test user DN | - |
| Test Bind Password | Password for test user | - |

### Example Configuration

```
Server URI: ldaps://ldap.company.com:636
Base DN: dc=company,dc=com
Bind DN Template: uid={username},ou=users,dc=company,dc=com
Use SSL: Yes
Search Filter: (uid={username})
Test Bind DN: cn=admin,dc=company,dc=com
Test Bind Password: [admin-password]
```

### Attribute Mapping

The system maps these LDAP attributes to user fields:
- `uid` → `username`
- `mail` → `email`
- `cn` or `displayName` → `full_name`
- DN → `external_id`

---

## Active Directory Configuration

### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| Server URI | AD server URL | `ldap://dc.example.com:389` or `ldaps://dc.example.com:636` |
| Domain | AD domain name | `example.com` or `EXAMPLE` |
| Base DN | Base for searches | `dc=example,dc=com` |

### Optional Fields

| Field | Description |
|-------|-------------|
| Use SSL | Enable LDAPS |
| Test Bind DN | Admin username (can be UPN or sAMAccountName) |
| Test Bind Password | Admin password |

### Example Configuration

```
Server URI: ldaps://dc.company.com:636
Domain: company.com
Base DN: dc=company,dc=com
Use SSL: Yes
Test Bind DN: admin@company.com
Test Bind Password: [admin-password]
```

### Authentication Formats Supported

Users can log in with any of these formats:
- UPN: `username@company.com`
- sAMAccountName: `username`
- Domain\User: `COMPANY\username`

### Attribute Mapping

- `sAMAccountName` → `username`
- `mail` or `userPrincipalName` → `email`
- `displayName` or `givenName + sn` → `full_name`
- `memberOf` → groups
- DN → `external_id`

---

## FreeIPA Configuration

### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| Server URI | FreeIPA server URL | `ldaps://ipa.example.com:636` |
| Base DN | IPA base DN | `dc=example,dc=com` |

### Optional Fields

| Field | Description |
|-------|-------------|
| Use SSL | Enable LDAPS (recommended) |
| Test Bind DN | Admin bind DN |
| Test Bind Password | Admin password |

### Example Configuration

```
Server URI: ldaps://ipa.company.com:636
Base DN: dc=company,dc=com
Use SSL: Yes
Test Bind DN: uid=admin,cn=users,dc=company,dc=com
Test Bind Password: [admin-password]
```

### FreeIPA-Specific Features

- Automatic user DN construction: `uid={username},cn=users,{base_dn}`
- Support for `ipaUniqueID` attribute
- Group membership via `memberOf`
- User container: `cn=users,{base_dn}`

### Attribute Mapping

- `uid` → `username`
- `mail` → `email`
- `displayName` or `cn` or `givenName + sn` → `full_name`
- `ipaUniqueID` or DN → `external_id`
- `memberOf` → groups

---

## Keycloak/OIDC Configuration

### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| Server URL | Keycloak base URL | `https://keycloak.example.com` |
| Realm | Keycloak realm name | `master` or `company-realm` |
| Client ID | OAuth2 client ID | `jira-worklog-manager` |
| Client Secret | OAuth2 client secret | `[secret]` |

### Optional Fields (for Admin API)

| Field | Description |
|-------|-------------|
| Admin Username | Keycloak admin username |
| Admin Password | Keycloak admin password |
| Admin Client ID | Admin client ID (default: `admin-cli`) |
| Verify SSL | Verify SSL certificates |

### Example Configuration

```
Server URL: https://keycloak.company.com
Realm: company
Client ID: jira-worklog
Client Secret: abc123-secret-xyz789
Verify SSL: Yes
Admin Username: admin
Admin Password: [admin-password]
```

### Keycloak Client Setup

1. **Create a new client** in Keycloak:
   - Client ID: `jira-worklog-manager`
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`

2. **Enable Direct Access Grants:**
   - Settings → Direct Access Grants Enabled: `ON`
   - This allows password-based authentication

3. **Configure Client Scopes:**
   - Add scopes: `openid`, `profile`, `email`
   - Optionally add `groups` for group sync

4. **Get Client Secret:**
   - Credentials tab → Copy the secret

### Attribute Mapping

- `preferred_username` or `username` → `username`
- `email` → `email`
- `name` → `full_name`
- `sub` → `external_id`
- `groups` and `realm_access.roles` → groups

### Authentication Flow

Keycloak uses the Resource Owner Password Credentials flow:
1. User enters username/password
2. System requests access token from Keycloak
3. Keycloak validates credentials
4. System retrieves user information from userinfo endpoint
5. User is created/updated in local database

---

## User Management

### Auto-Created Users

When **Auto-create Users** is enabled:
- Users are automatically created on first successful login
- User information is synced from the provider
- No password is stored locally (authentication is always via provider)

### User Attributes

External users have these attributes synced:
- `username` - Required, from provider
- `email` - From LDAP `mail` or OIDC `email`
- `full_name` - From LDAP `cn`/`displayName` or OIDC `name`
- `external_id` - Unique ID from provider (DN, UUID, sub)
- `auth_provider_id` - Links to authentication provider
- `last_login` - Updated on each login

### Manual User Creation

Admins can still create local users:
1. Regular registration (local authentication)
2. External users created automatically on first login

### User Updates

User information is updated from the provider on each login:
- Email address
- Full name
- External ID
- Last login timestamp

### Disabling External Authentication

To switch a user back to local authentication:
1. Admin sets a local password
2. Remove `auth_provider_id` (set to NULL)
3. User can now authenticate locally

---

## Troubleshooting

### Connection Test Fails

**LDAP/AD/FreeIPA:**
- Verify server URI is correct and reachable
- Check firewall rules (port 389 for LDAP, 636 for LDAPS)
- Ensure SSL certificate is valid (or disable SSL verification for testing)
- Verify base DN is correct
- Check test bind credentials

**Keycloak:**
- Verify server URL is accessible
- Check realm name is correct
- Ensure client ID exists
- Verify client secret is correct
- Check SSL certificate

### Authentication Fails

**User not found:**
- Check auto-create users is enabled
- Verify user exists in the provider
- Check search filter/DN template

**Invalid credentials:**
- Test credentials directly against the provider
- Check username format (UPN vs sAMAccountName for AD)
- Verify password is correct

**User created but can't login:**
- Check provider is enabled
- Verify user's auth_provider_id matches the provider
- Check logs for error messages

### Check Logs

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Logs show:
- Authentication attempts
- Provider connection attempts
- User creation/updates
- Error details

### Common Issues

1. **LDAP SSL Certificate Error:**
   - Solution: Disable SSL verification or install CA certificate

2. **AD Authentication Fails:**
   - Try different username formats (UPN, domain\user, sAMAccountName)
   - Ensure NTLM authentication is enabled

3. **Keycloak Direct Access Disabled:**
   - Solution: Enable "Direct Access Grants" in client settings

4. **User Auto-Creation Fails:**
   - Check database permissions
   - Verify username doesn't conflict with existing user
   - Check logs for specific error

---

## Security Considerations

### Password Storage

- **External users:** No password stored locally
- **Local users:** Passwords hashed with bcrypt
- **Provider credentials:** Encrypted with Fernet symmetric encryption

### Encryption

All sensitive provider configurations are encrypted:
- LDAP bind passwords
- AD admin passwords
- Keycloak client secrets
- Stored in database as encrypted binary data

### SSL/TLS

**Recommendations:**
- Always use SSL/TLS for production (LDAPS, HTTPS)
- Use valid SSL certificates
- For testing only, you can disable SSL verification

### Access Control

- Only admins can configure authentication providers
- Provider configurations are encrypted
- Users cannot view provider settings
- Test credentials should have minimal privileges

### Service Accounts

Create dedicated service accounts for provider testing:
- LDAP/AD: Read-only account in directory
- Keycloak: Separate admin account with limited scope

### Audit Trail

The system logs:
- Authentication attempts (success/failure)
- Provider configuration changes
- User creation from external providers
- All administrator actions

### Data Privacy

- User information synced from providers may include email, name
- External IDs stored for account linking
- No password data stored for external users
- Users can be deleted, removing all associated data

---

## Advanced Configuration

### Multiple Providers

You can configure multiple providers:
- Users authenticate against the first matching provider
- Useful for migration scenarios or multi-domain environments

### Provider Priority

Set one provider as **Default** to try it first after local authentication.

### Selective Auto-Creation

Disable auto-create to require manual user approval:
1. Create users manually in admin dashboard
2. Link to external provider by setting username
3. User authenticates via provider

### Attribute Customization

For LDAP providers, customize attribute mapping in the configuration:

```python
attribute_mapping = {
    'email': 'mail',
    'full_name': 'displayName'
}
```

### Group Sync

Groups from providers can be retrieved but are not currently used for authorization. Future enhancements may include role mapping from provider groups.

---

## API Reference

### Authentication Provider Model

```python
class AuthProvider:
    id: int
    name: str                    # Display name
    provider_type: str           # ldap, ad, freeipa, keycloak
    is_enabled: bool            # Whether provider is active
    is_default: bool            # Try this provider first
    auto_create_users: bool     # Auto-create users on login
    config_encrypted: bytes     # Encrypted configuration JSON
    created_at: datetime
    updated_at: datetime
```

### User Model Extensions

```python
class User:
    # ... existing fields ...
    email: str                  # User email from provider
    full_name: str              # Full name from provider
    auth_provider_id: int       # FK to AuthProvider
    external_id: str            # Unique ID from provider
    last_login: datetime        # Last successful login
    created_at: datetime        # Account creation time
```

---

## Support and Resources

### Documentation

- [LDAP Documentation](https://ldap.com/)
- [Active Directory Documentation](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/)
- [FreeIPA Documentation](https://www.freeipa.org/page/Documentation)
- [Keycloak Documentation](https://www.keycloak.org/documentation)

### Testing Tools

- **ldapsearch:** Test LDAP queries
- **AD Users and Computers:** Verify AD user attributes
- **Keycloak Admin Console:** Test OAuth flows
- **curl:** Test HTTP/HTTPS connectivity

### Getting Help

For issues or questions:
1. Check logs for error messages
2. Test connection from command line
3. Verify provider configuration
4. Check firewall and network connectivity
5. Review this documentation
6. Contact your system administrator

---

## Migration Guide

### From Local to External Authentication

To migrate existing local users to external authentication:

1. **Configure Authentication Provider:**
   - Set up LDAP/AD/Keycloak provider
   - Disable auto-create users initially

2. **Match Usernames:**
   - Ensure local usernames match provider usernames
   - Update usernames if necessary

3. **Link Accounts:**
   - For each user, set `auth_provider_id` to the provider
   - Set `external_id` to their provider ID
   - Clear `password_hash` (optional, for security)

4. **Enable Auto-Create:**
   - Once existing users are migrated
   - Enable auto-create for new users

### From One Provider to Another

1. Configure new provider
2. For each user:
   - Update `auth_provider_id`
   - Update `external_id`
3. Disable old provider
4. Delete old provider when all users migrated

---

## Changelog

### Version 2.0 (Current)
- Added LDAP authentication support
- Added Active Directory authentication support
- Added FreeIPA authentication support
- Added Keycloak/OIDC authentication support
- Auto-provisioning of users from external providers
- Attribute synchronization on login
- Multiple provider support
- Encrypted provider configuration storage

---

## License

This feature is part of the Jira Worklog Manager and follows the same license terms.
