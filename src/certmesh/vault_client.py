"""
certmesh.vault_client
======================

HashiCorp Vault integration for secret retrieval, certificate storage,
and PKI engine operations (issue & sign).

Supported authentication methods: approle, ldap, aws_iam.

PKI engine support
------------------
``issue_certificate``
    Generate a new certificate and private key via the Vault PKI secrets
    engine ``/issue/:role`` endpoint.

``sign_certificate``
    Sign a client-generated CSR via the Vault PKI secrets engine
    ``/sign/:role`` endpoint.  The private key never leaves the caller.

References
----------
* Vault PKI issue: https://developer.hashicorp.com/vault/api-docs/secret/pki#generate-certificate-and-key
* Vault PKI sign:  https://developer.hashicorp.com/vault/api-docs/secret/pki#sign-certificate
"""

from __future__ import annotations

import logging
import os
from typing import Any

import hvac
from hvac.exceptions import (
    Forbidden,
    InvalidPath,
    Unauthorized,
)
from hvac.exceptions import (
    VaultError as HvacVaultError,
)

from certmesh.exceptions import (
    ConfigurationError,
    VaultAuthenticationError,
    VaultAWSIAMError,
    VaultPKIError,
    VaultSecretNotFoundError,
    VaultWriteError,
)

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]
SecretData = dict[str, str]

_SUPPORTED_AUTH_METHODS: frozenset[str] = frozenset({"approle", "ldap", "aws_iam"})


# =============================================================================
# Client construction
# =============================================================================


def _build_client(vault_cfg: JsonDict) -> hvac.Client:
    """Instantiate an unauthenticated hvac.Client from configuration."""
    return hvac.Client(
        url=vault_cfg["url"],
        verify=vault_cfg.get("tls_verify", True),
        timeout=int(vault_cfg.get("timeout_seconds", 30)),
    )


# =============================================================================
# Authentication methods
# =============================================================================


def _auth_approle(client: hvac.Client, approle_cfg: JsonDict) -> None:
    """Authenticate via the Vault AppRole method."""
    role_id_env: str = approle_cfg["role_id_env"]
    secret_id_env: str = approle_cfg["secret_id_env"]

    role_id = os.environ.get(role_id_env)
    secret_id = os.environ.get(secret_id_env)

    if not role_id:
        raise ConfigurationError(
            f"Environment variable '{role_id_env}' (Vault AppRole role_id) is not set."
        )
    if not secret_id:
        raise ConfigurationError(
            f"Environment variable '{secret_id_env}' (Vault AppRole secret_id) is not set."
        )

    try:
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)
    except (Unauthorized, HvacVaultError) as exc:
        raise VaultAuthenticationError(f"Vault AppRole authentication failed: {exc}.") from exc

    logger.info("Vault: authenticated via AppRole.")


def _auth_ldap(client: hvac.Client, ldap_cfg: JsonDict) -> None:
    """Authenticate via the Vault LDAP / Active Directory auth method."""
    username_env: str = ldap_cfg["username_env"]
    password_env: str = ldap_cfg["password_env"]
    mount_point: str = ldap_cfg.get("mount_point", "ldap")

    username = os.environ.get(username_env)
    password = os.environ.get(password_env)

    if not username:
        raise ConfigurationError(
            f"Environment variable '{username_env}' (Vault LDAP username) is not set."
        )
    if not password:
        raise ConfigurationError(
            f"Environment variable '{password_env}' (Vault LDAP password) is not set."
        )

    try:
        client.auth.ldap.login(
            username=username,
            password=password,
            mount_point=mount_point,
        )
    except (Unauthorized, HvacVaultError) as exc:
        raise VaultAuthenticationError(
            f"Vault LDAP authentication failed for user '{username}' "
            f"(mount_point='{mount_point}'): {exc}."
        ) from exc

    logger.info("Vault: authenticated via LDAP as '%s'.", username)


def _auth_aws_iam(client: hvac.Client, aws_iam_cfg: JsonDict) -> None:
    """Authenticate to Vault via the AWS IAM auth method."""
    vault_role: str = aws_iam_cfg.get("role", "")
    if not vault_role:
        raise ConfigurationError("vault.aws_iam.role is required when auth_method is 'aws_iam'.")

    mount_point: str = aws_iam_cfg.get("mount_point", "aws")
    region: str | None = aws_iam_cfg.get("region") or os.environ.get("AWS_DEFAULT_REGION")
    header_value: str | None = aws_iam_cfg.get("header_value")

    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
    except ImportError as exc:
        raise VaultAWSIAMError(
            "boto3 is required for Vault AWS IAM authentication but is not installed."
        ) from exc

    try:
        session_kwargs: dict[str, str] = {}
        if region:
            session_kwargs["region_name"] = region

        boto_session = boto3.Session(**session_kwargs)
        credentials = boto_session.get_credentials()

        if credentials is None:
            raise VaultAWSIAMError(
                "boto3 could not resolve AWS credentials from the credential chain."
            )

        frozen = credentials.get_frozen_credentials()

    except NoCredentialsError as exc:
        raise VaultAWSIAMError(
            f"No AWS credentials found in the boto3 credential chain: {exc}"
        ) from exc
    except (BotoCoreError, ClientError) as exc:
        raise VaultAWSIAMError(f"boto3 credential resolution failed: {exc}") from exc

    try:
        login_kwargs: dict[str, Any] = {
            "access_key": frozen.access_key,
            "secret_key": frozen.secret_key,
            "session_token": frozen.token,
            "role": vault_role,
            "use_token": True,
            "mount_point": mount_point,
        }
        if header_value:
            login_kwargs["header_value"] = header_value

        client.auth.aws.iam_login(**login_kwargs)

    except (Unauthorized, HvacVaultError) as exc:
        raise VaultAWSIAMError(
            f"Vault AWS IAM login rejected for role '{vault_role}' "
            f"(mount_point='{mount_point}'): {exc}."
        ) from exc

    logger.info("Vault: authenticated via AWS IAM (role='%s').", vault_role)


# =============================================================================
# Public entry point
# =============================================================================


def get_authenticated_client(vault_cfg: JsonDict) -> hvac.Client:
    """Build and authenticate an hvac.Client using the configured auth method."""
    client = _build_client(vault_cfg)
    auth_method: str = vault_cfg.get("auth_method", "approle")

    if auth_method not in _SUPPORTED_AUTH_METHODS:
        raise ConfigurationError(
            f"Unsupported vault.auth_method '{auth_method}'. "
            f"Supported values: {sorted(_SUPPORTED_AUTH_METHODS)}"
        )

    logger.debug("Vault: authenticating via method '%s'.", auth_method)

    if auth_method == "approle":
        if "approle" not in vault_cfg:
            raise ConfigurationError(
                "vault.auth_method is 'approle' but vault.approle section is absent."
            )
        _auth_approle(client, vault_cfg["approle"])
    elif auth_method == "ldap":
        if "ldap" not in vault_cfg:
            raise ConfigurationError(
                "vault.auth_method is 'ldap' but vault.ldap section is absent."
            )
        _auth_ldap(client, vault_cfg["ldap"])
    elif auth_method == "aws_iam":
        if "aws_iam" not in vault_cfg:
            raise ConfigurationError(
                "vault.auth_method is 'aws_iam' but vault.aws_iam section is absent."
            )
        _auth_aws_iam(client, vault_cfg["aws_iam"])

    if not client.is_authenticated():
        raise VaultAuthenticationError(
            f"Vault '{auth_method}' auth appeared to succeed but "
            "is_authenticated() returned False."
        )

    return client


# =============================================================================
# KV v2 read helpers
# =============================================================================


def _split_path(path: str) -> tuple[str, str]:
    """Split ``mount/sub/path`` into ``(mount_point, sub_path)``."""
    parts = path.split("/", 1)
    if len(parts) != 2 or not parts[1]:
        raise VaultSecretNotFoundError(
            f"Vault path '{path}' is invalid. Expected format: 'mount_point/sub/path'."
        )
    return parts[0], parts[1]


def read_secret_field(client: hvac.Client, path: str, field: str) -> str:
    """Read a single field from a Vault KV v2 secret."""
    data = read_all_secret_fields(client, path)
    if field not in data:
        raise VaultSecretNotFoundError(
            f"Field '{field}' not found in Vault secret at '{path}'. "
            f"Available fields: {sorted(data.keys())}"
        )
    return data[field]


def read_all_secret_fields(client: hvac.Client, path: str) -> SecretData:
    """Read all key-value fields from a Vault KV v2 secret."""
    mount_point, sub_path = _split_path(path)

    try:
        response: JsonDict = client.secrets.kv.v2.read_secret_version(
            path=sub_path,
            mount_point=mount_point,
        )
    except InvalidPath as exc:
        raise VaultSecretNotFoundError(f"Vault secret not found at path '{path}'.") from exc
    except (Forbidden, Unauthorized) as exc:
        raise VaultAuthenticationError(
            f"Access denied reading Vault path '{path}': {exc}"
        ) from exc
    except HvacVaultError as exc:
        raise VaultSecretNotFoundError(f"Failed to read Vault secret at '{path}': {exc}") from exc

    return response.get("data", {}).get("data", {})


# =============================================================================
# KV v2 write helper
# =============================================================================


def write_secret(client: hvac.Client, path: str, data: SecretData) -> None:
    """Write or update key-value data in a Vault KV v2 secret path."""
    mount_point, sub_path = _split_path(path)

    try:
        client.secrets.kv.v2.create_or_update_secret(
            path=sub_path,
            secret=data,
            mount_point=mount_point,
        )
    except (Forbidden, Unauthorized) as exc:
        raise VaultAuthenticationError(
            f"Access denied writing to Vault path '{path}': {exc}"
        ) from exc
    except HvacVaultError as exc:
        raise VaultWriteError(f"Failed to write to Vault path '{path}': {exc}") from exc

    logger.info("Vault: wrote %d field(s) to path '%s'.", len(data), path)


# =============================================================================
# PKI engine: issue certificate
# =============================================================================


def issue_pki_certificate(
    client: hvac.Client,
    pki_cfg: JsonDict,
    common_name: str,
    *,
    alt_names: list[str] | None = None,
    ttl: str | None = None,
    ip_sans: list[str] | None = None,
) -> JsonDict:
    """
    Issue a new certificate and private key from the Vault PKI engine.

    Calls ``POST /v1/{mount_point}/issue/{role_name}`` which generates
    a private key server-side and returns it along with the certificate.

    Args:
        client: An authenticated hvac.Client.
        pki_cfg: The ``vault.pki`` section of the application config.
        common_name: The CN for the certificate.
        alt_names: Optional list of Subject Alternative Names.
        ttl: Optional TTL string (e.g. ``"720h"``). Defaults to config value.
        ip_sans: Optional list of IP SANs.

    Returns:
        Dict with keys: ``certificate``, ``issuing_ca``, ``ca_chain``,
        ``private_key``, ``private_key_type``, ``serial_number``,
        ``expiration``.

    Raises:
        VaultPKIError: If the PKI issue request fails.
        ConfigurationError: If required config is missing.
    """
    mount_point: str = pki_cfg.get("mount_point", "pki")
    role_name: str = pki_cfg.get("role_name", "")

    if not role_name:
        raise ConfigurationError(
            "vault.pki.role_name is required for PKI operations. Set CM_VAULT_PKI_ROLE."
        )

    extra_params: dict[str, Any] = {}
    if alt_names:
        extra_params["alt_names"] = ",".join(alt_names)
    if ip_sans:
        extra_params["ip_sans"] = ",".join(ip_sans)
    effective_ttl = ttl or pki_cfg.get("ttl", "8760h")
    if effective_ttl:
        extra_params["ttl"] = effective_ttl

    try:
        response = client.secrets.pki.generate_certificate(
            name=role_name,
            common_name=common_name,
            mount_point=mount_point,
            extra_params=extra_params,
        )
    except (Forbidden, Unauthorized) as exc:
        raise VaultAuthenticationError(
            f"Access denied issuing PKI certificate from '{mount_point}': {exc}"
        ) from exc
    except HvacVaultError as exc:
        raise VaultPKIError(
            f"Vault PKI issue failed for CN='{common_name}' "
            f"(mount='{mount_point}', role='{role_name}'): {exc}"
        ) from exc

    data: JsonDict = response.get("data", {})
    if not data.get("certificate"):
        raise VaultPKIError(f"Vault PKI issue returned no certificate for CN='{common_name}'.")

    logger.info(
        "Vault PKI: issued certificate for CN='%s' (serial=%s, mount='%s', role='%s').",
        common_name,
        data.get("serial_number", "unknown"),
        mount_point,
        role_name,
    )
    return data


# =============================================================================
# PKI engine: sign CSR
# =============================================================================


def sign_pki_certificate(
    client: hvac.Client,
    pki_cfg: JsonDict,
    common_name: str,
    csr: str,
    *,
    alt_names: list[str] | None = None,
    ttl: str | None = None,
    ip_sans: list[str] | None = None,
) -> JsonDict:
    """
    Sign a client-generated CSR using the Vault PKI engine.

    Calls ``POST /v1/{mount_point}/sign/{role_name}``.  The private key
    never leaves the caller.

    Args:
        client: An authenticated hvac.Client.
        pki_cfg: The ``vault.pki`` section of the application config.
        common_name: The CN for the certificate.
        csr: PEM-encoded Certificate Signing Request.
        alt_names: Optional list of Subject Alternative Names.
        ttl: Optional TTL string.
        ip_sans: Optional list of IP SANs.

    Returns:
        Dict with keys: ``certificate``, ``issuing_ca``, ``ca_chain``,
        ``serial_number``, ``expiration``.

    Raises:
        VaultPKIError: If the PKI sign request fails.
        ConfigurationError: If required config is missing.
    """
    mount_point: str = pki_cfg.get("mount_point", "pki")
    role_name: str = pki_cfg.get("role_name", "")

    if not role_name:
        raise ConfigurationError(
            "vault.pki.role_name is required for PKI operations. Set CM_VAULT_PKI_ROLE."
        )

    extra_params: dict[str, Any] = {}
    if alt_names:
        extra_params["alt_names"] = ",".join(alt_names)
    if ip_sans:
        extra_params["ip_sans"] = ",".join(ip_sans)
    effective_ttl = ttl or pki_cfg.get("ttl", "8760h")
    if effective_ttl:
        extra_params["ttl"] = effective_ttl

    try:
        response = client.secrets.pki.sign_certificate(
            name=role_name,
            csr=csr,
            common_name=common_name,
            mount_point=mount_point,
            extra_params=extra_params,
        )
    except (Forbidden, Unauthorized) as exc:
        raise VaultAuthenticationError(
            f"Access denied signing CSR via Vault PKI '{mount_point}': {exc}"
        ) from exc
    except HvacVaultError as exc:
        raise VaultPKIError(
            f"Vault PKI sign failed for CN='{common_name}' "
            f"(mount='{mount_point}', role='{role_name}'): {exc}"
        ) from exc

    data: JsonDict = response.get("data", {})
    if not data.get("certificate"):
        raise VaultPKIError(f"Vault PKI sign returned no certificate for CN='{common_name}'.")

    logger.info(
        "Vault PKI: signed CSR for CN='%s' (serial=%s, mount='%s', role='%s').",
        common_name,
        data.get("serial_number", "unknown"),
        mount_point,
        role_name,
    )
    return data


# =============================================================================
# PKI engine: revoke certificate
# =============================================================================


def revoke_pki_certificate(
    client: hvac.Client,
    pki_cfg: JsonDict,
    serial_number: str,
) -> JsonDict:
    """
    Revoke a certificate by serial number in the Vault PKI engine.

    Args:
        client: An authenticated hvac.Client.
        pki_cfg: The ``vault.pki`` section of the application config.
        serial_number: The serial number of the certificate to revoke.

    Returns:
        The revocation response data from Vault.

    Raises:
        VaultPKIError: If the revocation fails.
    """
    mount_point: str = pki_cfg.get("mount_point", "pki")

    try:
        response = client.secrets.pki.revoke_certificate(
            serial_number=serial_number,
            mount_point=mount_point,
        )
    except (Forbidden, Unauthorized) as exc:
        raise VaultAuthenticationError(
            f"Access denied revoking certificate '{serial_number}' in '{mount_point}': {exc}"
        ) from exc
    except HvacVaultError as exc:
        raise VaultPKIError(
            f"Vault PKI revoke failed for serial='{serial_number}' (mount='{mount_point}'): {exc}"
        ) from exc

    logger.info(
        "Vault PKI: revoked certificate serial='%s' (mount='%s').",
        serial_number,
        mount_point,
    )
    return response.get("data", {})


# =============================================================================
# PKI engine: list certificates
# =============================================================================


def list_pki_certificates(
    client: hvac.Client,
    pki_cfg: JsonDict,
) -> list[str]:
    """
    List all certificate serial numbers from the Vault PKI engine.

    Args:
        client: An authenticated hvac.Client.
        pki_cfg: The ``vault.pki`` section of the application config.

    Returns:
        List of serial number strings.

    Raises:
        VaultPKIError: If the list request fails.
    """
    mount_point: str = pki_cfg.get("mount_point", "pki")

    try:
        response = client.secrets.pki.list_certificates(mount_point=mount_point)
    except (Forbidden, Unauthorized) as exc:
        raise VaultAuthenticationError(
            f"Access denied listing certificates in '{mount_point}': {exc}"
        ) from exc
    except HvacVaultError as exc:
        raise VaultPKIError(
            f"Vault PKI list certificates failed (mount='{mount_point}'): {exc}"
        ) from exc

    keys: list[str] = response.get("data", {}).get("keys", [])
    logger.info("Vault PKI: listed %d certificate(s) (mount='%s').", len(keys), mount_point)
    return keys


# =============================================================================
# PKI engine: read certificate
# =============================================================================


def read_pki_certificate(
    client: hvac.Client,
    pki_cfg: JsonDict,
    serial_number: str,
) -> JsonDict:
    """
    Read a certificate by serial number from the Vault PKI engine.

    Args:
        client: An authenticated hvac.Client.
        pki_cfg: The ``vault.pki`` section of the application config.
        serial_number: The serial number of the certificate.

    Returns:
        Dict with ``certificate`` and ``revocation_time`` keys.

    Raises:
        VaultPKIError: If the read request fails.
    """
    mount_point: str = pki_cfg.get("mount_point", "pki")

    try:
        response = client.secrets.pki.read_certificate(
            serial=serial_number,
            mount_point=mount_point,
        )
    except (Forbidden, Unauthorized) as exc:
        raise VaultAuthenticationError(
            f"Access denied reading certificate '{serial_number}' in '{mount_point}': {exc}"
        ) from exc
    except HvacVaultError as exc:
        raise VaultPKIError(
            f"Vault PKI read certificate failed for serial='{serial_number}' "
            f"(mount='{mount_point}'): {exc}"
        ) from exc

    return response.get("data", {})
