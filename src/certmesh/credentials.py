"""
certmesh.credentials
=====================

Secret resolution with environment-first, Vault-fallback semantics.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import hvac

from certmesh.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

_ENV_DIGICERT_API_KEY = "CM_DIGICERT_API_KEY"
_ENV_VENAFI_USERNAME = "CM_VENAFI_USERNAME"
_ENV_VENAFI_PASSWORD = "CM_VENAFI_PASSWORD"


# =============================================================================
# Vault requirement checks
# =============================================================================


def vault_required_for_digicert() -> bool:
    """Return True when Vault is needed to resolve the DigiCert API key."""
    return not bool(os.environ.get(_ENV_DIGICERT_API_KEY))


def vault_required_for_venafi() -> bool:
    """Return True when Vault is needed to resolve Venafi AD credentials."""
    has_user = bool(os.environ.get(_ENV_VENAFI_USERNAME))
    has_pass = bool(os.environ.get(_ENV_VENAFI_PASSWORD))
    if has_user != has_pass:
        raise ConfigurationError(
            f"Both {_ENV_VENAFI_USERNAME} and {_ENV_VENAFI_PASSWORD} must be set "
            "together to bypass Vault for Venafi credentials."
        )
    return not has_user


def vault_required(cfg: JsonDict) -> bool:
    """Return True if any configured component requires a live Vault client."""
    return vault_required_for_digicert() or vault_required_for_venafi()


# =============================================================================
# Secret resolvers
# =============================================================================


def resolve_digicert_api_key(
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
) -> str:
    """Resolve the DigiCert CertCentral API key."""
    from certmesh import vault_client as _vc

    api_key = os.environ.get(_ENV_DIGICERT_API_KEY)
    if api_key:
        logger.debug("DigiCert API key resolved from environment variable.")
        return api_key

    if vault_cl is None:
        raise ConfigurationError(
            f"No DigiCert API key available: '{_ENV_DIGICERT_API_KEY}' is not set "
            "and no Vault client was provided."
        )

    path: str = vault_cfg["paths"]["digicert_api_key"]
    key = _vc.read_secret_field(vault_cl, path, "value")
    logger.debug("DigiCert API key resolved from Vault path '%s'.", path)
    return key


def resolve_venafi_credentials(
    vault_cfg: JsonDict,
    vault_cl: hvac.Client | None,
) -> dict[str, str]:
    """Resolve Venafi TPP Active Directory credentials."""
    from certmesh import vault_client as _vc

    username = os.environ.get(_ENV_VENAFI_USERNAME)
    password = os.environ.get(_ENV_VENAFI_PASSWORD)

    if username and password:
        logger.debug("Venafi credentials resolved from environment variables.")
        return {"username": username, "password": password}

    if bool(username) != bool(password):
        raise ConfigurationError(
            f"Both {_ENV_VENAFI_USERNAME} and {_ENV_VENAFI_PASSWORD} must be set together."
        )

    if vault_cl is None:
        raise ConfigurationError(
            f"No Venafi credentials available: '{_ENV_VENAFI_USERNAME}' / "
            f"'{_ENV_VENAFI_PASSWORD}' are not set and no Vault client was provided."
        )

    path: str = vault_cfg["paths"]["venafi_credentials"]
    data = _vc.read_all_secret_fields(vault_cl, path)
    logger.debug("Venafi credentials resolved from Vault path '%s'.", path)
    return data
