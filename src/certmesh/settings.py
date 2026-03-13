"""
certmesh.settings
==================

Environment-variable-first configuration layer.

Precedence (lowest -> highest):
  defaults < YAML file < environment variables (``CM_*``)
"""

from __future__ import annotations

import logging
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from certmesh.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

JsonDict = dict[str, Any]

# =============================================================================
# Built-in defaults
# =============================================================================

_DEFAULTS: JsonDict = {
    "vault": {
        "url": "",
        "auth_method": "approle",
        "tls_verify": True,
        "timeout_seconds": 30,
        "approle": {
            "role_id_env": "CM_VAULT_ROLE_ID",
            "secret_id_env": "CM_VAULT_SECRET_ID",
        },
        "ldap": {
            "username_env": "CM_VAULT_LDAP_USERNAME",
            "password_env": "CM_VAULT_LDAP_PASSWORD",
            "mount_point": "ldap",
        },
        "aws_iam": {
            "role": "",
            "mount_point": "aws",
            "region": None,
            "header_value": None,
        },
        "pki": {
            "mount_point": "pki",
            "role_name": "",
            "ttl": "8760h",
            "max_ttl": "",
        },
        "paths": {
            "digicert_api_key": "secret/certmesh/digicert/api_key",
            "venafi_credentials": "secret/certmesh/venafi/credentials",
        },
    },
    "digicert": {
        "base_url": "https://www.digicert.com/services/v2",
        "timeout_seconds": 30,
        "output": {
            "destination": "filesystem",
            "base_path": "/etc/certmesh/tls/digicert",
            "cert_filename": "{order_id}_cert.pem",
            "key_filename": "{order_id}_key.pem",
            "chain_filename": "{order_id}_chain.pem",
            "vault_path_template": "secret/certmesh/tls/digicert/{order_id}",
        },
        "certificate": {
            "key_size": 4096,
            "product_name_id": "ssl_plus",
            "validity_years": 1,
            "signature_hash": "sha256",
            "organization_id": None,
            "subject": {
                "country": "US",
                "state": "",
                "locality": "",
                "organisation": "",
                "organisational_unit": "",
            },
        },
        "polling": {
            "interval_seconds": 15,
            "max_wait_seconds": 1800,
        },
        "retry": {
            "max_attempts": 5,
            "wait_min_seconds": 2,
            "wait_max_seconds": 60,
            "wait_multiplier": 1.5,
        },
        "circuit_breaker": {
            "failure_threshold": 5,
            "recovery_timeout_seconds": 120,
        },
    },
    "venafi": {
        "base_url": "",
        "auth_method": "oauth",
        "oauth_client_id": "certapi",
        "oauth_scope": "certificate:manage",
        "tls_verify": True,
        "timeout_seconds": 30,
        "output": {
            "destination": "filesystem",
            "base_path": "/etc/certmesh/tls/venafi",
            "cert_filename": "{guid}_cert.pem",
            "key_filename": "{guid}_key.pem",
            "chain_filename": "{guid}_chain.pem",
            "vault_path_template": "secret/certmesh/tls/venafi/{guid}",
        },
        "certificate": {
            "key_size": 4096,
            "pkcs12_export_passphrase_env": "CM_VENAFI_PKCS12_PASSPHRASE",
        },
        "approval": {
            "reason": "Automated renewal approved by certmesh",
        },
        "polling": {
            "interval_seconds": 15,
            "max_wait_seconds": 1800,
        },
        "retry": {
            "max_attempts": 5,
            "wait_min_seconds": 2,
            "wait_max_seconds": 60,
            "wait_multiplier": 1.5,
        },
        "circuit_breaker": {
            "failure_threshold": 5,
            "recovery_timeout_seconds": 120,
        },
    },
    "acm": {
        "region": "",
        "timeout_seconds": 30,
        "output": {
            "destination": "filesystem",
            "base_path": "/etc/certmesh/tls/acm",
            "cert_filename": "{cert_arn_short}_cert.pem",
            "key_filename": "{cert_arn_short}_key.pem",
            "chain_filename": "{cert_arn_short}_chain.pem",
        },
        "certificate": {
            "key_algorithm": "RSA_2048",
            "validation_method": "DNS",
            "idempotency_token": "",
        },
        "private_ca": {
            "ca_arn": "",
            "signing_algorithm": "SHA256WITHRSA",
            "validity_days": 365,
            "template_arn": "",
        },
        "polling": {
            "interval_seconds": 10,
            "max_wait_seconds": 600,
        },
    },
    "logging": {
        "level": "INFO",
        "format": ("%(asctime)s [%(levelname)s] %(name)s - %(funcName)s:%(lineno)d - %(message)s"),
        "datefmt": "%Y-%m-%dT%H:%M:%S",
    },
}


# =============================================================================
# Public API
# =============================================================================


def build_config(config_file: str | Path | None = None) -> JsonDict:
    """Build the complete application configuration."""
    cfg = deepcopy(_DEFAULTS)

    if config_file is not None:
        path = Path(config_file).resolve()
        if not path.exists():
            raise ConfigurationError(f"Config file specified but not found: {path}")
        try:
            with path.open(encoding="utf-8") as fh:
                from_file: JsonDict = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"Failed to parse config YAML at '{path}': {exc}") from exc
        if not isinstance(from_file, dict):
            raise ConfigurationError(
                f"Config file '{path}' does not contain a YAML mapping at the top level."
            )
        cfg = _deep_merge(cfg, from_file)
        logger.debug("Loaded config file '%s'.", path)

    cfg = _deep_merge(cfg, _env_overrides())
    logger.debug("Configuration built (file=%s).", config_file)
    return cfg


def configure_logging(logging_cfg: JsonDict) -> None:
    """Apply structured logging from the logging config section."""
    import sys as _sys

    level_name: str = logging_cfg.get("level", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format=logging_cfg.get(
            "format",
            "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        ),
        datefmt=logging_cfg.get("datefmt"),
        stream=_sys.stderr,
        force=True,
    )
    logger.debug("Logging configured at level '%s'.", level_name)


# =============================================================================
# Environment variable -> config path mappings
# =============================================================================


def _env_overrides() -> JsonDict:
    """Read all ``CM_*`` environment variables and return as a partial config dict."""
    e = os.environ.get
    overrides: JsonDict = {}

    # Vault
    _sset(overrides, ["vault", "url"], e("CM_VAULT_URL"))
    _sset(overrides, ["vault", "auth_method"], e("CM_VAULT_AUTH_METHOD"))
    _sset(overrides, ["vault", "tls_verify"], _bool(e("CM_VAULT_TLS_VERIFY")))
    _sset(overrides, ["vault", "timeout_seconds"], _int(e("CM_VAULT_TIMEOUT")))
    _sset(overrides, ["vault", "ldap", "mount_point"], e("CM_VAULT_LDAP_MOUNT_POINT"))
    _sset(overrides, ["vault", "aws_iam", "role"], e("CM_VAULT_AWS_ROLE"))
    _sset(overrides, ["vault", "aws_iam", "mount_point"], e("CM_VAULT_AWS_MOUNT_POINT"))
    _sset(overrides, ["vault", "aws_iam", "region"], e("CM_VAULT_AWS_REGION"))
    _sset(overrides, ["vault", "aws_iam", "header_value"], e("CM_VAULT_AWS_HEADER_VALUE"))
    _sset(overrides, ["vault", "pki", "mount_point"], e("CM_VAULT_PKI_MOUNT"))
    _sset(overrides, ["vault", "pki", "role_name"], e("CM_VAULT_PKI_ROLE"))
    _sset(overrides, ["vault", "pki", "ttl"], e("CM_VAULT_PKI_TTL"))
    _sset(overrides, ["vault", "paths", "digicert_api_key"], e("CM_VAULT_PATH_DIGICERT"))
    _sset(overrides, ["vault", "paths", "venafi_credentials"], e("CM_VAULT_PATH_VENAFI"))

    # DigiCert
    _sset(overrides, ["digicert", "base_url"], e("CM_DIGICERT_BASE_URL"))
    _sset(overrides, ["digicert", "timeout_seconds"], _int(e("CM_DIGICERT_TIMEOUT")))
    _sset(overrides, ["digicert", "output", "destination"], e("CM_DIGICERT_OUTPUT_DEST"))
    _sset(overrides, ["digicert", "output", "base_path"], e("CM_DIGICERT_OUTPUT_PATH"))
    _sset(
        overrides,
        ["digicert", "output", "vault_path_template"],
        e("CM_DIGICERT_VAULT_PATH"),
    )
    _sset(
        overrides,
        ["digicert", "certificate", "key_size"],
        _int(e("CM_DIGICERT_KEY_SIZE")),
    )
    _sset(overrides, ["digicert", "certificate", "product_name_id"], e("CM_DIGICERT_PRODUCT"))
    _sset(
        overrides,
        ["digicert", "certificate", "validity_years"],
        _int(e("CM_DIGICERT_VALIDITY_DAYS")),
    )
    _sset(overrides, ["digicert", "certificate", "organization_id"], e("CM_DIGICERT_ORG_ID"))
    _sset(
        overrides,
        ["digicert", "certificate", "subject", "organisation"],
        e("CM_DIGICERT_SUBJECT_ORG"),
    )
    _sset(
        overrides,
        ["digicert", "certificate", "subject", "organisational_unit"],
        e("CM_DIGICERT_SUBJECT_OU"),
    )
    _sset(
        overrides,
        ["digicert", "certificate", "subject", "country"],
        e("CM_DIGICERT_SUBJECT_COUNTRY"),
    )
    _sset(
        overrides,
        ["digicert", "certificate", "subject", "state"],
        e("CM_DIGICERT_SUBJECT_STATE"),
    )
    _sset(
        overrides,
        ["digicert", "certificate", "subject", "locality"],
        e("CM_DIGICERT_SUBJECT_LOCALITY"),
    )
    _sset(
        overrides,
        ["digicert", "polling", "interval_seconds"],
        _int(e("CM_DIGICERT_POLL_INTERVAL")),
    )
    _sset(
        overrides,
        ["digicert", "polling", "max_wait_seconds"],
        _int(e("CM_DIGICERT_POLL_MAX_WAIT")),
    )
    _sset(
        overrides,
        ["digicert", "retry", "max_attempts"],
        _int(e("CM_DIGICERT_RETRY_ATTEMPTS")),
    )

    # Venafi
    _sset(overrides, ["venafi", "base_url"], e("CM_VENAFI_BASE_URL"))
    _sset(overrides, ["venafi", "auth_method"], e("CM_VENAFI_AUTH_METHOD"))
    _sset(overrides, ["venafi", "oauth_client_id"], e("CM_VENAFI_OAUTH_CLIENT_ID"))
    _sset(overrides, ["venafi", "oauth_scope"], e("CM_VENAFI_OAUTH_SCOPE"))
    _sset(overrides, ["venafi", "tls_verify"], _bool(e("CM_VENAFI_TLS_VERIFY")))
    _sset(overrides, ["venafi", "timeout_seconds"], _int(e("CM_VENAFI_TIMEOUT")))
    _sset(overrides, ["venafi", "output", "destination"], e("CM_VENAFI_OUTPUT_DEST"))
    _sset(overrides, ["venafi", "output", "base_path"], e("CM_VENAFI_OUTPUT_PATH"))
    _sset(
        overrides,
        ["venafi", "output", "vault_path_template"],
        e("CM_VENAFI_VAULT_PATH"),
    )
    _sset(overrides, ["venafi", "certificate", "key_size"], _int(e("CM_VENAFI_KEY_SIZE")))
    _sset(overrides, ["venafi", "approval", "reason"], e("CM_VENAFI_APPROVAL_REASON"))

    # ACM
    _sset(overrides, ["acm", "region"], e("CM_ACM_REGION"))
    _sset(overrides, ["acm", "output", "destination"], e("CM_ACM_OUTPUT_DEST"))
    _sset(overrides, ["acm", "output", "base_path"], e("CM_ACM_OUTPUT_PATH"))
    _sset(
        overrides,
        ["acm", "certificate", "key_algorithm"],
        e("CM_ACM_KEY_ALGORITHM"),
    )
    _sset(
        overrides,
        ["acm", "certificate", "validation_method"],
        e("CM_ACM_VALIDATION_METHOD"),
    )
    _sset(overrides, ["acm", "private_ca", "ca_arn"], e("CM_ACM_PCA_ARN"))
    _sset(
        overrides,
        ["acm", "private_ca", "signing_algorithm"],
        e("CM_ACM_PCA_SIGNING_ALGORITHM"),
    )
    _sset(
        overrides,
        ["acm", "private_ca", "validity_days"],
        _int(e("CM_ACM_PCA_VALIDITY_DAYS")),
    )

    # Logging
    _sset(overrides, ["logging", "level"], e("CM_LOG_LEVEL"))
    _sset(overrides, ["logging", "format"], e("CM_LOG_FORMAT"))

    return overrides


# =============================================================================
# Configuration validation
# =============================================================================

_VAULT_AUTH_METHODS: frozenset[str] = frozenset({"approle", "ldap", "aws_iam"})
_VENAFI_AUTH_METHODS: frozenset[str] = frozenset({"oauth", "ldap"})
_OUTPUT_DESTINATIONS: frozenset[str] = frozenset({"filesystem", "vault", "both"})


def validate_config(cfg: JsonDict) -> None:
    """Validate a fully merged configuration dictionary."""
    _validate_vault(cfg.get("vault", {}))
    _validate_digicert(cfg.get("digicert", {}))
    _validate_venafi(cfg.get("venafi", {}))


def _validate_vault(vault: JsonDict) -> None:
    if not vault.get("url"):
        raise ConfigurationError(
            "vault.url is required. Set CM_VAULT_URL or vault.url in the config file."
        )
    auth_method: str = vault.get("auth_method", "")
    if auth_method not in _VAULT_AUTH_METHODS:
        raise ConfigurationError(
            f"vault.auth_method '{auth_method}' is not supported. "
            f"Supported: {sorted(_VAULT_AUTH_METHODS)}. Set CM_VAULT_AUTH_METHOD."
        )
    if auth_method == "aws_iam" and not vault.get("aws_iam", {}).get("role"):
        raise ConfigurationError(
            "vault.auth_method is 'aws_iam' but no role is configured. Set CM_VAULT_AWS_ROLE."
        )


def _validate_digicert(digicert: JsonDict) -> None:
    dest: str = digicert.get("output", {}).get("destination", "")
    if dest not in _OUTPUT_DESTINATIONS:
        raise ConfigurationError(
            f"digicert.output.destination '{dest}' is invalid. "
            f"Supported: {sorted(_OUTPUT_DESTINATIONS)}."
        )
    if dest in ("vault", "both") and not digicert.get("output", {}).get("vault_path_template"):
        raise ConfigurationError(
            "digicert output destination includes 'vault' but no vault_path_template is set."
        )


def _validate_venafi(venafi: JsonDict) -> None:
    if not venafi.get("base_url"):
        raise ConfigurationError("venafi.base_url is required. Set CM_VENAFI_BASE_URL.")
    auth_method: str = venafi.get("auth_method", "oauth")
    if auth_method not in _VENAFI_AUTH_METHODS:
        raise ConfigurationError(
            f"venafi.auth_method '{auth_method}' is not supported. "
            f"Supported: {sorted(_VENAFI_AUTH_METHODS)}."
        )
    dest: str = venafi.get("output", {}).get("destination", "")
    if dest not in _OUTPUT_DESTINATIONS:
        raise ConfigurationError(
            f"venafi.output.destination '{dest}' is invalid. "
            f"Supported: {sorted(_OUTPUT_DESTINATIONS)}."
        )


# =============================================================================
# Helpers
# =============================================================================


def _deep_merge(base: JsonDict, override: JsonDict) -> JsonDict:
    """Recursively merge ``override`` into a copy of ``base``."""
    result = deepcopy(base)
    for key, value in override.items():
        if value is None:
            continue
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def _sset(d: JsonDict, path: list[str], value: Any) -> None:
    """Set a value at a nested dict path only when ``value`` is not ``None``."""
    if value is None:
        return
    node = d
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = value


def _bool(raw: str | None) -> bool | None:
    """Convert a string env var to bool."""
    if raw is None:
        return None
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(raw: str | None) -> int | None:
    """Convert a string env var to int."""
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        logger.warning("Could not convert env var value '%s' to int; ignoring.", raw)
        return None
