"""Shared pytest fixtures for the certmesh test suite."""

from __future__ import annotations

import datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

JsonDict = dict[str, Any]


# =============================================================================
# Minimal valid configuration fixtures
# =============================================================================


@pytest.fixture()
def digicert_cfg() -> JsonDict:
    return {
        "base_url": "https://www.digicert.com/services/v2",
        "timeout_seconds": 10,
        "output": {
            "destination": "filesystem",
            "base_path": "/tmp/test_certs",
            "cert_filename": "{order_id}_cert.pem",
            "key_filename": "{order_id}_key.pem",
            "chain_filename": "{order_id}_chain.pem",
        },
        "certificate": {
            "key_size": 2048,
            "product_name_id": "ssl_plus",
            "validity_years": 1,
            "signature_hash": "sha256",
            "subject": {
                "country": "US",
                "state": "Maryland",
                "locality": "Baltimore",
                "organisation": "Test Org",
                "organisational_unit": "Test Unit",
            },
        },
        "polling": {"interval_seconds": 1, "max_wait_seconds": 5},
        "retry": {
            "max_attempts": 2,
            "wait_min_seconds": 0,
            "wait_max_seconds": 1,
            "wait_multiplier": 1.0,
        },
        "circuit_breaker": {"failure_threshold": 3, "recovery_timeout_seconds": 5},
    }


@pytest.fixture()
def venafi_cfg() -> JsonDict:
    return {
        "base_url": "https://venafi.corp.example.com",
        "auth_method": "oauth",
        "oauth_client_id": "certapi",
        "oauth_scope": "certificate:manage",
        "tls_verify": False,
        "timeout_seconds": 10,
        "output": {
            "destination": "filesystem",
            "base_path": "/tmp/test_certs_venafi",
            "cert_filename": "{guid}_cert.pem",
            "key_filename": "{guid}_key.pem",
            "chain_filename": "{guid}_chain.pem",
        },
        "certificate": {
            "key_size": 2048,
            "pkcs12_export_passphrase_env": "TEST_PKCS12_PASSPHRASE",
        },
        "approval": {"reason": "Automated test approval"},
        "polling": {"interval_seconds": 0, "max_wait_seconds": 5},
        "retry": {
            "max_attempts": 2,
            "wait_min_seconds": 0,
            "wait_max_seconds": 1,
            "wait_multiplier": 1.0,
        },
        "circuit_breaker": {"failure_threshold": 3, "recovery_timeout_seconds": 5},
    }


@pytest.fixture()
def vault_cfg() -> JsonDict:
    return {
        "url": "https://vault.example.com",
        "auth_method": "approle",
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
            "role": "test-role",
            "mount_point": "aws",
        },
        "pki": {
            "mount_point": "pki",
            "role_name": "test-role",
            "ttl": "720h",
        },
        "paths": {
            "digicert_api_key": "secret/certmesh/digicert/api_key",
            "venafi_credentials": "secret/certmesh/venafi/credentials",
        },
        "tls_verify": False,
        "timeout_seconds": 5,
    }


@pytest.fixture()
def acm_cfg() -> JsonDict:
    return {
        "region": "us-east-1",
        "timeout_seconds": 10,
        "output": {
            "destination": "filesystem",
            "base_path": "/tmp/test_certs_acm",
            "cert_filename": "{cert_arn_short}_cert.pem",
            "key_filename": "{cert_arn_short}_key.pem",
            "chain_filename": "{cert_arn_short}_chain.pem",
        },
        "certificate": {
            "key_algorithm": "RSA_2048",
            "validation_method": "DNS",
        },
        "private_ca": {
            "ca_arn": "",
            "signing_algorithm": "SHA256WITHRSA",
            "validity_days": 365,
            "template_arn": "",
        },
        "polling": {
            "interval_seconds": 1,
            "max_wait_seconds": 5,
        },
    }


# =============================================================================
# Cryptographic fixtures
# =============================================================================


@pytest.fixture()
def rsa_private_key() -> rsa.RSAPrivateKey:
    """A small RSA-2048 key for fast test execution."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture()
def private_key_pem(rsa_private_key: rsa.RSAPrivateKey) -> bytes:
    return rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture()
def self_signed_cert_pem(rsa_private_key: rsa.RSAPrivateKey) -> bytes:
    """A minimal self-signed certificate for use in bundle assembly tests."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rsa_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .sign(rsa_private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture()
def pkcs12_bundle(
    rsa_private_key: rsa.RSAPrivateKey,
    self_signed_cert_pem: bytes,
) -> bytes:
    """A PKCS#12 bundle containing the test key and self-signed certificate."""
    cert = x509.load_pem_x509_certificate(self_signed_cert_pem)
    return pkcs12.serialize_key_and_certificates(
        name=b"test",
        key=rsa_private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(b"testpass"),
    )


@pytest.fixture()
def mock_vault_client() -> MagicMock:
    return MagicMock()
