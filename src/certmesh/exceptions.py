"""
certmesh.exceptions
====================

Custom exception hierarchy for the certificate automation client.

All exceptions derive from ``CertMeshError`` to allow broad catching at
application entry points while enabling fine-grained handling internally.
"""

from __future__ import annotations

# =============================================================================
# Base
# =============================================================================


class CertMeshError(Exception):
    """Base exception for all certmesh errors."""


# =============================================================================
# Configuration
# =============================================================================


class ConfigurationError(CertMeshError):
    """Raised when the application configuration is invalid or incomplete."""


# =============================================================================
# Circuit breaker
# =============================================================================


class CircuitBreakerOpenError(CertMeshError):
    """Raised when a circuit breaker is OPEN and rejects an outbound call."""


# =============================================================================
# HashiCorp Vault
# =============================================================================


class VaultError(CertMeshError):
    """Base exception for HashiCorp Vault operations."""


class VaultAuthenticationError(VaultError):
    """Raised when Vault authentication is rejected."""


class VaultAWSIAMError(VaultError):
    """Raised when Vault AWS IAM authentication fails."""


class VaultSecretNotFoundError(VaultError):
    """Raised when a Vault KV path does not exist or is inaccessible."""


class VaultWriteError(VaultError):
    """Raised when persisting data back to Vault fails."""


class VaultPKIError(VaultError):
    """Raised when a Vault PKI engine operation fails."""


# =============================================================================
# DigiCert CertCentral
# =============================================================================


class DigiCertError(CertMeshError):
    """Base exception for DigiCert CertCentral API errors."""


class DigiCertAuthenticationError(DigiCertError):
    """Raised when the DigiCert API rejects the API key (HTTP 401 / 403)."""


class DigiCertRateLimitError(DigiCertError):
    """Raised when the DigiCert API rate limit is exceeded (HTTP 429)."""


class DigiCertAPIError(DigiCertError):
    """Raised for unexpected DigiCert API error responses."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        body: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.status_code is not None:
            parts.append(f"HTTP {self.status_code}")
        if self.body:
            parts.append(f"body={self.body[:200]!r}")
        return " | ".join(parts)


class DigiCertCertificateNotReadyError(DigiCertError):
    """Raised when a certificate order is not yet issued."""


class DigiCertPollingTimeoutError(DigiCertError):
    """Raised when awaiting certificate issuance exceeds the configured timeout."""


class DigiCertDownloadError(DigiCertError):
    """Raised when downloading certificate material from DigiCert fails."""


class DigiCertOrderNotFoundError(DigiCertError):
    """Raised when a CertCentral order ID cannot be resolved (HTTP 404)."""


# =============================================================================
# Venafi TPP
# =============================================================================


class VenafiError(CertMeshError):
    """Base exception for Venafi Trust Protection Platform errors."""


class VenafiAuthenticationError(VenafiError):
    """Raised when Venafi TPP authentication is rejected."""


class VenafiLDAPAuthError(VenafiError):
    """Raised when Venafi TPP LDAP/legacy authentication fails."""


class VenafiAPIError(VenafiError):
    """Raised for unexpected Venafi TPP API error responses."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        body: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body

    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.status_code is not None:
            parts.append(f"HTTP {self.status_code}")
        if self.body:
            parts.append(f"body={self.body[:200]!r}")
        return " | ".join(parts)


class VenafiCertificateNotFoundError(VenafiError):
    """Raised when a GUID cannot be resolved to a certificate in Venafi TPP."""


class VenafiPrivateKeyExportError(VenafiError):
    """Raised when Venafi TPP denies private key export."""


class VenafiWorkflowApprovalError(VenafiError):
    """Raised when approving or retrieving a Venafi workflow ticket fails."""


class VenafiPollingTimeoutError(VenafiError):
    """Raised when awaiting Venafi renewal completion exceeds the configured timeout."""


# =============================================================================
# AWS ACM
# =============================================================================


class ACMError(CertMeshError):
    """Base exception for AWS ACM operations."""


class ACMRequestError(ACMError):
    """Raised when requesting a certificate from ACM fails."""


class ACMExportError(ACMError):
    """Raised when exporting certificate material from ACM fails."""


class ACMPrivateCAError(ACMError):
    """Raised when an AWS ACM Private CA operation fails."""


class ACMValidationError(ACMError):
    """Raised when certificate validation in ACM fails or times out."""


# =============================================================================
# Certificate utilities
# =============================================================================


class CertificateError(CertMeshError):
    """Base exception for certificate parsing or generation errors."""


class KeyGenerationError(CertificateError):
    """Raised when RSA private key generation fails."""


class CSRGenerationError(CertificateError):
    """Raised when building or signing a Certificate Signing Request fails."""


class PKCS12ParseError(CertificateError):
    """Raised when parsing a PKCS#12 bundle fails."""


class CertificateExportError(CertificateError):
    """Raised when writing certificate or key material to a destination fails."""
