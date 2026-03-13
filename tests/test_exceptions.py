"""Tests for certmesh.exceptions."""

from __future__ import annotations

from certmesh.exceptions import (
    ACMError,
    ACMExportError,
    ACMPrivateCAError,
    ACMRequestError,
    ACMValidationError,
    CertificateError,
    CertMeshError,
    CircuitBreakerOpenError,
    ConfigurationError,
    DigiCertAPIError,
    DigiCertError,
    VaultError,
    VaultPKIError,
    VenafiAPIError,
    VenafiError,
)


class TestExceptionHierarchy:
    def test_base_exception(self) -> None:
        exc = CertMeshError("test")
        assert str(exc) == "test"
        assert isinstance(exc, Exception)

    def test_configuration_error(self) -> None:
        exc = ConfigurationError("bad config")
        assert isinstance(exc, CertMeshError)

    def test_circuit_breaker_open(self) -> None:
        exc = CircuitBreakerOpenError("open")
        assert isinstance(exc, CertMeshError)

    def test_vault_hierarchy(self) -> None:
        assert issubclass(VaultError, CertMeshError)
        assert issubclass(VaultPKIError, VaultError)

    def test_digicert_api_error_str(self) -> None:
        exc = DigiCertAPIError("failed", status_code=500, body='{"error": "x"}')
        result = str(exc)
        assert "HTTP 500" in result
        assert "body=" in result

    def test_digicert_api_error_no_body(self) -> None:
        exc = DigiCertAPIError("failed")
        assert str(exc) == "failed"

    def test_venafi_api_error_str(self) -> None:
        exc = VenafiAPIError("failed", status_code=403, body="denied")
        result = str(exc)
        assert "HTTP 403" in result

    def test_acm_hierarchy(self) -> None:
        assert issubclass(ACMError, CertMeshError)
        assert issubclass(ACMRequestError, ACMError)
        assert issubclass(ACMExportError, ACMError)
        assert issubclass(ACMPrivateCAError, ACMError)
        assert issubclass(ACMValidationError, ACMError)

    def test_certificate_error_hierarchy(self) -> None:
        assert issubclass(CertificateError, CertMeshError)

    def test_all_digicert_errors_are_digicert_error(self) -> None:
        assert issubclass(DigiCertError, CertMeshError)

    def test_all_venafi_errors_are_venafi_error(self) -> None:
        assert issubclass(VenafiError, CertMeshError)
