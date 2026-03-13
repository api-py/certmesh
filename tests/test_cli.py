"""Tests for certmesh.cli — Click-based CLI commands.

Covers every sub-command group (config, vault-pki, acm, acm-pca, digicert,
venafi) and the ``_handle_error`` helper.  All external dependencies (Vault,
AWS, DigiCert, Venafi) are mocked so the tests run offline.
"""

from __future__ import annotations

import datetime
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from certmesh.cli import _handle_error, cli
from certmesh.exceptions import (
    ACMError,
    CertificateError,
    CertMeshError,
    ConfigurationError,
    DigiCertError,
    VaultError,
    VaultPKIError,
    VenafiError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

JsonDict = dict[str, Any]


def _make_cfg(**overrides: Any) -> JsonDict:
    """Return a minimal merged config dict suitable for the CLI context.

    The ``cli`` root group calls ``build_config`` then ``configure_logging``,
    so we patch ``build_config`` to return this dict directly.
    """
    base: JsonDict = {
        "vault": {
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
        },
        "digicert": {
            "base_url": "https://www.digicert.com/services/v2",
            "timeout_seconds": 10,
            "output": {"destination": "filesystem", "base_path": "/tmp/certs"},
            "certificate": {
                "key_size": 2048,
                "product_name_id": "ssl_plus",
                "validity_years": 1,
                "signature_hash": "sha256",
                "subject": {
                    "country": "US",
                    "state": "MD",
                    "locality": "Baltimore",
                    "organisation": "Acme",
                    "organisational_unit": "Eng",
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
        },
        "venafi": {
            "base_url": "https://venafi.corp.example.com",
            "auth_method": "oauth",
            "oauth_client_id": "certapi",
            "oauth_scope": "certificate:manage",
            "tls_verify": False,
            "timeout_seconds": 10,
            "output": {"destination": "filesystem", "base_path": "/tmp/certs_v"},
            "certificate": {"key_size": 2048},
            "approval": {"reason": "auto"},
            "polling": {"interval_seconds": 0, "max_wait_seconds": 5},
            "retry": {
                "max_attempts": 2,
                "wait_min_seconds": 0,
                "wait_max_seconds": 1,
                "wait_multiplier": 1.0,
            },
            "circuit_breaker": {"failure_threshold": 3, "recovery_timeout_seconds": 5},
        },
        "acm": {
            "region": "us-east-1",
            "timeout_seconds": 10,
            "output": {"destination": "filesystem", "base_path": "/tmp/certs_acm"},
            "certificate": {"key_algorithm": "RSA_2048", "validation_method": "DNS"},
            "private_ca": {
                "ca_arn": "",
                "signing_algorithm": "SHA256WITHRSA",
                "validity_days": 365,
                "template_arn": "",
            },
            "polling": {"interval_seconds": 1, "max_wait_seconds": 5},
        },
        "logging": {"level": "WARNING", "format": "%(message)s", "datefmt": None},
    }
    base.update(overrides)
    return base


def _patch_cli_init():
    """Context-manager shortcut that patches ``build_config`` and
    ``configure_logging`` so the root ``cli`` group succeeds without real I/O.
    """
    cfg = _make_cfg()
    return (
        patch("certmesh.cli.build_config", return_value=cfg),
        patch("certmesh.cli.configure_logging"),
    )


class _CliFixture:
    """Convenience wrapper that invokes the CLI while patching the root group."""

    def __init__(self) -> None:
        self.runner = CliRunner()

    def invoke(self, args: list[str], **kw: Any):
        p_build, p_log = _patch_cli_init()
        with p_build, p_log:
            return self.runner.invoke(cli, args, catch_exceptions=False, **kw)

    def invoke_catch(self, args: list[str], **kw: Any):
        """Invoke but allow SystemExit to be caught by CliRunner."""
        p_build, p_log = _patch_cli_init()
        with p_build, p_log:
            return self.runner.invoke(cli, args, catch_exceptions=True, **kw)


@pytest.fixture()
def clif() -> _CliFixture:
    return _CliFixture()


# ============================================================================
# _handle_error
# ============================================================================


class TestHandleError:
    """Verify that _handle_error maps exception types to the correct exit
    codes and writes to stderr."""

    def test_configuration_error_exits_1(self):
        with pytest.raises(SystemExit) as exc_info:
            _handle_error(ConfigurationError("bad config"))
        assert exc_info.value.code == 1

    def test_vault_error_exits_1(self):
        with pytest.raises(SystemExit) as exc_info:
            _handle_error(VaultError("vault down"))
        assert exc_info.value.code == 1

    def test_digicert_error_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            _handle_error(DigiCertError("dc failure"))
        assert exc_info.value.code == 2

    def test_venafi_error_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            _handle_error(VenafiError("venafi failure"))
        assert exc_info.value.code == 2

    def test_acm_error_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            _handle_error(ACMError("acm failure"))
        assert exc_info.value.code == 2

    def test_vault_pki_error_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            _handle_error(VaultPKIError("pki err"))
        assert exc_info.value.code == 2

    def test_certificate_error_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            _handle_error(CertificateError("cert err"))
        assert exc_info.value.code == 2

    def test_generic_certmesh_error_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            _handle_error(CertMeshError("generic"))
        assert exc_info.value.code == 2

    def test_unexpected_error_exits_3(self):
        with pytest.raises(SystemExit) as exc_info:
            _handle_error(RuntimeError("boom"))
        assert exc_info.value.code == 3


# ============================================================================
# config commands
# ============================================================================


class TestConfigShow:
    def test_config_show_success(self, clif: _CliFixture):
        result = clif.invoke(["config", "show"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "vault" in data
        assert "digicert" in data

    def test_config_show_redacts_env_keys(self, clif: _CliFixture):
        result = clif.invoke(["config", "show"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        approle = data["vault"]["approle"]
        assert approle["role_id_env"].startswith("<from env:")
        assert approle["secret_id_env"].startswith("<from env:")


class TestConfigValidate:
    def test_config_validate_success(self, clif: _CliFixture):
        with patch("certmesh.cli.validate_config"):
            result = clif.invoke(["config", "validate"])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_config_validate_failure(self, clif: _CliFixture):
        with patch(
            "certmesh.cli.validate_config",
            side_effect=ConfigurationError("vault.url is required"),
        ):
            result = clif.invoke_catch(["config", "validate"])
        assert result.exit_code == 1
        assert "Validation failed" in result.stderr


# ============================================================================
# vault-pki commands
# ============================================================================


class TestVaultPKIIssue:
    def test_issue_json_output(self, clif: _CliFixture):
        mock_result = {
            "certificate": "---CERT---",
            "private_key": "---KEY---",
            "ca_chain": ["---CA---"],
            "serial_number": "aa:bb:cc",
        }
        mock_vc_mod = MagicMock()
        mock_vc_mod.get_authenticated_client.return_value = MagicMock()
        mock_vc_mod.issue_pki_certificate.return_value = mock_result
        with patch("certmesh.vault_client", mock_vc_mod, create=True):
            result = clif.invoke(["vault-pki", "issue", "--cn", "svc.example.com"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["certificate"] == "---CERT---"

    def test_issue_with_san_and_ttl(self, clif: _CliFixture):
        mock_result = {
            "certificate": "---CERT---",
            "private_key": "---KEY---",
            "ca_chain": [],
            "serial_number": "dd:ee:ff",
        }
        mock_vc_mod = MagicMock()
        mock_vc_mod.get_authenticated_client.return_value = MagicMock()
        mock_vc_mod.issue_pki_certificate.return_value = mock_result
        with patch("certmesh.vault_client", mock_vc_mod, create=True):
            result = clif.invoke(
                [
                    "vault-pki",
                    "issue",
                    "--cn",
                    "svc.example.com",
                    "--san",
                    "alt1.example.com",
                    "--san",
                    "alt2.example.com",
                    "--ip-san",
                    "10.0.0.1",
                    "--ttl",
                    "360h",
                ]
            )
        assert result.exit_code == 0
        mock_vc_mod.issue_pki_certificate.assert_called_once()
        call_kw = mock_vc_mod.issue_pki_certificate.call_args
        assert call_kw[1]["alt_names"] == ["alt1.example.com", "alt2.example.com"]
        assert call_kw[1]["ttl"] == "360h"
        assert call_kw[1]["ip_sans"] == ["10.0.0.1"]


class TestVaultPKISign:
    def test_sign_json_output(self, clif: _CliFixture, tmp_path):
        csr_file = tmp_path / "req.pem"
        csr_file.write_text("---CSR---")
        mock_result = {"certificate": "---CERT---", "ca_chain": ["---CA---"]}
        mock_vc_mod = MagicMock()
        mock_vc_mod.get_authenticated_client.return_value = MagicMock()
        mock_vc_mod.sign_pki_certificate.return_value = mock_result
        with patch("certmesh.vault_client", mock_vc_mod, create=True):
            result = clif.invoke(
                [
                    "vault-pki",
                    "sign",
                    "--cn",
                    "svc.example.com",
                    "--csr-file",
                    str(csr_file),
                ]
            )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["certificate"] == "---CERT---"


class TestVaultPKIList:
    def test_list_returns_serials(self, clif: _CliFixture):
        mock_vc_mod = MagicMock()
        mock_vc_mod.get_authenticated_client.return_value = MagicMock()
        mock_vc_mod.list_pki_certificates.return_value = ["aa:bb", "cc:dd"]
        with patch("certmesh.vault_client", mock_vc_mod, create=True):
            result = clif.invoke(["vault-pki", "list"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["serial_numbers"] == ["aa:bb", "cc:dd"]
        assert data["count"] == 2


class TestVaultPKIRead:
    def test_read_returns_cert_data(self, clif: _CliFixture):
        mock_vc_mod = MagicMock()
        mock_vc_mod.get_authenticated_client.return_value = MagicMock()
        mock_vc_mod.read_pki_certificate.return_value = {"certificate": "---PEM---"}
        with patch("certmesh.vault_client", mock_vc_mod, create=True):
            result = clif.invoke(["vault-pki", "read", "--serial", "aa:bb:cc"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["certificate"] == "---PEM---"


class TestVaultPKIRevoke:
    def test_revoke_success(self, clif: _CliFixture):
        mock_vc_mod = MagicMock()
        mock_vc_mod.get_authenticated_client.return_value = MagicMock()
        with patch("certmesh.vault_client", mock_vc_mod, create=True):
            result = clif.invoke(["vault-pki", "revoke", "--serial", "aa:bb:cc"])
        assert result.exit_code == 0
        assert "aa:bb:cc" in result.output
        assert "revoked" in result.output.lower()


# ============================================================================
# acm commands
# ============================================================================


class TestACMRequest:
    def test_request_success(self, clif: _CliFixture):
        mock_acm = MagicMock()
        mock_acm.request_certificate.return_value = "arn:aws:acm:us-east-1:123:cert/abc"
        with patch("certmesh.acm_client", mock_acm, create=True):
            result = clif.invoke(
                [
                    "acm",
                    "request",
                    "--cn",
                    "app.example.com",
                    "--validation",
                    "DNS",
                ]
            )
        assert result.exit_code == 0
        assert "arn:aws:acm" in result.output

    def test_request_with_san_and_region(self, clif: _CliFixture):
        mock_acm = MagicMock()
        mock_acm.request_certificate.return_value = "arn:aws:acm:eu-west-1:123:cert/xyz"
        with patch("certmesh.acm_client", mock_acm, create=True):
            result = clif.invoke(
                [
                    "acm",
                    "request",
                    "--cn",
                    "app.example.com",
                    "--san",
                    "www.example.com",
                    "--region",
                    "eu-west-1",
                    "--key-algorithm",
                    "EC_prime256v1",
                ]
            )
        assert result.exit_code == 0
        call_kw = mock_acm.request_certificate.call_args
        assert call_kw[1]["key_algorithm"] == "EC_prime256v1"
        assert call_kw[1]["subject_alternative_names"] == ["www.example.com"]


class TestACMList:
    def test_list_success(self, clif: _CliFixture):
        item = SimpleNamespace(
            arn="arn:aws:acm:us-east-1:123:cert/abc",
            domain_name="app.example.com",
            status="ISSUED",
        )
        mock_acm = MagicMock()
        mock_acm.list_certificates.return_value = [item]
        with patch("certmesh.acm_client", mock_acm, create=True):
            result = clif.invoke(["acm", "list"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["arn"] == "arn:aws:acm:us-east-1:123:cert/abc"


class TestACMDescribe:
    def test_describe_success(self, clif: _CliFixture):
        detail = SimpleNamespace(
            arn="arn:aws:acm:us-east-1:123:cert/abc",
            domain_name="app.example.com",
            status="ISSUED",
        )
        mock_acm = MagicMock()
        mock_acm.describe_certificate.return_value = detail
        with patch("certmesh.acm_client", mock_acm, create=True):
            result = clif.invoke(
                [
                    "acm",
                    "describe",
                    "--arn",
                    "arn:aws:acm:us-east-1:123:cert/abc",
                ]
            )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ISSUED"


class TestACMExport:
    def test_export_to_stdout(self, clif: _CliFixture):
        bundle = SimpleNamespace(
            common_name="app.example.com",
            serial_number="aabbccdd",
            certificate_pem="---CERT---",
            private_key_pem="---KEY---",
            chain_pem="---CHAIN---",
        )
        mock_acm = MagicMock()
        mock_acm.export_certificate.return_value = bundle
        with patch("certmesh.acm_client", mock_acm, create=True):
            result = clif.invoke(
                [
                    "acm",
                    "export",
                    "--arn",
                    "arn:aws:acm:us-east-1:123:cert/abc",
                    "--passphrase",
                    "secret",
                ]
            )
        assert result.exit_code == 0
        assert "app.example.com" in result.output
        call_args = mock_acm.export_certificate.call_args
        # passphrase should be passed as bytes
        assert call_args[0][2] == b"secret"


class TestACMDelete:
    def test_delete_success(self, clif: _CliFixture):
        mock_acm = MagicMock()
        with patch("certmesh.acm_client", mock_acm, create=True):
            result = clif.invoke(
                [
                    "acm",
                    "delete",
                    "--arn",
                    "arn:aws:acm:us-east-1:123:cert/abc",
                ]
            )
        assert result.exit_code == 0
        assert "Deleted" in result.output
        mock_acm.delete_certificate.assert_called_once()


# ============================================================================
# acm-pca commands
# ============================================================================

_CA_ARN = "arn:aws:acm-pca:us-east-1:123:certificate-authority/abc"
_CERT_ARN = "arn:aws:acm-pca:us-east-1:123:certificate-authority/abc/certificate/xyz"


class TestACMPCAIssue:
    def test_issue_success(self, clif: _CliFixture, tmp_path):
        csr_file = tmp_path / "req.pem"
        csr_file.write_text("---CSR---")
        mock_acm = MagicMock()
        mock_acm.issue_private_certificate.return_value = (
            "arn:aws:acm-pca:us-east-1:123:certificate-authority/abc/certificate/xyz"
        )
        with patch("certmesh.acm_client", mock_acm, create=True):
            result = clif.invoke(
                [
                    "acm-pca",
                    "issue",
                    "--ca-arn",
                    _CA_ARN,
                    "--csr-file",
                    str(csr_file),
                ]
            )
        assert result.exit_code == 0
        assert "Issued private CA certificate" in result.output
        call_args = mock_acm.issue_private_certificate.call_args
        assert call_args[0][1] == "---CSR---"  # csr_pem
        assert call_args[1]["ca_arn"] == _CA_ARN


class TestACMPCAGet:
    def test_get_success(self, clif: _CliFixture):
        mock_acm = MagicMock()
        mock_acm.get_private_certificate.return_value = (
            "---PEM---",
            "---CHAIN---",
        )
        with patch("certmesh.acm_client", mock_acm, create=True):
            result = clif.invoke(
                [
                    "acm-pca",
                    "get",
                    "--ca-arn",
                    _CA_ARN,
                    "--cert-arn",
                    _CERT_ARN,
                ]
            )
        assert result.exit_code == 0
        call_args = mock_acm.get_private_certificate.call_args
        assert call_args[0][1] == _CERT_ARN  # certificate_arn
        assert call_args[1]["ca_arn"] == _CA_ARN


class TestACMPCARevoke:
    def test_revoke_success(self, clif: _CliFixture):
        mock_acm = MagicMock()
        with patch("certmesh.acm_client", mock_acm, create=True):
            result = clif.invoke(
                [
                    "acm-pca",
                    "revoke",
                    "--ca-arn",
                    _CA_ARN,
                    "--cert-arn",
                    _CERT_ARN,
                    "--cert-serial",
                    "1234",
                    "--reason",
                    "KEY_COMPROMISE",
                ]
            )
        assert result.exit_code == 0
        assert "1234" in result.output
        assert "revoked" in result.output.lower()
        call_args = mock_acm.revoke_private_certificate.call_args
        assert call_args[0][1] == _CERT_ARN  # certificate_arn
        assert call_args[0][2] == "1234"  # certificate_serial
        assert call_args[0][3] == "KEY_COMPROMISE"  # revocation_reason
        assert call_args[1]["ca_arn"] == _CA_ARN


class TestACMPCAList:
    def test_list_success(self, clif: _CliFixture):
        mock_acm = MagicMock()
        mock_acm.list_private_certificates.return_value = [
            {"CertificateArn": _CERT_ARN, "Status": "ISSUED"},
        ]
        with patch("certmesh.acm_client", mock_acm, create=True):
            result = clif.invoke(
                [
                    "acm-pca",
                    "list",
                    "--ca-arn",
                    _CA_ARN,
                ]
            )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        call_args = mock_acm.list_private_certificates.call_args
        assert call_args[1]["ca_arn"] == _CA_ARN


# ============================================================================
# digicert commands
# ============================================================================


class TestDigicertList:
    def test_list_success(self, clif: _CliFixture):
        item = SimpleNamespace(order_id=111, common_name="api.example.com", status="issued")
        mock_dc = MagicMock()
        mock_dc.list_issued_certificates.return_value = [item]
        with (
            patch("certmesh.digicert_client", mock_dc, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(["digicert", "list"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data[0]["order_id"] == 111

    def test_list_with_options(self, clif: _CliFixture):
        mock_dc = MagicMock()
        mock_dc.list_issued_certificates.return_value = []
        with (
            patch("certmesh.digicert_client", mock_dc, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(
                [
                    "digicert",
                    "list",
                    "--status",
                    "pending",
                    "--limit",
                    "50",
                ]
            )
        assert result.exit_code == 0
        call_kw = mock_dc.list_issued_certificates.call_args
        assert call_kw[1]["status"] == "pending"
        assert call_kw[1]["page_size"] == 50


class TestDigicertSearch:
    def test_search_by_cn(self, clif: _CliFixture):
        item = SimpleNamespace(order_id=222, common_name="api.example.com")
        mock_dc = MagicMock()
        mock_dc.search_certificates.return_value = [item]
        with (
            patch("certmesh.digicert_client", mock_dc, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(["digicert", "search", "--cn", "api.example.com"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data[0]["common_name"] == "api.example.com"

    def test_search_with_all_filters(self, clif: _CliFixture):
        mock_dc = MagicMock()
        mock_dc.search_certificates.return_value = []
        with (
            patch("certmesh.digicert_client", mock_dc, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(
                [
                    "digicert",
                    "search",
                    "--cn",
                    "api",
                    "--serial",
                    "AABB",
                    "--status",
                    "issued",
                    "--product",
                    "ssl_plus",
                ]
            )
        assert result.exit_code == 0
        call_kw = mock_dc.search_certificates.call_args
        assert call_kw[1]["common_name"] == "api"
        assert call_kw[1]["serial_number"] == "AABB"
        assert call_kw[1]["product_name_id"] == "ssl_plus"


class TestDigicertDescribe:
    def test_describe_success(self, clif: _CliFixture):
        detail = SimpleNamespace(
            order_id=333,
            common_name="api.example.com",
            status="issued",
            serial_number="aabb",
        )
        mock_dc = MagicMock()
        mock_dc.describe_certificate.return_value = detail
        with (
            patch("certmesh.digicert_client", mock_dc, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(["digicert", "describe", "--cert-id", "333"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["order_id"] == 333


class TestDigicertOrder:
    def test_order_success(self, clif: _CliFixture):
        bundle = SimpleNamespace(
            common_name="new.example.com",
            serial_number="ccdd",
            not_after=datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc),
        )
        mock_dc = MagicMock()
        mock_dc.OrderRequest = MagicMock()
        mock_dc.order_and_await_certificate.return_value = bundle
        with (
            patch("certmesh.digicert_client", mock_dc, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(
                [
                    "digicert",
                    "order",
                    "--cn",
                    "new.example.com",
                    "--san",
                    "www.example.com",
                ]
            )
        assert result.exit_code == 0
        assert "new.example.com" in result.output
        assert "ccdd" in result.output


class TestDigicertDownload:
    def test_download_success(self, clif: _CliFixture, tmp_path):
        key_file = tmp_path / "key.pem"
        key_file.write_text("---PRIVATE KEY---")
        bundle = SimpleNamespace(common_name="api.example.com", serial_number="eeff")
        mock_dc = MagicMock()
        mock_dc.download_issued_certificate.return_value = bundle
        with (
            patch("certmesh.digicert_client", mock_dc, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(
                [
                    "digicert",
                    "download",
                    "--cert-id",
                    "555",
                    "--key-file",
                    str(key_file),
                ]
            )
        assert result.exit_code == 0
        assert "api.example.com" in result.output
        call_args = mock_dc.download_issued_certificate.call_args
        assert call_args[0][3] == 555  # certificate_id
        assert call_args[0][4] == "---PRIVATE KEY---"  # private_key_pem


class TestDigicertRevoke:
    def test_revoke_success(self, clif: _CliFixture):
        mock_dc = MagicMock()
        with (
            patch("certmesh.digicert_client", mock_dc, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(
                [
                    "digicert",
                    "revoke",
                    "--cert-id",
                    "666",
                    "--reason",
                    "key_compromise",
                    "--comments",
                    "compromised",
                ]
            )
        assert result.exit_code == 0
        assert "666" in result.output
        assert "revoked" in result.output.lower()
        mock_dc.revoke_certificate.assert_called_once()
        call_kw = mock_dc.revoke_certificate.call_args
        assert call_kw[1]["certificate_id"] == 666
        assert call_kw[1]["reason"] == "key_compromise"
        assert call_kw[1]["comments"] == "compromised"


class TestDigicertDuplicate:
    def test_duplicate_success(self, clif: _CliFixture, tmp_path):
        csr_file = tmp_path / "dup.csr"
        csr_file.write_text("---CSR PEM---")
        mock_dc = MagicMock()
        mock_dc.duplicate_certificate.return_value = {"order_id": 777, "status": "pending"}
        with (
            patch("certmesh.digicert_client", mock_dc, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(
                [
                    "digicert",
                    "duplicate",
                    "--order-id",
                    "123",
                    "--csr-file",
                    str(csr_file),
                    "--cn",
                    "dup.example.com",
                    "--san",
                    "www.dup.example.com",
                ]
            )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["order_id"] == 777
        call_kw = mock_dc.duplicate_certificate.call_args
        assert call_kw[0][3] == 123  # order_id
        assert call_kw[0][4] == "---CSR PEM---"  # csr_pem
        assert call_kw[1]["common_name"] == "dup.example.com"


# ============================================================================
# venafi commands
# ============================================================================


class TestVenafiList:
    def test_list_success(self, clif: _CliFixture):
        item = SimpleNamespace(guid="{aaa}", common_name="v.example.com", status="Active")
        mock_vn = MagicMock()
        mock_vn.authenticate.return_value = MagicMock()  # session
        mock_vn.list_certificates.return_value = [item]
        with (
            patch("certmesh.venafi_client", mock_vn, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(["venafi", "list"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data[0]["guid"] == "{aaa}"
        mock_vn.authenticate.assert_called_once()


class TestVenafiSearch:
    def test_search_by_cn(self, clif: _CliFixture):
        item = SimpleNamespace(guid="{bbb}", common_name="api.corp.com")
        mock_vn = MagicMock()
        mock_vn.authenticate.return_value = MagicMock()  # session
        mock_vn.search_certificates.return_value = [item]
        with (
            patch("certmesh.venafi_client", mock_vn, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(["venafi", "search", "--cn", "api.corp.com"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data[0]["common_name"] == "api.corp.com"
        call_kw = mock_vn.search_certificates.call_args
        assert call_kw[1]["common_name"] == "api.corp.com"


class TestVenafiDescribe:
    def test_describe_success(self, clif: _CliFixture):
        detail = SimpleNamespace(
            guid="{ccc}",
            common_name="svc.corp.com",
            status="Active",
            serial_number="aabbcc",
        )
        mock_vn = MagicMock()
        mock_vn.authenticate.return_value = MagicMock()  # session
        mock_vn.describe_certificate.return_value = detail
        with (
            patch("certmesh.venafi_client", mock_vn, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(["venafi", "describe", "--guid", "{ccc}"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["guid"] == "{ccc}"
        call_kw = mock_vn.describe_certificate.call_args
        assert call_kw[1]["certificate_guid"] == "{ccc}"


class TestVenafiRequest:
    def test_request_success(self, clif: _CliFixture):
        bundle = SimpleNamespace(common_name="new.corp.com", serial_number="ddeeff")
        mock_vn = MagicMock()
        mock_vn.authenticate.return_value = MagicMock()  # session
        mock_vn.request_certificate.return_value = bundle
        with (
            patch("certmesh.venafi_client", mock_vn, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(
                [
                    "venafi",
                    "request",
                    "--policy-dn",
                    "\\VED\\Policy\\Certs",
                    "--cn",
                    "new.corp.com",
                    "--san",
                    "alt.corp.com",
                ]
            )
        assert result.exit_code == 0
        assert "new.corp.com" in result.output
        assert "ddeeff" in result.output
        call_kw = mock_vn.request_certificate.call_args
        assert call_kw[1]["policy_dn"] == "\\VED\\Policy\\Certs"


class TestVenafiRenew:
    def test_renew_success(self, clif: _CliFixture):
        bundle = SimpleNamespace(
            common_name="renew.corp.com",
            serial_number="112233",
            not_after=datetime.datetime(2027, 6, 15, tzinfo=datetime.timezone.utc),
        )
        mock_vn = MagicMock()
        mock_vn.authenticate.return_value = MagicMock()  # session
        mock_vn.renew_and_download_certificate.return_value = bundle
        with (
            patch("certmesh.venafi_client", mock_vn, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(["venafi", "renew", "--guid", "{eee}"])
        assert result.exit_code == 0
        assert "Renewed" in result.output
        assert "renew.corp.com" in result.output
        call_kw = mock_vn.renew_and_download_certificate.call_args
        assert call_kw[1]["certificate_guid"] == "{eee}"


class TestVenafiRevoke:
    def test_revoke_with_dn(self, clif: _CliFixture):
        mock_vn = MagicMock()
        mock_vn.authenticate.return_value = MagicMock()  # session
        with (
            patch("certmesh.venafi_client", mock_vn, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(
                [
                    "venafi",
                    "revoke",
                    "--dn",
                    "\\VED\\Policy\\Certs\\svc.corp.com",
                    "--reason",
                    "1",
                    "--comments",
                    "rotation",
                ]
            )
        assert result.exit_code == 0
        assert "revoked" in result.output.lower()
        call_kw = mock_vn.revoke_certificate.call_args
        assert call_kw[1]["certificate_dn"] == "\\VED\\Policy\\Certs\\svc.corp.com"
        assert call_kw[1]["reason"] == 1

    def test_revoke_with_thumbprint(self, clif: _CliFixture):
        mock_vn = MagicMock()
        mock_vn.authenticate.return_value = MagicMock()  # session
        with (
            patch("certmesh.venafi_client", mock_vn, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(
                [
                    "venafi",
                    "revoke",
                    "--thumbprint",
                    "AABBCCDD",
                ]
            )
        assert result.exit_code == 0
        call_kw = mock_vn.revoke_certificate.call_args
        assert call_kw[1]["thumbprint"] == "AABBCCDD"

    def test_revoke_no_dn_no_thumbprint_fails(self, clif: _CliFixture):
        mock_vn = MagicMock()
        mock_vn.authenticate.return_value = MagicMock()  # session
        with (
            patch("certmesh.venafi_client", mock_vn, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke_catch(["venafi", "revoke"])
        assert result.exit_code == 1
        assert "either --dn or --thumbprint" in result.stderr


class TestVenafiDownload:
    def test_download_success(self, clif: _CliFixture):
        bundle = SimpleNamespace(common_name="dl.corp.com", serial_number="445566")
        mock_vn = MagicMock()
        mock_vn.authenticate.return_value = MagicMock()  # session
        mock_vn.renew_and_download_certificate.return_value = bundle
        with (
            patch("certmesh.venafi_client", mock_vn, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke(["venafi", "download", "--guid", "{fff}"])
        assert result.exit_code == 0
        assert "dl.corp.com" in result.output
        call_kw = mock_vn.renew_and_download_certificate.call_args
        assert call_kw[1]["certificate_guid"] == "{fff}"


# ============================================================================
# Error propagation from commands
# ============================================================================


class TestCommandErrorHandling:
    """Verify that exceptions raised inside commands are routed through
    ``_handle_error`` and produce the correct exit code."""

    def test_digicert_list_digicert_error(self, clif: _CliFixture):
        mock_dc = MagicMock()
        mock_dc.list_issued_certificates.side_effect = DigiCertError("api 500")
        with (
            patch("certmesh.digicert_client", mock_dc, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke_catch(["digicert", "list"])
        assert result.exit_code == 2
        assert "api 500" in result.stderr

    def test_venafi_list_venafi_error(self, clif: _CliFixture):
        mock_vn = MagicMock()
        mock_vn.authenticate.return_value = MagicMock()  # session
        mock_vn.list_certificates.side_effect = VenafiError("tpp down")
        with (
            patch("certmesh.venafi_client", mock_vn, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke_catch(["venafi", "list"])
        assert result.exit_code == 2
        assert "tpp down" in result.stderr

    def test_acm_list_acm_error(self, clif: _CliFixture):
        mock_acm = MagicMock()
        mock_acm.list_certificates.side_effect = ACMError("aws fail")
        with patch("certmesh.acm_client", mock_acm, create=True):
            result = clif.invoke_catch(["acm", "list"])
        assert result.exit_code == 2
        assert "aws fail" in result.stderr

    def test_vault_pki_list_vault_error(self, clif: _CliFixture):
        mock_vc_mod = MagicMock()
        mock_vc_mod.get_authenticated_client.side_effect = VaultError("sealed")
        with patch("certmesh.vault_client", mock_vc_mod, create=True):
            result = clif.invoke_catch(["vault-pki", "list"])
        assert result.exit_code == 1
        assert "sealed" in result.stderr

    def test_unexpected_error_exits_3(self, clif: _CliFixture):
        mock_dc = MagicMock()
        mock_dc.list_issued_certificates.side_effect = RuntimeError("oops")
        with (
            patch("certmesh.digicert_client", mock_dc, create=True),
            patch("certmesh.cli._get_vault_client", return_value=None),
        ):
            result = clif.invoke_catch(["digicert", "list"])
        assert result.exit_code == 3
        assert "oops" in result.stderr


# ============================================================================
# Root group flags
# ============================================================================


class TestRootGroup:
    def test_version_flag(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "certmesh" in result.output

    def test_help_flag(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "certmesh" in result.output.lower()
