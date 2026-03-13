"""Tests for certmesh.vault_client."""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from hvac.exceptions import Forbidden, InvalidPath, Unauthorized

from certmesh.exceptions import (
    ConfigurationError,
    VaultAuthenticationError,
    VaultSecretNotFoundError,
)
from certmesh.vault_client import (
    _split_path,
    get_authenticated_client,
    issue_pki_certificate,
    list_pki_certificates,
    read_all_secret_fields,
    read_pki_certificate,
    read_secret_field,
    revoke_pki_certificate,
    sign_pki_certificate,
    write_secret,
)

JsonDict = dict[str, Any]


class TestSplitPath:
    def test_valid_path(self) -> None:
        mount, sub = _split_path("secret/data/my/key")
        assert mount == "secret"
        assert sub == "data/my/key"

    def test_invalid_path_raises(self) -> None:
        with pytest.raises(VaultSecretNotFoundError, match="invalid"):
            _split_path("noslash")


class TestGetAuthenticatedClient:
    def test_unsupported_auth_method(self, vault_cfg: JsonDict) -> None:
        vault_cfg["auth_method"] = "kerberos"
        with pytest.raises(ConfigurationError, match="Unsupported"):
            get_authenticated_client(vault_cfg)

    def test_approle_missing_section(self, vault_cfg: JsonDict) -> None:
        del vault_cfg["approle"]
        with pytest.raises(ConfigurationError, match="approle section"):
            get_authenticated_client(vault_cfg)

    def test_ldap_missing_section(self, vault_cfg: JsonDict) -> None:
        vault_cfg["auth_method"] = "ldap"
        del vault_cfg["ldap"]
        with pytest.raises(ConfigurationError, match="ldap section"):
            get_authenticated_client(vault_cfg)

    def test_aws_iam_missing_section(self, vault_cfg: JsonDict) -> None:
        vault_cfg["auth_method"] = "aws_iam"
        del vault_cfg["aws_iam"]
        with pytest.raises(ConfigurationError, match="aws_iam section"):
            get_authenticated_client(vault_cfg)

    def test_approle_missing_role_id(self, vault_cfg: JsonDict) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with patch("certmesh.vault_client._build_client"):
                with pytest.raises(ConfigurationError, match="role_id"):
                    get_authenticated_client(vault_cfg)

    def test_approle_missing_secret_id(self, vault_cfg: JsonDict) -> None:
        with patch.dict(os.environ, {"CM_VAULT_ROLE_ID": "role"}, clear=True):
            with patch("certmesh.vault_client._build_client"):
                with pytest.raises(ConfigurationError, match="secret_id"):
                    get_authenticated_client(vault_cfg)

    def test_approle_success(self, vault_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        with (
            patch.dict(
                os.environ,
                {"CM_VAULT_ROLE_ID": "role", "CM_VAULT_SECRET_ID": "secret"},
            ),
            patch("certmesh.vault_client._build_client", return_value=mock_client),
        ):
            client = get_authenticated_client(vault_cfg)
        assert client is mock_client
        mock_client.auth.approle.login.assert_called_once()

    def test_approle_auth_failure(self, vault_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_client.auth.approle.login.side_effect = Unauthorized("bad creds")
        with (
            patch.dict(
                os.environ,
                {"CM_VAULT_ROLE_ID": "role", "CM_VAULT_SECRET_ID": "secret"},
            ),
            patch("certmesh.vault_client._build_client", return_value=mock_client),
            pytest.raises(VaultAuthenticationError),
        ):
            get_authenticated_client(vault_cfg)

    def test_ldap_success(self, vault_cfg: JsonDict) -> None:
        vault_cfg["auth_method"] = "ldap"
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        with (
            patch.dict(
                os.environ,
                {"CM_VAULT_LDAP_USERNAME": "user", "CM_VAULT_LDAP_PASSWORD": "pass"},
            ),
            patch("certmesh.vault_client._build_client", return_value=mock_client),
        ):
            client = get_authenticated_client(vault_cfg)
        assert client is mock_client

    def test_is_authenticated_false_raises(self, vault_cfg: JsonDict) -> None:
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = False
        with (
            patch.dict(
                os.environ,
                {"CM_VAULT_ROLE_ID": "role", "CM_VAULT_SECRET_ID": "secret"},
            ),
            patch("certmesh.vault_client._build_client", return_value=mock_client),
            pytest.raises(VaultAuthenticationError, match="is_authenticated"),
        ):
            get_authenticated_client(vault_cfg)


class TestReadSecretField:
    def test_success(self) -> None:
        mock_cl = MagicMock()
        mock_cl.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"value": "my-secret"}}
        }
        result = read_secret_field(mock_cl, "secret/my/path", "value")
        assert result == "my-secret"

    def test_missing_field_raises(self) -> None:
        mock_cl = MagicMock()
        mock_cl.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {"other": "x"}}}
        with pytest.raises(VaultSecretNotFoundError, match="not found"):
            read_secret_field(mock_cl, "secret/my/path", "value")

    def test_invalid_path_raises(self) -> None:
        mock_cl = MagicMock()
        mock_cl.secrets.kv.v2.read_secret_version.side_effect = InvalidPath()
        with pytest.raises(VaultSecretNotFoundError):
            read_secret_field(mock_cl, "secret/my/path", "value")


class TestReadAllSecretFields:
    def test_success(self) -> None:
        mock_cl = MagicMock()
        mock_cl.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"a": "1", "b": "2"}}
        }
        result = read_all_secret_fields(mock_cl, "secret/path")
        assert result == {"a": "1", "b": "2"}

    def test_forbidden_raises(self) -> None:
        mock_cl = MagicMock()
        mock_cl.secrets.kv.v2.read_secret_version.side_effect = Forbidden()
        with pytest.raises(VaultAuthenticationError, match="denied"):
            read_all_secret_fields(mock_cl, "secret/path")


class TestWriteSecret:
    def test_success(self) -> None:
        mock_cl = MagicMock()
        write_secret(mock_cl, "secret/path", {"key": "val"})
        mock_cl.secrets.kv.v2.create_or_update_secret.assert_called_once()

    def test_forbidden_raises(self) -> None:
        mock_cl = MagicMock()
        mock_cl.secrets.kv.v2.create_or_update_secret.side_effect = Forbidden()
        with pytest.raises(VaultAuthenticationError, match="denied"):
            write_secret(mock_cl, "secret/path", {"key": "val"})


class TestIssuePKICertificate:
    def test_success(self) -> None:
        mock_cl = MagicMock()
        mock_cl.secrets.pki.generate_certificate.return_value = {
            "data": {
                "certificate": "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
                "private_key": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
                "serial_number": "12:34",
                "ca_chain": [],
            }
        }
        pki_cfg = {"mount_point": "pki", "role_name": "test-role", "ttl": "720h"}
        result = issue_pki_certificate(mock_cl, pki_cfg, "test.example.com")
        assert result["certificate"]
        assert result["serial_number"] == "12:34"

    def test_missing_role_raises(self) -> None:
        mock_cl = MagicMock()
        pki_cfg = {"mount_point": "pki", "role_name": ""}
        with pytest.raises(ConfigurationError, match="role_name"):
            issue_pki_certificate(mock_cl, pki_cfg, "test.example.com")

    def test_forbidden_raises(self) -> None:
        mock_cl = MagicMock()
        mock_cl.secrets.pki.generate_certificate.side_effect = Forbidden()
        pki_cfg = {"mount_point": "pki", "role_name": "test-role"}
        with pytest.raises(VaultAuthenticationError):
            issue_pki_certificate(mock_cl, pki_cfg, "test.example.com")

    def test_with_alt_names_and_ip_sans(self) -> None:
        mock_cl = MagicMock()
        mock_cl.secrets.pki.generate_certificate.return_value = {
            "data": {"certificate": "cert", "serial_number": "1234"}
        }
        pki_cfg = {"mount_point": "pki", "role_name": "test-role", "ttl": "720h"}
        issue_pki_certificate(
            mock_cl,
            pki_cfg,
            "test.example.com",
            alt_names=["api.example.com"],
            ip_sans=["10.0.0.1"],
        )
        call_kwargs = mock_cl.secrets.pki.generate_certificate.call_args
        extra = call_kwargs.kwargs.get("extra_params", {})
        assert extra["alt_names"] == "api.example.com"
        assert extra["ip_sans"] == "10.0.0.1"


class TestSignPKICertificate:
    def test_success(self) -> None:
        mock_cl = MagicMock()
        mock_cl.secrets.pki.sign_certificate.return_value = {
            "data": {
                "certificate": "signed-cert",
                "serial_number": "56:78",
            }
        }
        pki_cfg = {"mount_point": "pki", "role_name": "test-role", "ttl": "720h"}
        result = sign_pki_certificate(
            mock_cl,
            pki_cfg,
            "test.example.com",
            "-----BEGIN CSR-----\nfake\n-----END CSR-----",
        )
        assert result["certificate"] == "signed-cert"

    def test_missing_role_raises(self) -> None:
        mock_cl = MagicMock()
        pki_cfg = {"mount_point": "pki", "role_name": ""}
        with pytest.raises(ConfigurationError, match="role_name"):
            sign_pki_certificate(mock_cl, pki_cfg, "test.example.com", "csr")


class TestRevokePKICertificate:
    def test_success(self) -> None:
        mock_cl = MagicMock()
        mock_cl.secrets.pki.revoke_certificate.return_value = {"data": {"revocation_time": 123}}
        pki_cfg = {"mount_point": "pki"}
        result = revoke_pki_certificate(mock_cl, pki_cfg, "12:34")
        assert result.get("revocation_time") == 123


class TestListPKICertificates:
    def test_success(self) -> None:
        mock_cl = MagicMock()
        mock_cl.secrets.pki.list_certificates.return_value = {"data": {"keys": ["12:34", "56:78"]}}
        pki_cfg = {"mount_point": "pki"}
        result = list_pki_certificates(mock_cl, pki_cfg)
        assert result == ["12:34", "56:78"]


class TestReadPKICertificate:
    def test_success(self) -> None:
        mock_cl = MagicMock()
        mock_cl.secrets.pki.read_certificate.return_value = {
            "data": {"certificate": "cert-pem", "revocation_time": 0}
        }
        pki_cfg = {"mount_point": "pki"}
        result = read_pki_certificate(mock_cl, pki_cfg, "12:34")
        assert result["certificate"] == "cert-pem"
