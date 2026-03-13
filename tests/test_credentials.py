"""Tests for certmesh.credentials."""

from __future__ import annotations

import os
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from certmesh.credentials import (
    resolve_digicert_api_key,
    resolve_venafi_credentials,
    vault_required,
    vault_required_for_digicert,
    vault_required_for_venafi,
)
from certmesh.exceptions import ConfigurationError

JsonDict = dict[str, Any]


class TestVaultRequired:
    def test_vault_required_when_no_env_vars(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            assert vault_required_for_digicert() is True
            assert vault_required_for_venafi() is True

    def test_vault_not_required_for_digicert(self) -> None:
        with patch.dict(os.environ, {"CM_DIGICERT_API_KEY": "test-key"}):
            assert vault_required_for_digicert() is False

    def test_vault_not_required_for_venafi(self) -> None:
        with patch.dict(
            os.environ,
            {"CM_VENAFI_USERNAME": "user", "CM_VENAFI_PASSWORD": "pass"},
        ):
            assert vault_required_for_venafi() is False

    def test_partial_venafi_creds_raises(self) -> None:
        with patch.dict(os.environ, {"CM_VENAFI_USERNAME": "user"}, clear=True):
            with pytest.raises(ConfigurationError, match="Both"):
                vault_required_for_venafi()

    def test_vault_required_combined(self) -> None:
        with patch.dict(
            os.environ,
            {"CM_DIGICERT_API_KEY": "k", "CM_VENAFI_USERNAME": "u", "CM_VENAFI_PASSWORD": "p"},
        ):
            assert vault_required({}) is False


class TestResolveDigicertAPIKey:
    def test_from_env(self, vault_cfg: JsonDict) -> None:
        with patch.dict(os.environ, {"CM_DIGICERT_API_KEY": "env-key"}):
            assert resolve_digicert_api_key(vault_cfg, None) == "env-key"

    def test_from_vault(self, vault_cfg: JsonDict) -> None:
        mock_cl = MagicMock()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("certmesh.vault_client.read_secret_field", return_value="vault-key"),
        ):
            key = resolve_digicert_api_key(vault_cfg, mock_cl)
        assert key == "vault-key"

    def test_no_source_raises(self, vault_cfg: JsonDict) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ConfigurationError, match="No DigiCert"):
                resolve_digicert_api_key(vault_cfg, None)


class TestResolveVenafiCredentials:
    def test_from_env(self, vault_cfg: JsonDict) -> None:
        with patch.dict(
            os.environ,
            {"CM_VENAFI_USERNAME": "user", "CM_VENAFI_PASSWORD": "pass"},
        ):
            creds = resolve_venafi_credentials(vault_cfg, None)
        assert creds == {"username": "user", "password": "pass"}

    def test_from_vault(self, vault_cfg: JsonDict) -> None:
        mock_cl = MagicMock()
        expected = {"username": "vu", "password": "vp"}
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("certmesh.vault_client.read_all_secret_fields", return_value=expected),
        ):
            creds = resolve_venafi_credentials(vault_cfg, mock_cl)
        assert creds == expected

    def test_partial_env_raises(self, vault_cfg: JsonDict) -> None:
        with patch.dict(os.environ, {"CM_VENAFI_USERNAME": "user"}, clear=True):
            with pytest.raises(ConfigurationError, match="Both"):
                resolve_venafi_credentials(vault_cfg, None)

    def test_no_source_raises(self, vault_cfg: JsonDict) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ConfigurationError, match="No Venafi"):
                resolve_venafi_credentials(vault_cfg, None)
