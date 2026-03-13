"""Tests for certmesh.settings."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from certmesh.exceptions import ConfigurationError
from certmesh.settings import (
    _bool,
    _deep_merge,
    _int,
    _sset,
    build_config,
    configure_logging,
    validate_config,
)

JsonDict = dict[str, Any]


class TestDeepMerge:
    def test_basic_merge(self) -> None:
        base = {"a": 1, "b": {"c": 2, "d": 3}}
        override = {"b": {"c": 99}}
        result = _deep_merge(base, override)
        assert result["a"] == 1
        assert result["b"]["c"] == 99
        assert result["b"]["d"] == 3

    def test_none_values_skipped(self) -> None:
        base = {"a": 1}
        override = {"a": None, "b": 2}
        result = _deep_merge(base, override)
        assert result["a"] == 1
        assert result["b"] == 2

    def test_new_keys_added(self) -> None:
        base = {"a": 1}
        override = {"b": 2}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 2}

    def test_does_not_mutate_base(self) -> None:
        base = {"a": {"b": 1}}
        override = {"a": {"b": 2}}
        _deep_merge(base, override)
        assert base["a"]["b"] == 1


class TestSset:
    def test_simple_path(self) -> None:
        d: JsonDict = {}
        _sset(d, ["a", "b"], 42)
        assert d == {"a": {"b": 42}}

    def test_none_value_skipped(self) -> None:
        d: JsonDict = {}
        _sset(d, ["a"], None)
        assert d == {}

    def test_overwrites_existing(self) -> None:
        d: JsonDict = {"a": {"b": 1}}
        _sset(d, ["a", "b"], 2)
        assert d["a"]["b"] == 2


class TestBool:
    @pytest.mark.parametrize("val", ["1", "true", "True", "yes", "on", "  TRUE  "])
    def test_truthy(self, val: str) -> None:
        assert _bool(val) is True

    @pytest.mark.parametrize("val", ["0", "false", "no", "off", "other"])
    def test_falsy(self, val: str) -> None:
        assert _bool(val) is False

    def test_none(self) -> None:
        assert _bool(None) is None


class TestInt:
    def test_valid(self) -> None:
        assert _int("42") == 42

    def test_invalid(self) -> None:
        assert _int("abc") is None

    def test_none(self) -> None:
        assert _int(None) is None


class TestBuildConfig:
    def test_defaults_loaded(self) -> None:
        cfg = build_config()
        assert "vault" in cfg
        assert "digicert" in cfg
        assert "venafi" in cfg
        assert "acm" in cfg
        assert "logging" in cfg

    def test_env_overrides(self) -> None:
        with patch.dict(os.environ, {"CM_VAULT_URL": "https://my-vault.example.com"}):
            cfg = build_config()
        assert cfg["vault"]["url"] == "https://my-vault.example.com"

    def test_yaml_file(self, tmp_path: Path) -> None:
        config_file = tmp_path / "test.yaml"
        config_file.write_text(yaml.dump({"vault": {"url": "https://yaml-vault.com"}}))
        cfg = build_config(config_file=str(config_file))
        assert cfg["vault"]["url"] == "https://yaml-vault.com"

    def test_missing_config_file_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="not found"):
            build_config(config_file="/nonexistent/path.yaml")

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        config_file = tmp_path / "bad.yaml"
        config_file.write_text(":::invalid yaml{{{}}")
        with pytest.raises(ConfigurationError, match="does not contain a YAML mapping"):
            build_config(config_file=str(config_file))

    def test_malformed_yaml_raises(self, tmp_path: Path) -> None:
        config_file = tmp_path / "bad.yaml"
        config_file.write_text("{{{\n  bad: [unterminated")
        with pytest.raises(ConfigurationError, match="Failed to parse"):
            build_config(config_file=str(config_file))

    def test_env_overrides_yaml(self, tmp_path: Path) -> None:
        config_file = tmp_path / "test.yaml"
        config_file.write_text(yaml.dump({"vault": {"url": "https://yaml-vault.com"}}))
        with patch.dict(os.environ, {"CM_VAULT_URL": "https://env-vault.com"}):
            cfg = build_config(config_file=str(config_file))
        assert cfg["vault"]["url"] == "https://env-vault.com"

    def test_acm_env_overrides(self) -> None:
        with patch.dict(os.environ, {"CM_ACM_REGION": "eu-west-1"}):
            cfg = build_config()
        assert cfg["acm"]["region"] == "eu-west-1"

    def test_vault_pki_env_overrides(self) -> None:
        with patch.dict(
            os.environ,
            {"CM_VAULT_PKI_MOUNT": "pki-int", "CM_VAULT_PKI_ROLE": "my-role"},
        ):
            cfg = build_config()
        assert cfg["vault"]["pki"]["mount_point"] == "pki-int"
        assert cfg["vault"]["pki"]["role_name"] == "my-role"


class TestValidateConfig:
    def test_valid_config_passes(self, tmp_path: Path) -> None:
        cfg = build_config()
        cfg["vault"]["url"] = "https://vault.example.com"
        cfg["venafi"]["base_url"] = "https://venafi.example.com"
        validate_config(cfg)

    def test_missing_vault_url_raises(self) -> None:
        cfg = build_config()
        cfg["vault"]["url"] = ""
        cfg["venafi"]["base_url"] = "https://venafi.example.com"
        with pytest.raises(ConfigurationError, match="vault.url"):
            validate_config(cfg)

    def test_invalid_vault_auth_method_raises(self) -> None:
        cfg = build_config()
        cfg["vault"]["url"] = "https://vault.example.com"
        cfg["vault"]["auth_method"] = "invalid"
        with pytest.raises(ConfigurationError, match="auth_method"):
            validate_config(cfg)

    def test_missing_venafi_base_url_raises(self) -> None:
        cfg = build_config()
        cfg["vault"]["url"] = "https://vault.example.com"
        with pytest.raises(ConfigurationError, match="venafi.base_url"):
            validate_config(cfg)

    def test_invalid_digicert_output_dest_raises(self) -> None:
        cfg = build_config()
        cfg["vault"]["url"] = "https://vault.example.com"
        cfg["venafi"]["base_url"] = "https://venafi.example.com"
        cfg["digicert"]["output"]["destination"] = "invalid"
        with pytest.raises(ConfigurationError, match="destination"):
            validate_config(cfg)


class TestConfigureLogging:
    def test_configure_logging(self) -> None:
        configure_logging({"level": "DEBUG", "format": "%(message)s"})

    def test_configure_logging_defaults(self) -> None:
        configure_logging({})
