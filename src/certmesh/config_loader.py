"""
certmesh.config_loader
========================

Compatibility shim — delegates to certmesh.settings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from certmesh.settings import build_config, configure_logging, validate_config

__all__ = ["configure_logging", "load_config"]

JsonDict = dict[str, Any]


def load_config(config_path: str | Path = "config/config.yaml") -> JsonDict:
    """Load configuration from a YAML file (deprecated — use ``build_config``)."""
    cfg = build_config(config_file=config_path)
    validate_config(cfg)
    return cfg
