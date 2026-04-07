"""Tests for config parsing and validation."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from proxy.config import AppConfig, load_config


class TestLoadConfig:
    """Tests for load_config() from YAML files."""

    def test_valid_config_loads(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yml"
        config_file.write_text(
            """\
technitium:
  url: "http://dns:5380"
  token: "admin-tok"
  verify_ssl: false
tokens:
  - name: "client-a"
    token: "secret-a"
    zones:
      - name: "example.com"
        allowed_record_types: ["A", "AAAA"]
        allowed_operations: ["list", "get"]
        subdomain_filter: "sub"
"""
        )
        os.environ["CONFIG_PATH"] = str(config_file)
        cfg = load_config()

        assert cfg.technitium.url == "http://dns:5380"
        assert cfg.technitium.token == "admin-tok"
        assert cfg.technitium.verify_ssl is False
        assert len(cfg.tokens) == 1
        assert cfg.tokens[0].name == "client-a"
        assert cfg.tokens[0].zones[0].name == "example.com"
        assert cfg.tokens[0].zones[0].allowed_record_types == ["A", "AAAA"]
        assert cfg.tokens[0].zones[0].subdomain_filter == "sub"

    def test_defaults_applied(self, tmp_path: Path) -> None:
        """Optional fields get defaults when omitted."""
        config_file = tmp_path / "config.yml"
        config_file.write_text(
            """\
technitium:
  url: "http://dns:5380"
  token: "tok"
"""
        )
        os.environ["CONFIG_PATH"] = str(config_file)
        cfg = load_config()

        assert cfg.technitium.verify_ssl is True
        assert cfg.tokens == []

    def test_missing_technitium_url_fails(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yml"
        config_file.write_text(
            """\
technitium:
  token: "tok"
"""
        )
        os.environ["CONFIG_PATH"] = str(config_file)
        with pytest.raises(ValidationError, match="url"):
            load_config()

    def test_missing_technitium_token_fails(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yml"
        config_file.write_text(
            """\
technitium:
  url: "http://dns:5380"
"""
        )
        os.environ["CONFIG_PATH"] = str(config_file)
        with pytest.raises(ValidationError, match="token"):
            load_config()

    def test_missing_technitium_section_fails(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yml"
        config_file.write_text("tokens: []\n")
        os.environ["CONFIG_PATH"] = str(config_file)
        with pytest.raises(ValidationError, match="technitium"):
            load_config()

    def test_file_not_found_raises(self, tmp_path: Path) -> None:
        os.environ["CONFIG_PATH"] = str(tmp_path / "nonexistent.yml")
        with pytest.raises(FileNotFoundError):
            load_config()


class TestAppConfigModel:
    """Tests for config model validation directly."""

    def test_token_global_read_only_default(self) -> None:
        cfg = AppConfig.model_validate(
            {
                "technitium": {"url": "http://x", "token": "t"},
                "tokens": [{"name": "ro", "token": "s"}],
            }
        )
        assert cfg.tokens[0].global_read_only is False
        assert cfg.tokens[0].zones == []

    def test_zone_policy_defaults(self) -> None:
        cfg = AppConfig.model_validate(
            {
                "technitium": {"url": "http://x", "token": "t"},
                "tokens": [
                    {
                        "name": "c",
                        "token": "s",
                        "zones": [{"name": "z.com"}],
                    }
                ],
            }
        )
        zp = cfg.tokens[0].zones[0]
        assert zp.allowed_record_types == []
        assert zp.allowed_operations == []
        assert zp.subdomain_filter is None


class TestZonePolicyExpansion:
    """Tests for 'names' shorthand expansion in zone policies."""

    def test_names_expands_to_multiple_policies(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yml"
        config_file.write_text(
            """\
technitium:
  url: "http://dns:5380"
  token: "admin-tok"
tokens:
  - name: "acme"
    token: "acme-tok"
    zones:
      - names: ["example.com", "other.org", "third.io"]
        allowed_record_types: ["TXT"]
        allowed_operations: ["add", "delete"]
        subdomain_filter: "^_acme-challenge\\\\."
"""
        )
        os.environ["CONFIG_PATH"] = str(config_file)
        cfg = load_config()

        zones = cfg.tokens[0].zones
        assert len(zones) == 3
        assert [z.name for z in zones] == ["example.com", "other.org", "third.io"]
        for z in zones:
            assert z.allowed_record_types == ["TXT"]
            assert z.allowed_operations == ["add", "delete"]
            assert z.subdomain_filter == "^_acme-challenge\\."

    def test_names_mixed_with_name(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yml"
        config_file.write_text(
            """\
technitium:
  url: "http://dns:5380"
  token: "admin-tok"
tokens:
  - name: "mixed"
    token: "mixed-tok"
    zones:
      - name: "single.com"
        allowed_record_types: ["A"]
      - names: ["multi1.com", "multi2.com"]
        allowed_record_types: ["TXT"]
"""
        )
        os.environ["CONFIG_PATH"] = str(config_file)
        cfg = load_config()

        zones = cfg.tokens[0].zones
        assert len(zones) == 3
        assert zones[0].name == "single.com"
        assert zones[0].allowed_record_types == ["A"]
        assert zones[1].name == "multi1.com"
        assert zones[1].allowed_record_types == ["TXT"]
        assert zones[2].name == "multi2.com"
        assert zones[2].allowed_record_types == ["TXT"]

    def test_neither_name_nor_names_raises(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yml"
        config_file.write_text(
            """\
technitium:
  url: "http://dns:5380"
  token: "admin-tok"
tokens:
  - name: "bad"
    token: "bad-tok"
    zones:
      - allowed_record_types: ["TXT"]
"""
        )
        os.environ["CONFIG_PATH"] = str(config_file)
        with pytest.raises(ValueError, match="name.*names"):
            load_config()
