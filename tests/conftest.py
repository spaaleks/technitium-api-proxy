"""Shared fixtures for tests.

Sets CONFIG_PATH before any proxy module is imported so that the
module-level load_config() in main.py finds a valid config file.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Generator

import pytest

# Minimal valid YAML config for test purposes
MINIMAL_CONFIG_YAML = """\
technitium:
  url: "http://localhost:5380"
  token: "admin-token"
tokens:
  - name: "test-client"
    token: "test-secret"
    zones:
      - name: "example.com"
  - name: "readonly-client"
    token: "readonly-secret"
    global_read_only: true
"""


@pytest.fixture(autouse=True)
def _set_config_path(tmp_path: Path) -> Generator[None, None, None]:  # pyright: ignore[reportUnusedFunction]
    """Write a test config and point CONFIG_PATH to it before each test."""
    config_file = tmp_path / "config.yml"
    config_file.write_text(MINIMAL_CONFIG_YAML)
    old = os.environ.get("CONFIG_PATH")
    os.environ["CONFIG_PATH"] = str(config_file)
    yield
    if old is None:
        os.environ.pop("CONFIG_PATH", None)
    else:
        os.environ["CONFIG_PATH"] = old
