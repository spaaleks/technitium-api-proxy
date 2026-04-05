from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel


class TechnitiumConfig(BaseModel):
    url: str
    token: str
    verify_ssl: bool = True


class ZonePolicy(BaseModel):
    name: str
    allowed_record_types: list[str] = []
    allowed_operations: list[str] = []
    subdomain_filter: str | None = None


class TokenConfig(BaseModel):
    name: str
    token: str
    global_read_only: bool = False
    zones: list[ZonePolicy] = []


class AppConfig(BaseModel):
    technitium: TechnitiumConfig
    tokens: list[TokenConfig] = []


def load_config() -> AppConfig:
    config_path = Path(os.environ.get("CONFIG_PATH", "config.yml"))
    with open(config_path) as f:
        raw = yaml.safe_load(f)
    return AppConfig.model_validate(raw)
