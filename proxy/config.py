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


class ZonePolicyInput(BaseModel):
    """Config input that accepts either 'name' (single) or 'names' (list)."""
    name: str | None = None
    names: list[str] | None = None
    allowed_record_types: list[str] = []
    allowed_operations: list[str] = []
    subdomain_filter: str | None = None


def _expand_zone_policies(inputs: list[dict]) -> list[ZonePolicy]:
    """Expand zone policy inputs: entries with 'names' become multiple ZonePolicy objects."""
    result: list[ZonePolicy] = []
    for raw in inputs:
        entry = ZonePolicyInput.model_validate(raw)
        if entry.names is not None:
            for n in entry.names:
                result.append(ZonePolicy(
                    name=n,
                    allowed_record_types=entry.allowed_record_types,
                    allowed_operations=entry.allowed_operations,
                    subdomain_filter=entry.subdomain_filter,
                ))
        elif entry.name is not None:
            result.append(ZonePolicy(
                name=entry.name,
                allowed_record_types=entry.allowed_record_types,
                allowed_operations=entry.allowed_operations,
                subdomain_filter=entry.subdomain_filter,
            ))
        else:
            raise ValueError("Zone policy must have either 'name' or 'names'")
    return result


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

    # Expand 'names' shorthand in zone policies before validation
    for token_raw in raw.get("tokens", []):
        if "zones" in token_raw:
            token_raw["zones"] = [
                {"name": zp.name, "allowed_record_types": zp.allowed_record_types,
                 "allowed_operations": zp.allowed_operations, "subdomain_filter": zp.subdomain_filter}
                for zp in _expand_zone_policies(token_raw["zones"])
            ]

    return AppConfig.model_validate(raw)
