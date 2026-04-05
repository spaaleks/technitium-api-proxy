"""E2E test fixtures.

Requires a running Technitium DNS server (see docker-compose.e2e.yml).
Set TECHNITIUM_URL to override the default http://localhost:5380.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Generator

import dns.resolver
import httpx
import pytest

TECHNITIUM_URL = os.environ.get("TECHNITIUM_URL", "http://localhost:5380")
TECHNITIUM_DNS_PORT = int(os.environ.get("TECHNITIUM_DNS_PORT", "5354"))

# Client tokens used in the proxy config (arbitrary secrets for testing)
TOKENS = {
    "full_access": "e2e-full-access-secret",
    "limited_ops": "e2e-limited-ops-secret",
    "limited_types": "e2e-limited-types-secret",
    "subdomain_filtered": "e2e-subdomain-secret",
    "readonly": "e2e-readonly-secret",
    "multi_zone": "e2e-multi-zone-secret",
}

ZONE_ALLOWED = "e2e-allowed.test"
ZONE_SECOND = "e2e-second.test"
ZONE_FORBIDDEN = "e2e-forbidden.test"


def _wait_for_technitium(url: str, timeout: float = 60) -> None:
    """Poll Technitium until it responds or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{url}/", timeout=3)
            if r.status_code < 500:
                return
        except httpx.ConnectError:
            pass
        time.sleep(1)
    pytest.fail(f"Technitium did not become ready at {url} within {timeout}s")


def _technitium_login(url: str) -> str:
    """Login to Technitium and return the admin API token."""
    r = httpx.get(
        f"{url}/api/user/login",
        params={"user": "admin", "pass": "admin", "includeInfo": "true"},
        timeout=10,
    )
    r.raise_for_status()
    data = r.json()
    if data.get("status") != "ok":
        pytest.fail(f"Technitium login failed: {data}")
    return data["token"]


def _create_zone(url: str, token: str, zone: str) -> None:
    """Create a primary zone in Technitium (idempotent)."""
    r = httpx.get(
        f"{url}/api/zones/create",
        params={"token": token, "zone": zone, "type": "Primary"},
        timeout=10,
    )
    r.raise_for_status()


def _build_config_yaml(admin_token: str) -> str:
    return f"""\
technitium:
  url: "{TECHNITIUM_URL}"
  token: "{admin_token}"
  verify_ssl: false

tokens:
  - name: "full-access"
    token: "{TOKENS['full_access']}"
    zones:
      - name: "{ZONE_ALLOWED}"

  - name: "limited-ops"
    token: "{TOKENS['limited_ops']}"
    zones:
      - name: "{ZONE_ALLOWED}"
        allowed_operations: ["get"]

  - name: "limited-types"
    token: "{TOKENS['limited_types']}"
    zones:
      - name: "{ZONE_ALLOWED}"
        allowed_record_types: ["A", "AAAA"]

  - name: "subdomain-filtered"
    token: "{TOKENS['subdomain_filtered']}"
    zones:
      - name: "{ZONE_ALLOWED}"
        subdomain_filter: "^app\\."

  - name: "readonly"
    token: "{TOKENS['readonly']}"
    global_read_only: true

  - name: "multi-zone"
    token: "{TOKENS['multi_zone']}"
    zones:
      - name: "{ZONE_ALLOWED}"
      - name: "{ZONE_SECOND}"
"""


@pytest.fixture(scope="session")
def technitium_admin_token() -> str:
    """Wait for Technitium, login, create test zones, return admin token."""
    _wait_for_technitium(TECHNITIUM_URL)
    token = _technitium_login(TECHNITIUM_URL)

    for zone in (ZONE_ALLOWED, ZONE_SECOND, ZONE_FORBIDDEN):
        _create_zone(TECHNITIUM_URL, token, zone)

    return token


@pytest.fixture(scope="session")
def e2e_config_path(
    technitium_admin_token: str, tmp_path_factory: pytest.TempPathFactory
) -> Path:
    """Write the proxy config file and return its path."""
    config_dir = tmp_path_factory.mktemp("e2e_config")
    config_file = config_dir / "config.yml"
    config_file.write_text(_build_config_yaml(technitium_admin_token))
    return config_file


@pytest.fixture(scope="session")
def e2e_app(e2e_config_path: Path):  # noqa: ANN201
    """Create the FastAPI app with the e2e config pointing at real Technitium."""
    os.environ["CONFIG_PATH"] = str(e2e_config_path)

    # Clear any cached proxy modules so load_config() re-runs with our config
    for mod_name in list(sys.modules):
        if mod_name.startswith("proxy"):
            del sys.modules[mod_name]

    from proxy.main import app
    return app


@pytest.fixture()
def client(e2e_app) -> Generator:  # noqa: ANN001
    from fastapi.testclient import TestClient
    with TestClient(e2e_app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture()
def technitium(technitium_admin_token: str) -> Generator[httpx.Client, None, None]:
    """Direct httpx client to Technitium for verification queries."""
    c = httpx.Client(base_url=TECHNITIUM_URL, params={"token": technitium_admin_token})
    yield c
    c.close()


@pytest.fixture(scope="session")
def dns_resolver() -> dns.resolver.Resolver:
    """DNS resolver configured to query the Technitium DNS server directly."""
    import socket
    from urllib.parse import urlparse
    hostname = urlparse(TECHNITIUM_URL).hostname or "127.0.0.1"
    # dnspython requires an IP address, not a hostname
    ip = socket.gethostbyname(hostname)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [ip]
    resolver.port = TECHNITIUM_DNS_PORT
    resolver.lifetime = 5
    return resolver
