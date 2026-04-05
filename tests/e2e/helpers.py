"""Shared helpers for e2e tests."""
from __future__ import annotations

import httpx

from tests.e2e.conftest import TOKENS


def auth_header(token_key: str) -> dict[str, str]:
    """Return X-API-Token header for a named token."""
    return {"X-API-Token": TOKENS[token_key]}


def add_record(
    technitium: httpx.Client,
    zone: str,
    domain: str,
    rtype: str = "A",
    value: str = "1.2.3.4",
    ttl: int = 300,
) -> None:
    """Create a DNS record directly in Technitium (bypassing the proxy)."""
    params: dict[str, str | int] = {
        "zone": zone,
        "domain": domain,
        "type": rtype,
        "ttl": ttl,
    }
    if rtype in ("A", "AAAA"):
        params["ipAddress"] = value
    elif rtype == "TXT":
        params["text"] = value
    elif rtype == "CNAME":
        params["cname"] = value
    elif rtype == "MX":
        params["exchange"] = value
        params["preference"] = 10

    r = technitium.get("/api/zones/records/add", params=params)
    r.raise_for_status()


def delete_record(
    technitium: httpx.Client,
    zone: str,
    domain: str,
    rtype: str = "A",
    value: str = "1.2.3.4",
) -> None:
    """Delete a DNS record directly in Technitium."""
    params: dict[str, str] = {
        "zone": zone,
        "domain": domain,
        "type": rtype,
    }
    if rtype in ("A", "AAAA"):
        params["ipAddress"] = value
    elif rtype == "TXT":
        params["text"] = value
    elif rtype == "CNAME":
        params["cname"] = value
    elif rtype == "MX":
        params["exchange"] = value
        params["preference"] = "10"

    technitium.get("/api/zones/records/delete", params=params)
