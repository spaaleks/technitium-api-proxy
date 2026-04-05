from __future__ import annotations

import re
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from proxy.config import ZonePolicy

class Tier(Enum):
    TIER_1 = 1
    TIER_2 = 2
    TIER_3 = 3


# Tier 1: record operations + zone list (read)
_TIER_1_PREFIXES = (
    "/api/zones/records/get",
    "/api/zones/records/add",
    "/api/zones/records/update",
    "/api/zones/records/delete",
    "/api/zones/list",
)

# Tier 1 endpoints that require a zone to be resolved
_TIER_1_RECORD_PREFIXES = (
    "/api/zones/records/get",
    "/api/zones/records/add",
    "/api/zones/records/update",
    "/api/zones/records/delete",
)

# Tier 2: zone management operations
_TIER_2_PREFIXES = (
    "/api/zones/create",
    "/api/zones/delete",
    "/api/zones/enable",
    "/api/zones/disable",
    "/api/zones/import",
    "/api/zones/export",
)


def classify_endpoint(path: str) -> Tier | None:
    """Classify an API endpoint into a tier.

    Returns None for non-/api/ paths.
    """
    if not path.startswith("/api/"):
        return None

    lower = path.lower().rstrip("/")

    for prefix in _TIER_1_PREFIXES:
        if lower == prefix or lower.startswith(prefix + "/"):
            return Tier.TIER_1

    for prefix in _TIER_2_PREFIXES:
        if lower == prefix or lower.startswith(prefix + "/"):
            return Tier.TIER_2

    return Tier.TIER_3


def is_record_endpoint(path: str) -> bool:
    """Return True if the path is a Tier 1 record endpoint that requires zone resolution."""
    lower = path.lower().rstrip("/")
    for prefix in _TIER_1_RECORD_PREFIXES:
        if lower == prefix or lower.startswith(prefix + "/"):
            return True
    return False


# Map endpoint path suffixes to operation names
_OPERATION_MAP: dict[str, str] = {
    "/api/zones/records/get": "get",
    "/api/zones/records/add": "add",
    "/api/zones/records/update": "update",
    "/api/zones/records/delete": "delete",
}


_READ_ONLY_PREFIXES = (
    "/api/zones/records/get",
    "/api/zones/list",
)


def is_read_only_endpoint(path: str) -> bool:
    """Return True if the path is a read-only Tier 1 endpoint."""
    lower = path.lower().rstrip("/")
    for prefix in _READ_ONLY_PREFIXES:
        if lower == prefix or lower.startswith(prefix + "/"):
            return True
    return False


def extract_operation(path: str) -> str | None:
    """Extract the operation name from a record endpoint path."""
    lower = path.lower().rstrip("/")
    for prefix, op in _OPERATION_MAP.items():
        if lower == prefix or lower.startswith(prefix + "/"):
            return op
    return None


def find_zone_policy(
    zone: str, zone_policies: list[ZonePolicy],
) -> ZonePolicy | None:
    """Find the ZonePolicy matching the given zone name (case-insensitive)."""
    zone_lower = zone.lower()
    for zp in zone_policies:
        if zp.name.lower() == zone_lower:
            return zp
    return None


def evaluate_policy(
    zone: str,
    zone_policies: list[ZonePolicy],
    endpoint_path: str,
    domain_param: str | None,
    type_param: str | None,
) -> str | None:
    """Evaluate access policy for a request.

    Returns an error message string if the request should be denied,
    or None if the request is permitted.
    """
    zone_policy = find_zone_policy(zone, zone_policies)
    if zone_policy is None:
        return "Access denied: zone not permitted"

    operation = extract_operation(endpoint_path)
    if operation and zone_policy.allowed_operations:
        if operation not in zone_policy.allowed_operations:
            return f"Access denied: operation {operation} not permitted"

    if type_param and zone_policy.allowed_record_types:
        if type_param.upper() not in (rt.upper() for rt in zone_policy.allowed_record_types):
            return f"Access denied: record type {type_param} not allowed"

    if zone_policy.subdomain_filter and domain_param:
        if not re.search(zone_policy.subdomain_filter, domain_param, re.IGNORECASE):
            return "Access denied: subdomain not permitted"

    return None


def resolve_zone(
    zone_param: str | None,
    domain_param: str | None,
    configured_zones: list[str],
) -> str | None:
    """Extract the target zone from request parameters.

    Priority: ?zone= takes precedence over ?domain=.
    For ?domain=, strips leftmost labels until a configured zone matches.
    Returns None if no zone can be determined.
    """
    if zone_param:
        return zone_param

    if not domain_param:
        return None

    # Strip leftmost labels from domain until we find a configured zone
    lower_zones = {z.lower(): z for z in configured_zones}
    domain = domain_param.lower()
    while domain:
        if domain in lower_zones:
            return lower_zones[domain]
        # Strip the leftmost label
        dot_idx = domain.find(".")
        if dot_idx == -1:
            break
        domain = domain[dot_idx + 1 :]

    return None
