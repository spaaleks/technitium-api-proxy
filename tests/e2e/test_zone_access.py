"""E2E: Zone access control and zone list filtering."""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.e2e.conftest import ZONE_ALLOWED, ZONE_SECOND, ZONE_FORBIDDEN
from tests.e2e.helpers import add_record, auth_header, delete_record

pytestmark = pytest.mark.e2e


class TestZoneAccess:
    """Scoped tokens can only access their configured zones."""

    # -- ALLOW --

    def test_allow_configured_zone(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/records/get",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED},
        )
        assert resp.status_code == 200

    def test_allow_zone_via_domain_resolution(
        self, client: TestClient, technitium: httpx.Client
    ) -> None:
        """Zone should be resolved from ?domain= by stripping labels."""
        add_record(technitium, ZONE_ALLOWED, f"sub.{ZONE_ALLOWED}", "A", "10.0.0.1")
        resp = client.get(
            "/api/zones/records/get",
            headers=auth_header("full_access"),
            params={"domain": f"sub.{ZONE_ALLOWED}", "type": "A"},
        )
        assert resp.status_code == 200
        delete_record(technitium, ZONE_ALLOWED, f"sub.{ZONE_ALLOWED}", "A", "10.0.0.1")

    # -- DENY --

    def test_deny_forbidden_zone(self, client: TestClient) -> None:
        """Zone exists in Technitium but is NOT in the token's config."""
        resp = client.get(
            "/api/zones/records/get",
            headers=auth_header("full_access"),
            params={"zone": ZONE_FORBIDDEN},
        )
        assert resp.status_code == 403
        assert "zone not permitted" in resp.json()["errorMessage"]

    def test_deny_nonexistent_zone(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/records/get",
            headers=auth_header("full_access"),
            params={"zone": "does-not-exist.test"},
        )
        assert resp.status_code == 403

    def test_deny_missing_zone_param(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/records/get",
            headers=auth_header("full_access"),
        )
        assert resp.status_code == 403
        assert "zone cannot be determined" in resp.json()["errorMessage"]

    def test_deny_domain_resolves_to_forbidden_zone(
        self, client: TestClient, technitium: httpx.Client
    ) -> None:
        add_record(technitium, ZONE_FORBIDDEN, f"sub.{ZONE_FORBIDDEN}", "A", "10.0.0.1")
        resp = client.get(
            "/api/zones/records/get",
            headers=auth_header("full_access"),
            params={"domain": f"sub.{ZONE_FORBIDDEN}"},
        )
        assert resp.status_code == 403
        delete_record(technitium, ZONE_FORBIDDEN, f"sub.{ZONE_FORBIDDEN}", "A", "10.0.0.1")


class TestZoneListFiltering:
    """Scoped tokens see only their allowed zones in /api/zones/list."""

    def test_scoped_token_sees_only_allowed_zone(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list", headers=auth_header("full_access"))
        assert resp.status_code == 200
        zone_names = [z["name"] for z in resp.json()["response"]["zones"]]
        assert ZONE_ALLOWED in zone_names
        assert ZONE_FORBIDDEN not in zone_names
        assert ZONE_SECOND not in zone_names

    def test_multi_zone_token_sees_both_allowed_zones(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list", headers=auth_header("multi_zone"))
        assert resp.status_code == 200
        zone_names = [z["name"] for z in resp.json()["response"]["zones"]]
        assert ZONE_ALLOWED in zone_names
        assert ZONE_SECOND in zone_names
        assert ZONE_FORBIDDEN not in zone_names

    def test_readonly_token_sees_all_zones(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list", headers=auth_header("readonly"))
        assert resp.status_code == 200
        zone_names = [z["name"] for z in resp.json()["response"]["zones"]]
        assert ZONE_ALLOWED in zone_names
        assert ZONE_SECOND in zone_names
        assert ZONE_FORBIDDEN in zone_names
