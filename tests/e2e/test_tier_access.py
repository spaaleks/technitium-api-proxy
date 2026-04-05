"""E2E: Tier-based access control - Tier 1 allowed, Tier 2/3 blocked."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.e2e.conftest import ZONE_ALLOWED
from tests.e2e.helpers import auth_header

pytestmark = pytest.mark.e2e


class TestTierAccess:

    # -- ALLOW --

    def test_allow_tier1_zones_list(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list", headers=auth_header("full_access"))
        assert resp.status_code == 200

    def test_allow_tier1_records_get(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/records/get",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED},
        )
        assert resp.status_code == 200

    # -- DENY --

    def test_deny_tier2_zones_create(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/create",
            headers=auth_header("full_access"),
            params={"zone": "should-not-create.test", "type": "Primary"},
        )
        assert resp.status_code == 403
        assert "endpoint not permitted" in resp.json()["errorMessage"]

    def test_deny_tier2_zones_delete(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/delete",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED},
        )
        assert resp.status_code == 403

    def test_deny_tier2_zones_enable(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/enable",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED},
        )
        assert resp.status_code == 403

    def test_deny_tier2_zones_disable(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/disable",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED},
        )
        assert resp.status_code == 403

    def test_deny_tier3_admin_endpoint(self, client: TestClient) -> None:
        resp = client.get(
            "/api/admin/settings/get",
            headers=auth_header("full_access"),
        )
        assert resp.status_code in (403, 404)

    def test_deny_tier3_dashboard(self, client: TestClient) -> None:
        resp = client.get(
            "/api/dashboard/stats",
            headers=auth_header("full_access"),
        )
        assert resp.status_code in (403, 404)
