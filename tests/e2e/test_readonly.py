"""E2E: Read-only token - reads allowed, writes blocked."""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.e2e.conftest import ZONE_ALLOWED, ZONE_FORBIDDEN
from tests.e2e.helpers import auth_header

pytestmark = pytest.mark.e2e


class TestReadOnlyToken:

    # -- ALLOW --

    def test_allow_list_zones(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list", headers=auth_header("readonly"))
        assert resp.status_code == 200

    def test_allow_get_records(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/records/get",
            headers=auth_header("readonly"),
            params={"zone": ZONE_ALLOWED},
        )
        assert resp.status_code == 200

    def test_allow_get_records_any_zone(self, client: TestClient) -> None:
        """Read-only tokens can read from any zone (no zone scoping)."""
        resp = client.get(
            "/api/zones/records/get",
            headers=auth_header("readonly"),
            params={"zone": ZONE_FORBIDDEN},
        )
        assert resp.status_code == 200

    # -- DENY --

    def test_deny_add_records(self, client: TestClient) -> None:
        resp = client.post(
            "/api/zones/records/add",
            headers=auth_header("readonly"),
            params={"zone": ZONE_ALLOWED, "domain": f"ro-add.{ZONE_ALLOWED}", "type": "A", "ipAddress": "10.0.3.1"},
        )
        assert resp.status_code == 403
        assert "read-only" in resp.json()["errorMessage"]

    def test_deny_update_records(self, client: TestClient) -> None:
        resp = client.post(
            "/api/zones/records/update",
            headers=auth_header("readonly"),
            params={"zone": ZONE_ALLOWED, "domain": f"ro-upd.{ZONE_ALLOWED}", "type": "A"},
        )
        assert resp.status_code == 403
        assert "read-only" in resp.json()["errorMessage"]

    def test_deny_delete_records(self, client: TestClient) -> None:
        resp = client.post(
            "/api/zones/records/delete",
            headers=auth_header("readonly"),
            params={"zone": ZONE_ALLOWED, "domain": f"ro-del.{ZONE_ALLOWED}", "type": "A"},
        )
        assert resp.status_code == 403
        assert "read-only" in resp.json()["errorMessage"]

    def test_deny_add_does_not_reach_technitium(
        self, client: TestClient, technitium: httpx.Client
    ) -> None:
        domain = f"ro-blocked.{ZONE_ALLOWED}"
        client.post(
            "/api/zones/records/add",
            headers=auth_header("readonly"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "10.0.3.2"},
        )
        r = technitium.get(
            "/api/zones/records/get",
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A"},
        )
        records = r.json().get("response", {}).get("records", [])
        a_records = [rec for rec in records if rec.get("type") == "A" and rec.get("rData", {}).get("ipAddress") == "10.0.3.2"]
        assert len(a_records) == 0
