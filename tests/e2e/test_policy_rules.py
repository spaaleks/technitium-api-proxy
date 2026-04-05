"""E2E: Fine-grained policy rules - operations, record types, subdomain filtering."""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.e2e.conftest import ZONE_ALLOWED
from tests.e2e.helpers import add_record, auth_header, delete_record

pytestmark = pytest.mark.e2e


# ===========================================================================
# Operation Filtering
# ===========================================================================


class TestOperationFiltering:
    """Token with allowed_operations=["get"] can only read, not write."""

    # -- ALLOW --

    def test_allow_permitted_operation_get(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/records/get",
            headers=auth_header("limited_ops"),
            params={"zone": ZONE_ALLOWED},
        )
        assert resp.status_code == 200

    # -- DENY --

    def test_deny_operation_add(self, client: TestClient) -> None:
        resp = client.post(
            "/api/zones/records/add",
            headers=auth_header("limited_ops"),
            params={
                "zone": ZONE_ALLOWED,
                "domain": f"blocked.{ZONE_ALLOWED}",
                "type": "A",
                "ipAddress": "6.6.6.6",
            },
        )
        assert resp.status_code == 403
        assert "operation add not permitted" in resp.json()["errorMessage"]

    def test_deny_operation_update(self, client: TestClient) -> None:
        resp = client.post(
            "/api/zones/records/update",
            headers=auth_header("limited_ops"),
            params={"zone": ZONE_ALLOWED, "domain": f"x.{ZONE_ALLOWED}", "type": "A"},
        )
        assert resp.status_code == 403
        assert "operation update not permitted" in resp.json()["errorMessage"]

    def test_deny_operation_delete(self, client: TestClient) -> None:
        resp = client.post(
            "/api/zones/records/delete",
            headers=auth_header("limited_ops"),
            params={"zone": ZONE_ALLOWED, "domain": f"x.{ZONE_ALLOWED}", "type": "A"},
        )
        assert resp.status_code == 403
        assert "operation delete not permitted" in resp.json()["errorMessage"]

    def test_deny_add_does_not_create_record(
        self, client: TestClient, technitium: httpx.Client
    ) -> None:
        """Verify denied add never reaches Technitium."""
        domain = f"should-not-exist.{ZONE_ALLOWED}"
        client.post(
            "/api/zones/records/add",
            headers=auth_header("limited_ops"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "6.6.6.6"},
        )
        r = technitium.get(
            "/api/zones/records/get",
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A"},
        )
        records = r.json().get("response", {}).get("records", [])
        a_records = [rec for rec in records if rec.get("type") == "A" and rec.get("rData", {}).get("ipAddress") == "6.6.6.6"]
        assert len(a_records) == 0


# ===========================================================================
# Record Type Filtering
# ===========================================================================


class TestRecordTypeFiltering:
    """Token with allowed_record_types=["A","AAAA"] blocks other types."""

    # -- ALLOW --

    def test_allow_permitted_type_a(
        self, client: TestClient, technitium: httpx.Client
    ) -> None:
        domain = f"type-a.{ZONE_ALLOWED}"
        resp = client.get(
            "/api/zones/records/add",
            headers=auth_header("limited_types"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "10.0.0.50"},
        )
        assert resp.status_code == 200
        delete_record(technitium, ZONE_ALLOWED, domain, "A", "10.0.0.50")

    def test_allow_permitted_type_aaaa(
        self, client: TestClient, technitium: httpx.Client
    ) -> None:
        domain = f"type-aaaa.{ZONE_ALLOWED}"
        resp = client.get(
            "/api/zones/records/add",
            headers=auth_header("limited_types"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "AAAA", "ipAddress": "::1"},
        )
        assert resp.status_code == 200
        delete_record(technitium, ZONE_ALLOWED, domain, "AAAA", "::1")

    # -- DENY --

    def test_deny_type_txt(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/records/add",
            headers=auth_header("limited_types"),
            params={"zone": ZONE_ALLOWED, "domain": f"txt.{ZONE_ALLOWED}", "type": "TXT", "text": "nope"},
        )
        assert resp.status_code == 403
        assert "record type TXT not allowed" in resp.json()["errorMessage"]

    def test_deny_type_mx(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/records/add",
            headers=auth_header("limited_types"),
            params={"zone": ZONE_ALLOWED, "domain": f"mx.{ZONE_ALLOWED}", "type": "MX", "exchange": "mail.example.com", "preference": "10"},
        )
        assert resp.status_code == 403
        assert "record type MX not allowed" in resp.json()["errorMessage"]

    def test_deny_type_cname(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/records/add",
            headers=auth_header("limited_types"),
            params={"zone": ZONE_ALLOWED, "domain": f"cname.{ZONE_ALLOWED}", "type": "CNAME", "cname": "other.example.com"},
        )
        assert resp.status_code == 403
        assert "record type CNAME not allowed" in resp.json()["errorMessage"]

    def test_deny_type_does_not_create_record(
        self, client: TestClient, technitium: httpx.Client
    ) -> None:
        domain = f"denied-txt.{ZONE_ALLOWED}"
        client.get(
            "/api/zones/records/add",
            headers=auth_header("limited_types"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "TXT", "text": "nope"},
        )
        r = technitium.get(
            "/api/zones/records/get",
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "TXT"},
        )
        records = r.json().get("response", {}).get("records", [])
        assert not any(rec.get("type") == "TXT" for rec in records)


# ===========================================================================
# Subdomain Filtering
# ===========================================================================


class TestSubdomainFiltering:
    """Token with subdomain_filter="app." only allows matching domains."""

    # -- ALLOW --

    def test_allow_matching_subdomain(
        self, client: TestClient, technitium: httpx.Client
    ) -> None:
        domain = f"app.service.{ZONE_ALLOWED}"
        resp = client.get(
            "/api/zones/records/add",
            headers=auth_header("subdomain_filtered"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "10.0.1.1"},
        )
        assert resp.status_code == 200
        delete_record(technitium, ZONE_ALLOWED, domain, "A", "10.0.1.1")

    def test_allow_exact_prefix(
        self, client: TestClient, technitium: httpx.Client
    ) -> None:
        domain = f"app.{ZONE_ALLOWED}"
        resp = client.get(
            "/api/zones/records/add",
            headers=auth_header("subdomain_filtered"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "10.0.1.2"},
        )
        assert resp.status_code == 200
        delete_record(technitium, ZONE_ALLOWED, domain, "A", "10.0.1.2")

    # -- DENY --

    def test_deny_non_matching_subdomain(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/records/add",
            headers=auth_header("subdomain_filtered"),
            params={"zone": ZONE_ALLOWED, "domain": f"web.{ZONE_ALLOWED}", "type": "A", "ipAddress": "10.0.2.1"},
        )
        assert resp.status_code == 403
        assert "subdomain not permitted" in resp.json()["errorMessage"]

    def test_deny_bare_zone_domain(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/records/add",
            headers=auth_header("subdomain_filtered"),
            params={"zone": ZONE_ALLOWED, "domain": ZONE_ALLOWED, "type": "A", "ipAddress": "10.0.2.2"},
        )
        assert resp.status_code == 403
        assert "subdomain not permitted" in resp.json()["errorMessage"]

    def test_deny_subdomain_does_not_create_record(
        self, client: TestClient, technitium: httpx.Client
    ) -> None:
        domain = f"web.{ZONE_ALLOWED}"
        client.get(
            "/api/zones/records/add",
            headers=auth_header("subdomain_filtered"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "10.0.2.1"},
        )
        r = technitium.get(
            "/api/zones/records/get",
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A"},
        )
        records = r.json().get("response", {}).get("records", [])
        a_records = [rec for rec in records if rec.get("type") == "A" and rec.get("rData", {}).get("ipAddress") == "10.0.2.1"]
        assert len(a_records) == 0
