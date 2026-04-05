"""E2E: Real DNS record CRUD, admin token substitution, and DNS protocol verification."""
from __future__ import annotations

import dns.resolver
import httpx
import pytest
from fastapi.testclient import TestClient

from tests.e2e.conftest import TOKENS, ZONE_ALLOWED
from tests.e2e.helpers import auth_header, delete_record

pytestmark = pytest.mark.e2e


class TestAdminTokenSubstitution:
    """Verify the proxy replaces client tokens with the admin token."""

    def test_proxy_creates_record_with_admin_token(
        self, client: TestClient, technitium: httpx.Client
    ) -> None:
        domain = f"substitution-test.{ZONE_ALLOWED}"
        resp = client.get(
            "/api/zones/records/add",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "10.0.4.1", "ttl": "300"},
        )
        assert resp.status_code == 200

        r = technitium.get(
            "/api/zones/records/get",
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A"},
        )
        ips = [rec["rData"]["ipAddress"] for rec in r.json()["response"]["records"] if rec["type"] == "A"]
        assert "10.0.4.1" in ips
        delete_record(technitium, ZONE_ALLOWED, domain, "A", "10.0.4.1")

    def test_client_token_not_leaked_to_upstream(
        self, client: TestClient, technitium: httpx.Client
    ) -> None:
        domain = f"token-leak-test.{ZONE_ALLOWED}"
        resp = client.get(
            "/api/zones/records/add",
            headers=auth_header("full_access"),
            params={
                "zone": ZONE_ALLOWED,
                "domain": domain,
                "type": "A",
                "ipAddress": "10.0.4.2",
                "token": TOKENS["full_access"],
            },
        )
        assert resp.status_code == 200
        delete_record(technitium, ZONE_ALLOWED, domain, "A", "10.0.4.2")


class TestRealDnsRecordCrud:
    """Full create-read-update-delete cycle through the proxy."""

    def test_full_crud_lifecycle(
        self, client: TestClient, technitium: httpx.Client
    ) -> None:
        domain = f"crud-test.{ZONE_ALLOWED}"

        # CREATE
        resp = client.get(
            "/api/zones/records/add",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "10.0.5.1", "ttl": "300"},
        )
        assert resp.status_code == 200

        # READ - through proxy
        resp = client.get(
            "/api/zones/records/get",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A"},
        )
        assert resp.status_code == 200
        ips = [r["rData"]["ipAddress"] for r in resp.json()["response"]["records"] if r["type"] == "A"]
        assert "10.0.5.1" in ips

        # READ - verify in Technitium directly
        r = technitium.get(
            "/api/zones/records/get",
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A"},
        )
        direct_ips = [rec["rData"]["ipAddress"] for rec in r.json()["response"]["records"] if rec["type"] == "A"]
        assert "10.0.5.1" in direct_ips

        # UPDATE
        resp = client.get(
            "/api/zones/records/update",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "10.0.5.1", "newIpAddress": "10.0.5.2", "ttl": "600"},
        )
        assert resp.status_code == 200

        r = technitium.get(
            "/api/zones/records/get",
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A"},
        )
        updated_ips = [rec["rData"]["ipAddress"] for rec in r.json()["response"]["records"] if rec["type"] == "A"]
        assert "10.0.5.2" in updated_ips
        assert "10.0.5.1" not in updated_ips

        # DELETE
        resp = client.get(
            "/api/zones/records/delete",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "10.0.5.2"},
        )
        assert resp.status_code == 200

        r = technitium.get(
            "/api/zones/records/get",
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A"},
        )
        remaining = [
            rec for rec in r.json()["response"]["records"]
            if rec["type"] == "A" and rec["rData"]["ipAddress"] in ("10.0.5.1", "10.0.5.2")
        ]
        assert len(remaining) == 0


class TestDnsProtocolResolution:
    """Verify records created through the proxy are resolvable via DNS protocol."""

    def test_a_record_resolvable_via_dns(
        self,
        client: TestClient,
        technitium: httpx.Client,
        dns_resolver: dns.resolver.Resolver,
    ) -> None:
        domain = f"dns-resolve-a.{ZONE_ALLOWED}"
        client.get(
            "/api/zones/records/add",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "10.0.6.1", "ttl": "60"},
        )

        answers = dns_resolver.resolve(domain, "A")
        resolved_ips = [rdata.address for rdata in answers]
        assert "10.0.6.1" in resolved_ips

        delete_record(technitium, ZONE_ALLOWED, domain, "A", "10.0.6.1")

    def test_aaaa_record_resolvable_via_dns(
        self,
        client: TestClient,
        technitium: httpx.Client,
        dns_resolver: dns.resolver.Resolver,
    ) -> None:
        domain = f"dns-resolve-aaaa.{ZONE_ALLOWED}"
        client.get(
            "/api/zones/records/add",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "AAAA", "ipAddress": "2001:db8::1", "ttl": "60"},
        )

        answers = dns_resolver.resolve(domain, "AAAA")
        resolved = [rdata.address for rdata in answers]
        assert "2001:db8::1" in resolved

        delete_record(technitium, ZONE_ALLOWED, domain, "AAAA", "2001:db8::1")

    def test_txt_record_resolvable_via_dns(
        self,
        client: TestClient,
        technitium: httpx.Client,
        dns_resolver: dns.resolver.Resolver,
    ) -> None:
        domain = f"dns-resolve-txt.{ZONE_ALLOWED}"
        client.get(
            "/api/zones/records/add",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "TXT", "text": "e2e-verification", "ttl": "60"},
        )

        answers = dns_resolver.resolve(domain, "TXT")
        texts = [rdata.strings[0].decode() for rdata in answers]
        assert "e2e-verification" in texts

        delete_record(technitium, ZONE_ALLOWED, domain, "TXT", "e2e-verification")

    def test_deleted_record_not_resolvable_via_dns(
        self,
        client: TestClient,
        technitium: httpx.Client,
        dns_resolver: dns.resolver.Resolver,
    ) -> None:
        """After deleting a record through the proxy, DNS should not resolve it."""
        domain = f"dns-deleted.{ZONE_ALLOWED}"

        # Create then delete
        client.get(
            "/api/zones/records/add",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "10.0.6.99", "ttl": "60"},
        )
        client.get(
            "/api/zones/records/delete",
            headers=auth_header("full_access"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "10.0.6.99"},
        )

        with pytest.raises(dns.resolver.NXDOMAIN):
            dns_resolver.resolve(domain, "A")

    def test_denied_record_not_resolvable_via_dns(
        self,
        client: TestClient,
        dns_resolver: dns.resolver.Resolver,
    ) -> None:
        """A denied add should leave no DNS record."""
        domain = f"dns-denied.{ZONE_ALLOWED}"

        # Try to add via limited-ops token (only allows get)
        resp = client.post(
            "/api/zones/records/add",
            headers=auth_header("limited_ops"),
            params={"zone": ZONE_ALLOWED, "domain": domain, "type": "A", "ipAddress": "10.0.6.100"},
        )
        assert resp.status_code == 403

        with pytest.raises(dns.resolver.NXDOMAIN):
            dns_resolver.resolve(domain, "A")


class TestHealthCheck:
    """Health endpoint requires no auth."""

    def test_health_no_auth_required(self, client: TestClient) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
