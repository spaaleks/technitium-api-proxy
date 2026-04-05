"""Integration tests for end-to-end proxy request flow using respx to mock upstream."""
from __future__ import annotations

import json
from typing import Any, Generator

import pytest
import respx
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse


UPSTREAM_BASE = "http://localhost:5380"


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    from proxy.main import app

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


class TestAllowedRequestForwarding:
    """Test: allowed request forwarded to upstream with admin token substituted."""

    @respx.mock
    def test_allowed_get_records_forwarded(self, client: TestClient) -> None:
        upstream_body: dict[str, Any] = {"status": "ok", "response": {"records": []}}
        route = respx.get(f"{UPSTREAM_BASE}/api/zones/records/get").mock(
            return_value=HttpxResponse(200, json=upstream_body),
        )

        resp = client.get(
            "/api/zones/records/get",
            headers={"X-API-Token": "test-secret"},
            params={"zone": "example.com"},
        )

        assert resp.status_code == 200
        assert resp.json() == upstream_body
        assert route.called

    @respx.mock
    def test_admin_token_substituted(self, client: TestClient) -> None:
        """Verify client token is replaced with admin token in upstream request."""
        route = respx.get(f"{UPSTREAM_BASE}/api/zones/records/get").mock(
            return_value=HttpxResponse(200, json={"status": "ok"}),
        )

        client.get(
            "/api/zones/records/get",
            headers={"X-API-Token": "test-secret"},
            params={"zone": "example.com", "token": "test-secret"},
        )

        assert route.called
        upstream_request = route.calls[0].request  # pyright: ignore[reportUnknownVariableType,reportUnknownMemberType]
        query_params: dict[str, str] = dict(upstream_request.url.params)  # pyright: ignore[reportUnknownArgumentType,reportUnknownMemberType]
        assert query_params["token"] == "admin-token"


class TestDeniedRequestNoUpstream:
    """Test: denied request returns 403 without contacting upstream."""

    @respx.mock
    def test_denied_zone_returns_403(self, client: TestClient) -> None:
        route = respx.get(f"{UPSTREAM_BASE}/api/zones/records/get").mock(
            return_value=HttpxResponse(200, json={"status": "ok"}),
        )

        resp = client.get(
            "/api/zones/records/get",
            headers={"X-API-Token": "test-secret"},
            params={"zone": "forbidden.com"},
        )

        assert resp.status_code == 403
        assert "zone not permitted" in resp.json()["errorMessage"]
        assert not route.called  # Upstream not contacted

    @respx.mock
    def test_tier2_endpoint_returns_403(self, client: TestClient) -> None:
        route = respx.post(f"{UPSTREAM_BASE}/api/zones/create").mock(
            return_value=HttpxResponse(200, json={"status": "ok"}),
        )

        resp = client.post(
            "/api/zones/create",
            headers={"X-API-Token": "test-secret"},
        )

        assert resp.status_code == 403
        assert not route.called


class TestGlobalReadOnlyToken:
    """Test: global_read_only token can read but not write."""

    @respx.mock
    def test_read_only_can_list_zones(self, client: TestClient) -> None:
        upstream_body: dict[str, Any] = {"status": "ok", "response": {"zones": []}}
        route = respx.get(f"{UPSTREAM_BASE}/api/zones/list").mock(
            return_value=HttpxResponse(200, json=upstream_body),
        )

        resp = client.get(
            "/api/zones/list",
            headers={"X-API-Token": "readonly-secret"},
        )

        assert resp.status_code == 200
        assert route.called

    @respx.mock
    def test_read_only_can_get_records(self, client: TestClient) -> None:
        route = respx.get(f"{UPSTREAM_BASE}/api/zones/records/get").mock(
            return_value=HttpxResponse(200, json={"status": "ok"}),
        )

        resp = client.get(
            "/api/zones/records/get",
            headers={"X-API-Token": "readonly-secret"},
            params={"zone": "any.com"},
        )

        assert resp.status_code == 200
        assert route.called

    @respx.mock
    def test_read_only_cannot_add_records(self, client: TestClient) -> None:
        route = respx.post(f"{UPSTREAM_BASE}/api/zones/records/add").mock(
            return_value=HttpxResponse(200, json={"status": "ok"}),
        )

        resp = client.post(
            "/api/zones/records/add",
            headers={"X-API-Token": "readonly-secret"},
            params={"zone": "example.com"},
        )

        assert resp.status_code == 403
        assert "read-only" in resp.json()["errorMessage"]
        assert not route.called

    @respx.mock
    def test_read_only_cannot_delete_records(self, client: TestClient) -> None:
        route = respx.post(f"{UPSTREAM_BASE}/api/zones/records/delete").mock(
            return_value=HttpxResponse(200, json={"status": "ok"}),
        )

        resp = client.post(
            "/api/zones/records/delete",
            headers={"X-API-Token": "readonly-secret"},
        )

        assert resp.status_code == 403
        assert not route.called


class TestZoneListFiltering:
    """Test: zone list response filtered to allowed zones only."""

    @respx.mock
    def test_scoped_token_sees_only_allowed_zones(self, client: TestClient) -> None:
        upstream_body = {
            "status": "ok",
            "response": {
                "zones": [
                    {"name": "example.com", "type": "Primary"},
                    {"name": "other.com", "type": "Primary"},
                    {"name": "secret.com", "type": "Primary"},
                ],
            },
        }
        respx.get(f"{UPSTREAM_BASE}/api/zones/list").mock(
            return_value=HttpxResponse(200, json=upstream_body),
        )

        resp = client.get(
            "/api/zones/list",
            headers={"X-API-Token": "test-secret"},
        )

        assert resp.status_code == 200
        zones = resp.json()["response"]["zones"]
        zone_names = [z["name"] for z in zones]
        assert zone_names == ["example.com"]

    @respx.mock
    def test_readonly_token_sees_all_zones(self, client: TestClient) -> None:
        upstream_body = {
            "status": "ok",
            "response": {
                "zones": [
                    {"name": "example.com", "type": "Primary"},
                    {"name": "other.com", "type": "Primary"},
                ],
            },
        }
        respx.get(f"{UPSTREAM_BASE}/api/zones/list").mock(
            return_value=HttpxResponse(200, json=upstream_body),
        )

        resp = client.get(
            "/api/zones/list",
            headers={"X-API-Token": "readonly-secret"},
        )

        assert resp.status_code == 200
        zones = resp.json()["response"]["zones"]
        assert len(zones) == 2


class TestAuditLogging:
    """Test: audit log entry emitted for both allowed and denied requests.

    structlog renders JSON to stdout, so we capture stdout to verify audit entries.
    """

    @respx.mock
    def test_audit_log_on_allowed_request(self, client: TestClient, capsys: pytest.CaptureFixture[str]) -> None:
        respx.get(f"{UPSTREAM_BASE}/api/zones/records/get").mock(
            return_value=HttpxResponse(200, json={"status": "ok"}),
        )

        client.get(
            "/api/zones/records/get",
            headers={"X-API-Token": "test-secret"},
            params={"zone": "example.com"},
        )

        captured = capsys.readouterr().out
        log_lines = [json.loads(line) for line in captured.strip().splitlines() if line.strip()]
        allowed = [l for l in log_lines if l.get("event") == "request_allowed"]
        assert len(allowed) >= 1
        assert allowed[0]["decision"] == "allow"
        assert allowed[0]["token_name"] == "test-client"

    @respx.mock
    def test_audit_log_on_denied_request(self, client: TestClient, capsys: pytest.CaptureFixture[str]) -> None:
        route = respx.get(f"{UPSTREAM_BASE}/api/zones/records/get").mock(
            return_value=HttpxResponse(200, json={"status": "ok"}),
        )

        client.get(
            "/api/zones/records/get",
            headers={"X-API-Token": "test-secret"},
            params={"zone": "forbidden.com"},
        )

        assert not route.called
        captured = capsys.readouterr().out
        log_lines = [json.loads(line) for line in captured.strip().splitlines() if line.strip()]
        denied = [l for l in log_lines if l.get("event") == "request_denied"]
        assert len(denied) >= 1
        assert denied[0]["decision"] == "deny"
        assert "zone not permitted" in denied[0]["deny_reason"]
