"""Tests for token authentication."""
from __future__ import annotations

from typing import Generator

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    """Create a TestClient that runs the lifespan (sets app.state.config)."""
    from proxy.main import app

    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


class TestTokenFromHeader:
    """Tests for token extraction from X-API-Token header."""

    def test_valid_header_token(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list", headers={"X-API-Token": "test-secret"})
        # Should not be 401 — token is valid (may be 502/other due to no upstream)
        assert resp.status_code != 401

    def test_invalid_header_token(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list", headers={"X-API-Token": "wrong-token"})
        assert resp.status_code == 401
        body = resp.json()
        assert body["status"] == "error"
        assert "token" in body["errorMessage"].lower()


class TestTokenFromQuery:
    """Tests for token extraction from ?token= query parameter."""

    def test_valid_query_token(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list", params={"token": "test-secret"})
        assert resp.status_code != 401

    def test_invalid_query_token(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list", params={"token": "bad-token"})
        assert resp.status_code == 401
        body = resp.json()
        assert body["status"] == "error"


class TestMissingToken:
    """Tests for 401 response when no token is provided."""

    def test_no_token_at_all(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list")
        assert resp.status_code == 401
        body = resp.json()
        assert body["status"] == "error"
        assert "token" in body["errorMessage"].lower()

    def test_empty_header_token(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list", headers={"X-API-Token": ""})
        assert resp.status_code == 401


class TestHeaderPrecedence:
    """Header should take precedence over query parameter."""

    def test_header_wins_over_query(self, client: TestClient) -> None:
        # Valid header, invalid query — should succeed (not 401)
        resp = client.get(
            "/api/zones/list",
            headers={"X-API-Token": "test-secret"},
            params={"token": "wrong"},
        )
        assert resp.status_code != 401

    def test_invalid_header_blocks_even_with_valid_query(self, client: TestClient) -> None:
        # Invalid header, valid query — header takes precedence, should fail
        resp = client.get(
            "/api/zones/list",
            headers={"X-API-Token": "wrong"},
            params={"token": "test-secret"},
        )
        assert resp.status_code == 401
