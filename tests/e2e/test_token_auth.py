"""E2E: Token authentication - valid/invalid/missing tokens."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.e2e.conftest import TOKENS
from tests.e2e.helpers import auth_header

pytestmark = pytest.mark.e2e


class TestTokenAuthentication:

    def test_allow_valid_token_in_header(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list", headers=auth_header("full_access"))
        assert resp.status_code == 200

    def test_allow_valid_token_in_query_param(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list", params={"token": TOKENS["full_access"]})
        assert resp.status_code == 200

    def test_deny_missing_token(self, client: TestClient) -> None:
        resp = client.get("/api/zones/list")
        assert resp.status_code == 401
        assert "Invalid or missing token" in resp.json()["errorMessage"]

    def test_deny_invalid_token(self, client: TestClient) -> None:
        resp = client.get(
            "/api/zones/list",
            headers={"X-API-Token": "bogus-nonexistent-token"},
        )
        assert resp.status_code == 401
