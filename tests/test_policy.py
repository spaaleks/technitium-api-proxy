"""Tests for zone extraction and policy evaluation engine."""
from __future__ import annotations

from proxy.config import ZonePolicy
from proxy.policy import evaluate_policy, find_zone_policy, has_wildcard_zone, resolve_zone


class TestResolveZoneFromParam:
    """Tests for zone extraction from ?zone= parameter."""

    def test_zone_param_returned_directly(self) -> None:
        result = resolve_zone("example.com", None, ["example.com"])
        assert result == "example.com"

    def test_zone_param_takes_precedence_over_domain(self) -> None:
        result = resolve_zone("example.com", "sub.other.com", ["example.com", "other.com"])
        assert result == "example.com"

    def test_zone_param_not_in_configured_zones_still_returned(self) -> None:
        # resolve_zone returns zone_param as-is; policy check handles allowlist
        result = resolve_zone("unknown.com", None, ["example.com"])
        assert result == "unknown.com"


class TestResolveZoneFromDomain:
    """Tests for zone derivation from ?domain= by stripping labels."""

    def test_exact_domain_match(self) -> None:
        result = resolve_zone(None, "example.com", ["example.com"])
        assert result == "example.com"

    def test_single_label_strip(self) -> None:
        result = resolve_zone(None, "sub.example.com", ["example.com"])
        assert result == "example.com"

    def test_multiple_label_strip(self) -> None:
        result = resolve_zone(None, "a.b.c.example.com", ["example.com"])
        assert result == "example.com"

    def test_case_insensitive_matching(self) -> None:
        result = resolve_zone(None, "Sub.Example.COM", ["example.com"])
        assert result == "example.com"

    def test_returns_original_configured_zone_case(self) -> None:
        result = resolve_zone(None, "sub.myzone.io", ["MyZone.IO"])
        assert result == "MyZone.IO"

    def test_no_match_returns_none(self) -> None:
        result = resolve_zone(None, "sub.other.com", ["example.com"])
        assert result is None

    def test_no_domain_no_zone_returns_none(self) -> None:
        result = resolve_zone(None, None, ["example.com"])
        assert result is None


class TestEvaluatePolicyZoneAllowlist:
    """Tests for zone allowlist enforcement."""

    def test_allowed_zone(self) -> None:
        policies = [ZonePolicy(name="example.com")]
        result = evaluate_policy("example.com", policies, "/api/zones/records/get", None, None)
        assert result is None

    def test_denied_zone(self) -> None:
        policies = [ZonePolicy(name="example.com")]
        result = evaluate_policy("other.com", policies, "/api/zones/records/get", None, None)
        assert result is not None
        assert "zone not permitted" in result

    def test_zone_match_case_insensitive(self) -> None:
        policies = [ZonePolicy(name="Example.COM")]
        result = evaluate_policy("example.com", policies, "/api/zones/records/get", None, None)
        assert result is None


class TestEvaluatePolicyOperations:
    """Tests for operation check enforcement."""

    def test_allowed_operation(self) -> None:
        policies = [ZonePolicy(name="example.com", allowed_operations=["get", "add"])]
        result = evaluate_policy("example.com", policies, "/api/zones/records/get", None, None)
        assert result is None

    def test_denied_operation(self) -> None:
        policies = [ZonePolicy(name="example.com", allowed_operations=["get"])]
        result = evaluate_policy("example.com", policies, "/api/zones/records/delete", None, None)
        assert result is not None
        assert "operation" in result
        assert "delete" in result

    def test_empty_allowed_operations_means_all_allowed(self) -> None:
        policies = [ZonePolicy(name="example.com", allowed_operations=[])]
        result = evaluate_policy("example.com", policies, "/api/zones/records/delete", None, None)
        assert result is None


class TestEvaluatePolicyRecordTypes:
    """Tests for record type check enforcement."""

    def test_allowed_record_type(self) -> None:
        policies = [ZonePolicy(name="example.com", allowed_record_types=["A", "AAAA"])]
        result = evaluate_policy("example.com", policies, "/api/zones/records/get", None, "A")
        assert result is None

    def test_denied_record_type(self) -> None:
        policies = [ZonePolicy(name="example.com", allowed_record_types=["A"])]
        result = evaluate_policy("example.com", policies, "/api/zones/records/get", None, "MX")
        assert result is not None
        assert "record type" in result
        assert "MX" in result

    def test_record_type_case_insensitive(self) -> None:
        policies = [ZonePolicy(name="example.com", allowed_record_types=["a", "aaaa"])]
        result = evaluate_policy("example.com", policies, "/api/zones/records/get", None, "A")
        assert result is None

    def test_empty_allowed_record_types_means_all_allowed(self) -> None:
        policies = [ZonePolicy(name="example.com", allowed_record_types=[])]
        result = evaluate_policy("example.com", policies, "/api/zones/records/get", None, "MX")
        assert result is None


class TestEvaluatePolicySubdomainFilter:
    """Tests for subdomain_filter enforcement."""

    def test_matching_subdomain(self) -> None:
        policies = [ZonePolicy(name="example.com", subdomain_filter=r"^app\.")]
        result = evaluate_policy(
            "example.com", policies, "/api/zones/records/get", "app.example.com", None,
        )
        assert result is None

    def test_non_matching_subdomain(self) -> None:
        policies = [ZonePolicy(name="example.com", subdomain_filter=r"^app\.")]
        result = evaluate_policy(
            "example.com", policies, "/api/zones/records/get", "mail.example.com", None,
        )
        assert result is not None
        assert "subdomain not permitted" in result

    def test_no_subdomain_filter_allows_all(self) -> None:
        policies = [ZonePolicy(name="example.com", subdomain_filter=None)]
        result = evaluate_policy(
            "example.com", policies, "/api/zones/records/get", "anything.example.com", None,
        )
        assert result is None

    def test_no_domain_param_skips_subdomain_check(self) -> None:
        policies = [ZonePolicy(name="example.com", subdomain_filter=r"^app\.")]
        result = evaluate_policy(
            "example.com", policies, "/api/zones/records/get", None, None,
        )
        assert result is None

    def test_regex_pattern_multiple_subdomains(self) -> None:
        policies = [ZonePolicy(name="example.com", subdomain_filter=r"^(app|api)\.")]
        result = evaluate_policy(
            "example.com", policies, "/api/zones/records/get", "app.example.com", None,
        )
        assert result is None
        result = evaluate_policy(
            "example.com", policies, "/api/zones/records/get", "api.example.com", None,
        )
        assert result is None
        result = evaluate_policy(
            "example.com", policies, "/api/zones/records/get", "mail.example.com", None,
        )
        assert result is not None


class TestWildcardZone:
    """Tests for wildcard zone ('*') support."""

    def test_has_wildcard_zone_true(self) -> None:
        policies = [ZonePolicy(name="*", allowed_record_types=["TXT"])]
        assert has_wildcard_zone(policies) is True

    def test_has_wildcard_zone_false(self) -> None:
        policies = [ZonePolicy(name="example.com")]
        assert has_wildcard_zone(policies) is False

    def test_find_zone_policy_wildcard_fallback(self) -> None:
        wildcard = ZonePolicy(name="*", allowed_record_types=["TXT"])
        policies = [ZonePolicy(name="example.com"), wildcard]
        assert find_zone_policy("example.com", policies).name == "example.com"
        assert find_zone_policy("other.com", policies) is wildcard

    def test_resolve_zone_wildcard_with_domain(self) -> None:
        result = resolve_zone(None, "_acme-challenge.example.com", ["*"])
        assert result == "_acme-challenge.example.com"

    def test_resolve_zone_wildcard_with_zone_param(self) -> None:
        result = resolve_zone("example.com", None, ["*"])
        assert result == "example.com"

    def test_resolve_zone_wildcard_prefers_explicit_match(self) -> None:
        result = resolve_zone(None, "_acme-challenge.example.com", ["*", "example.com"])
        assert result == "example.com"

    def test_evaluate_policy_wildcard_allows_any_zone(self) -> None:
        policies = [ZonePolicy(name="*", allowed_record_types=["TXT"], allowed_operations=["add", "delete"])]
        result = evaluate_policy("anydomain.com", policies, "/api/zones/records/add", None, "TXT")
        assert result is None

    def test_evaluate_policy_wildcard_enforces_record_type(self) -> None:
        policies = [ZonePolicy(name="*", allowed_record_types=["TXT"])]
        result = evaluate_policy("anydomain.com", policies, "/api/zones/records/add", None, "A")
        assert result is not None
        assert "record type" in result

    def test_evaluate_policy_wildcard_enforces_subdomain_filter(self) -> None:
        policies = [ZonePolicy(name="*", subdomain_filter=r"^_acme-challenge\.")]
        result = evaluate_policy("example.com", policies, "/api/zones/records/add", "_acme-challenge.example.com", None)
        assert result is None
        result = evaluate_policy("example.com", policies, "/api/zones/records/add", "www.example.com", None)
        assert result is not None

    def test_evaluate_policy_wildcard_enforces_operations(self) -> None:
        policies = [ZonePolicy(name="*", allowed_operations=["add", "delete"])]
        result = evaluate_policy("example.com", policies, "/api/zones/records/get", None, None)
        assert result is not None
        assert "operation" in result
