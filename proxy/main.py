from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

import os

import httpx
import structlog
import uvicorn
from fastapi import Depends, FastAPI, Request
from fastapi.responses import Response, JSONResponse

from proxy.auth import TokenError, resolve_token
from proxy.config import TokenConfig, load_config
from proxy.logger import setup_logging
from proxy.policy import Tier, classify_endpoint, evaluate_policy, extract_operation, is_read_only_endpoint, is_record_endpoint, resolve_zone

audit_log = structlog.get_logger("proxy.audit")
_reload_log = structlog.get_logger("proxy.reload")

_config = load_config()
setup_logging(os.environ.get("LOG_LEVEL", "info"))

_CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "config.yml"))
_RELOAD_INTERVAL = int(os.environ.get("RELOAD_INTERVAL", "5"))


async def _watch_config(app: FastAPI) -> None:
    """Poll config file for changes and hot-reload on modification."""
    last_mtime: float = _CONFIG_PATH.stat().st_mtime if _CONFIG_PATH.exists() else 0
    while True:
        await asyncio.sleep(_RELOAD_INTERVAL)
        try:
            current_mtime = _CONFIG_PATH.stat().st_mtime
            if current_mtime <= last_mtime:
                continue
            last_mtime = current_mtime
            new_config = load_config()
            app.state.config = new_config
            _reload_log.info("config_reloaded", config_path=str(_CONFIG_PATH))
        except Exception as exc:
            _reload_log.error("config_reload_failed", error=str(exc), config_path=str(_CONFIG_PATH))


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    app.state.config = _config
    app.state.http_client = httpx.AsyncClient(verify=_config.technitium.verify_ssl)
    watcher = asyncio.create_task(_watch_config(app)) if _RELOAD_INTERVAL > 0 else None
    yield
    if watcher is not None:
        watcher.cancel()
    await app.state.http_client.aclose()


app = FastAPI(title="Technitium API Proxy", lifespan=lifespan)


@app.exception_handler(TokenError)
async def token_error_handler(request: Request, exc: TokenError) -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"status": "error", "errorMessage": "Invalid or missing token"},
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def api_proxy(
    request: Request,
    path: str,
    token_config: TokenConfig = Depends(resolve_token),
) -> Response:
    endpoint_path = f"/api/{path}"
    tier = classify_endpoint(endpoint_path)
    client_ip = request.client.host if request.client else "unknown"
    zone_name: str | None = request.query_params.get("zone")
    domain_param: str | None = request.query_params.get("domain")
    type_param: str | None = request.query_params.get("type")
    operation = extract_operation(endpoint_path)

    log_fields: dict[str, str | int | None] = {
        "token_name": token_config.name,
        "endpoint": endpoint_path,
        "method": request.method,
        "zone": zone_name,
        "domain": domain_param,
        "record_type": type_param,
        "operation": operation,
        "client_ip": client_ip,
    }

    if tier is None:
        audit_log.info("request_denied", **log_fields, decision="deny", deny_reason="Not found", upstream_status=None)
        return JSONResponse(
            status_code=404,
            content={"status": "error", "errorMessage": "Not found"},
        )

    if tier in (Tier.TIER_2, Tier.TIER_3):
        reason = "Access denied: endpoint not permitted"
        audit_log.info("request_denied", **log_fields, decision="deny", deny_reason=reason, upstream_status=None)
        return JSONResponse(
            status_code=403,
            content={"status": "error", "errorMessage": reason},
        )

    # Global read-only tokens: allow reads, block writes
    if token_config.global_read_only:
        if not is_read_only_endpoint(endpoint_path):
            reason = "Access denied: read-only token"
            audit_log.info("request_denied", **log_fields, decision="deny", deny_reason=reason, upstream_status=None)
            return JSONResponse(
                status_code=403,
                content={"status": "error", "errorMessage": reason},
            )
    else:
        # Tier 1: resolve zone for record endpoints
        if is_record_endpoint(endpoint_path):
            configured_zones = [z.name for z in token_config.zones]
            resolved_zone: str | None = resolve_zone(
                zone_param=zone_name,
                domain_param=domain_param,
                configured_zones=configured_zones,
            )
            if resolved_zone is None:
                reason = "Access denied: zone cannot be determined"
                audit_log.info("request_denied", **log_fields, decision="deny", deny_reason=reason, upstream_status=None)
                return JSONResponse(
                    status_code=403,
                    content={"status": "error", "errorMessage": reason},
                )

            # Update zone in log fields to resolved value
            log_fields["zone"] = resolved_zone

            # Evaluate fine-grained policy
            denial = evaluate_policy(
                zone=resolved_zone,
                zone_policies=token_config.zones,
                endpoint_path=endpoint_path,
                domain_param=domain_param,
                type_param=type_param,
            )
            if denial is not None:
                audit_log.info("request_denied", **log_fields, decision="deny", deny_reason=denial, upstream_status=None)
                return JSONResponse(
                    status_code=403,
                    content={"status": "error", "errorMessage": denial},
                )

    # Tier 1: forward request to upstream Technitium
    response = await forward_upstream(request, endpoint_path)

    # Filter zone list for scoped tokens
    # Wildcard zones ('*') won't match real zone names, so only explicitly
    # listed zones appear in the filtered list.
    if endpoint_path.lower().rstrip("/") == "/api/zones/list" and not token_config.global_read_only:
        response = _filter_zone_list_response(response, token_config)

    audit_log.info("request_allowed", **log_fields, decision="allow", deny_reason=None, upstream_status=response.status_code)
    return response


def _filter_zone_list_response(response: Response, token_config: TokenConfig) -> Response:
    """Filter /api/zones/list response to only include zones the token is allowed to access."""
    try:
        data: dict[str, Any] = json.loads(bytes(response.body))
    except (json.JSONDecodeError, ValueError):
        return response

    zones: list[dict[str, Any]] | None = data.get("response", {}).get("zones")
    if zones is None:
        return response

    allowed_zone_names = {z.name.lower() for z in token_config.zones}
    filtered = [z for z in zones if z.get("name", "").lower() in allowed_zone_names]

    data["response"]["zones"] = filtered
    filtered_body = json.dumps(data)

    # Preserve original headers but update content-length
    headers = dict(response.headers)
    headers.pop("content-length", None)

    return Response(
        content=filtered_body,
        status_code=response.status_code,
        headers=headers,
        media_type=response.media_type,
    )


async def forward_upstream(request: Request, endpoint_path: str) -> Response:
    """Forward a request to the upstream Technitium server with token substitution."""
    config = request.app.state.config
    client: httpx.AsyncClient = request.app.state.http_client

    # Build upstream URL
    base_url = config.technitium.url.rstrip("/")
    upstream_url = f"{base_url}{endpoint_path}"

    # Build query params: strip client token, inject admin token
    upstream_params: list[tuple[str, str]] = [
        (k, v)
        for k, v in request.query_params.multi_items()
        if k.lower() != "token"
    ]
    upstream_params.append(("token", config.technitium.token))
    params_seq: tuple[tuple[str, str], ...] = tuple(upstream_params)

    # Build headers: strip hop-by-hop and client auth headers
    skip_headers = {"host", "x-api-token", "content-length", "transfer-encoding"}
    upstream_headers = {
        k: v
        for k, v in request.headers.items()
        if k.lower() not in skip_headers
    }

    body = await request.body()

    upstream_response = await client.request(
        method=request.method,
        url=upstream_url,
        params=params_seq,
        headers=upstream_headers,
        content=body if body else None,
    )

    # Return upstream response: status, headers, body
    response_headers = dict(upstream_response.headers)
    # Remove hop-by-hop headers from response
    for h in ("transfer-encoding", "content-encoding", "content-length"):
        response_headers.pop(h, None)

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
    )


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "31399"))
    log_level = os.environ.get("LOG_LEVEL", "info")
    uvicorn.run(
        "proxy.main:app",
        host=host,
        port=port,
        log_level=log_level,
    )


if __name__ == "__main__":
    main()
