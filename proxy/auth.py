from __future__ import annotations

from fastapi import Header, Query, Request
from fastapi.responses import JSONResponse

from proxy.config import TokenConfig

_UNAUTHORIZED = JSONResponse(
    status_code=401,
    content={"status": "error", "errorMessage": "Invalid or missing token"},
)


class TokenError(Exception):
    pass


def resolve_token(
    request: Request,
    x_api_token: str | None = Header(None),
    token: str | None = Query(None),
) -> TokenConfig:
    """Resolve and validate the API token from header or query parameter.

    Header takes precedence over query parameter.
    """
    raw_token = x_api_token or token

    if not raw_token:
        raise TokenError

    config = request.app.state.config
    for tc in config.tokens:
        if tc.token == raw_token:
            return tc

    raise TokenError
