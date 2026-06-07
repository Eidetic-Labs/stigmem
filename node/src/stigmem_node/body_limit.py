"""Request body-size limit middleware (F-AVAIL-1).

Rejects requests whose declared ``Content-Length`` exceeds the configured cap
before the body is read or parsed, bounding memory use from a single request.
``settings.max_request_body_bytes == 0`` disables the check.
"""

from __future__ import annotations

from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .settings import settings


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Return 413 when ``Content-Length`` exceeds ``max_request_body_bytes``."""

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        limit = settings.max_request_body_bytes
        if limit > 0:
            raw = request.headers.get("content-length")
            if raw is not None:
                try:
                    declared = int(raw)
                except ValueError:
                    declared = -1
                if declared > limit:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": f"request body exceeds {limit} bytes",
                            "max_request_body_bytes": limit,
                        },
                    )
        return await call_next(request)
