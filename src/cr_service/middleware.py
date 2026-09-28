"""HTTP middleware for the wide event and gateway prefixes."""

import http
import logging
import time
import uuid
from typing import Any

import fastapi
import sentry_sdk
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from cr_service import context
from cr_service.tracing import current_trace_context, set_span_attributes

logger = logging.getLogger("access")

# Probe hits are logged at debug so they do not drown out real traffic.
_PROBE_PATHS = frozenset({"/livez", "/readyz", "/metrics"})


def _resolve_request_id(request: fastapi.Request) -> str:
    """Reuse an upstream correlation id if present, otherwise mint one."""
    upstream = request.headers.get("x-request-id") or request.headers.get("x-amzn-trace-id")
    return upstream or uuid.uuid4().hex


def _client_ip(request: fastapi.Request) -> str | None:
    # Traefik strips untrusted X-Forwarded-For, so the first hop is the caller unless Traefik was bypassed.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


class WideEventMiddleware:
    """Emit one wide event per HTTP request and stamp correlation headers.

    Each request runs inside a fresh log scope holding its ``request_id``,
    so every record logged while it runs carries the id,
    and fields bound with :func:`cr_service.context.bind` (such as the caller) land on the wide event.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI entry-point: wraps the downstream app to time and log the request."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = fastapi.Request(scope, receive=receive)
        request_id = _resolve_request_id(request)
        request.state.request_id = request_id
        sentry_sdk.set_tag("request_id", request_id)
        set_span_attributes(request_id=request_id)

        with context.log_scope(request_id=request_id):
            await self._run(request, request_id, scope, receive, send)

    async def _run(
        self, request: fastapi.Request, request_id: str, scope: Scope, receive: Receive, send: Send
    ) -> None:
        start = time.perf_counter()
        status_code: int | None = None
        response_bytes = 0

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, response_bytes
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode()))
                headers.append((b"x-process-time", f"{time.perf_counter() - start:.6f}".encode()))
                message["headers"] = headers
            elif message["type"] == "http.response.body":
                response_bytes += len(message.get("body", b""))
            await send(message)

        error_type: str | None = None
        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:
            error_type = type(exc).__name__
            if status_code is None:
                status_code = 500
            raise
        finally:
            event: dict[str, Any] = {
                **context.get_context(),
                "event": "http_request",
                "method": request.method,
                "path": request.url.path,
                "query": dict(request.query_params),
                "status": status_code,
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                "response_bytes": response_bytes,
                "client_ip": _client_ip(request),
                "user_agent": request.headers.get("user-agent"),
                "referer": request.headers.get("referer"),
                "sentry_trace_id": sentry_sdk.get_current_scope().get_active_propagation_context().trace_id,
                **current_trace_context(),
            }

            if error_type:
                event["error_type"] = error_type
                logger.error("http_request", extra=event)
            elif (
                request.url.path in _PROBE_PATHS
                and status_code is not None
                and status_code < http.HTTPStatus.BAD_REQUEST
            ):
                logger.debug("http_request", extra=event)
            else:
                logger.info("http_request", extra=event)


async def record_validation_errors(request: fastapi.Request, exc: Exception) -> Response:
    """Put a 422's validation errors on the wide event, then answer as FastAPI does."""
    assert isinstance(exc, RequestValidationError)
    context.bind(
        validation_errors=[
            {"loc": list(error.get("loc", ())), "type": error.get("type"), "msg": error.get("msg")}
            for error in exc.errors()
        ]
    )
    return await request_validation_exception_handler(request, exc)


class ForwardedPrefixMiddleware:
    """Use the gateway's ``X-Forwarded-Prefix`` as the ASGI ``root_path``.

    One pod can serve its own hostname and a path on a shared gateway that strips the prefix,
    so a fixed ``API_ROOT_PATH`` cannot fit both and ``/docs`` would fetch the wrong schema.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Set ``root_path`` from the header when it holds an absolute prefix."""
        if scope["type"] == "http":
            for name, value in scope["headers"]:
                if name == b"x-forwarded-prefix":
                    prefix = value.decode("latin-1").rstrip("/")
                    if prefix.startswith("/"):
                        scope = {**scope, "root_path": prefix}
                    break
        await self.app(scope, receive, send)
