"""One call to wire the shared observability and auth into a FastAPI app."""

import typing
from collections.abc import Awaitable, Callable, Iterable, Mapping

import fastapi
from fastapi.exceptions import RequestValidationError

from cr_service import metrics, tracing
from cr_service.auth.dependencies import AuthConfig, install_auth
from cr_service.health import router as health_router
from cr_service.info import ServiceInfo
from cr_service.logging_config import configure_logging
from cr_service.middleware import ForwardedPrefixMiddleware, WideEventMiddleware, record_validation_errors
from cr_service.profiling import RouteTagMiddleware, start_profiler
from cr_service.sentry import init_sentry
from cr_service.settings import ServiceSettings

ReadinessCheck = Callable[[], object | Awaitable[object]]


def setup(  # noqa: PLR0913
    app: fastapi.FastAPI,
    *,
    service: ServiceInfo,
    settings: ServiceSettings,
    auth: AuthConfig | None = AuthConfig(),
    readiness_checks: Iterable[ReadinessCheck] = (),
    sentry_options: Mapping[str, typing.Any] | None = None,
    redact_paths: Iterable[str] = (),
) -> None:
    """Install logging, Sentry, profiling, the wide event, health probes, metrics, tracing and auth.

    Call it after adding the service's own middleware, such as CORS,
    so the wide event and the trace wrap them.
    Pass ``auth=None`` for a service with no authenticated routes.
    ``redact_paths`` are logged without their query or referer, for routes such as OAuth callbacks.
    """
    configure_logging(service, settings)
    init_sentry(settings, service, **(sentry_options or {}))
    start_profiler(service, settings.environment)

    checks = getattr(app.state, "readiness_checks", None) or []
    app.state.readiness_checks = [*checks, *readiness_checks]
    app.add_exception_handler(RequestValidationError, record_validation_errors)

    app.add_middleware(WideEventMiddleware, redact_paths=redact_paths)
    app.add_middleware(RouteTagMiddleware)
    app.add_middleware(ForwardedPrefixMiddleware)

    app.include_router(health_router)
    metrics.instrument_app(app)
    tracing.instrument_app(app, service)

    if auth is not None:
        install_auth(app, settings, auth)
