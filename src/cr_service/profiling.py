"""Continuous profiling with Pyroscope, on once ``PYROSCOPE_SERVER_ADDRESS`` is set.

The profiler lives in the optional ``profiling`` extra, so this degrades to a no-op when it is missing.
"""

import logging
import os
import typing

from starlette.routing import Match
from starlette.types import ASGIApp, Receive, Scope, Send

from cr_service.info import ServiceInfo
from cr_service.logging_config import build_env_context

logger = logging.getLogger(__name__)

_started = False


def profiling_enabled() -> bool:
    """Profiling is opt-in through the server address, so local runs stay quiet."""
    return bool(os.environ.get("PYROSCOPE_SERVER_ADDRESS"))


def start_profiler(service: ServiceInfo, environment: str) -> None:
    """Start pushing CPU profiles to Pyroscope, tagged with the same fields as the wide events."""
    global _started  # noqa: PLW0603
    if _started or not profiling_enabled():
        return

    try:
        import pyroscope  # noqa: PLC0415
    except ImportError:
        logger.warning("PYROSCOPE_SERVER_ADDRESS is set but the profiling extra is not installed")
        return

    tags = {key: str(value) for key, value in build_env_context(service, environment).items()}
    pyroscope.configure(
        application_name=tags.pop("service"),
        server_address=os.environ["PYROSCOPE_SERVER_ADDRESS"],
        tags=tags,
    )
    _started = True


def _route_template(scope: Scope) -> str:
    """Return the matched route pattern, so tag values stay bounded regardless of path parameters."""
    for route in scope["app"].router.routes:
        match, _ = route.matches(scope)
        if match == Match.FULL:
            return typing.cast(str, getattr(route, "path_format", "unmatched"))
    return "unmatched"


class RouteTagMiddleware:
    """Tag profile samples with the route and method while a request runs.

    Tags are per thread, so under concurrent async requests the attribution is approximate.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Run the request under its endpoint and method tags."""
        if scope["type"] != "http" or not _started:
            await self.app(scope, receive, send)
            return

        import pyroscope  # noqa: PLC0415

        with pyroscope.tag_wrapper({"endpoint": _route_template(scope), "method": scope["method"]}):
            await self.app(scope, receive, send)
