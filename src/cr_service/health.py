"""Liveness and readiness probes."""

import inspect
import logging

import anyio
import anyio.to_thread
import fastapi

logger = logging.getLogger(__name__)

router = fastapi.APIRouter(include_in_schema=False)

# Kept out of traces, metrics and the info-level access log so they do not drown out real traffic.
PROBE_PATHS = ("/livez", "/readyz", "/metrics")

# Sync readiness checks run on their own threads, not the request thread pool,
# so a pool saturated by slow requests can't make the pod look unready.
_readiness_check_limiter = anyio.CapacityLimiter(4)


# `async`, so it answers on the event loop instead of waiting for a free thread behind slow sync routes.
@router.get("/livez")
async def liveness_probe() -> dict[str, str]:
    """Report process liveness without touching any dependency."""
    return {"status": "alive"}


@router.get("/readyz")
async def readiness_probe(request: fastapi.Request) -> dict[str, str]:
    """Report readiness by running the checks registered on ``app.state.readiness_checks``.

    Each check is a callable that returns a falsy value or raises to signal it is not ready.
    A check may be async, in which case what it returns is awaited.
    A sync check runs in a worker thread, so a slow one doesn't block the event loop.
    An empty (or unset) check list means the service is always ready.
    """
    checks = getattr(request.app.state, "readiness_checks", [])
    failures: dict[str, str] = {}
    for check in checks:
        name = getattr(check, "__name__", repr(check))
        try:
            if inspect.iscoroutinefunction(check):
                ok = await check()
            else:
                ok = await anyio.to_thread.run_sync(check, limiter=_readiness_check_limiter)
            if inspect.isawaitable(ok):
                ok = await ok
        except Exception as exc:
            logger.warning("Readiness check %s failed", name, exc_info=True)
            failures[name] = str(exc)
            continue
        if not ok:
            failures[name] = "check returned a falsy result"

    if failures:
        raise fastapi.HTTPException(status_code=503, detail=failures)
    return {"status": "ready"}
