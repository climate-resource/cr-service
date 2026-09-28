"""Request-scoped log context.

Fields bound here are merged into every log line emitted while the request runs,
and into the wide event emitted when it finishes.
The middleware opens a fresh scope per request,
and anything else (a job runner, a CLI command) can open its own with :func:`log_scope`.
"""

import contextlib
import contextvars
from collections.abc import Iterator
from typing import Any

# A mutable dict rather than a value per field,
# so a bind from a sync dependency running in the threadpool is visible to the middleware.
_context: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "cr_service_log_context", default=None
)


def bind(**fields: Any) -> None:
    """Add fields to the current scope, doing nothing outside one."""
    context = _context.get()
    if context is not None:
        context.update(fields)


def unbind(*names: str) -> None:
    """Remove fields from the current scope."""
    context = _context.get()
    if context is not None:
        for name in names:
            context.pop(name, None)


def get_context() -> dict[str, Any]:
    """Return a snapshot of the fields bound in the current scope."""
    context = _context.get()
    return dict(context) if context is not None else {}


@contextlib.contextmanager
def log_scope(**fields: Any) -> Iterator[None]:
    """Open a fresh scope, starting from ``fields``, for the duration of the block."""
    token = _context.set(dict(fields))
    try:
        yield
    finally:
        _context.reset(token)
