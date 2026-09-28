"""Structured JSON logging.

Installs a single formatter on the root logger so every record is one parseable line,
and silences uvicorn's plaintext access log in favour of the wide-event middleware.
``LOG_FORMAT=text`` switches to a human-readable line for local development.

Services with their own logging stack can skip :func:`configure_logging`
and still pick up the request context through :func:`merge_request_context`.
"""

import json
import logging
import os
import sys
import time
from collections.abc import MutableMapping
from typing import Any

from cr_service import redact
from cr_service.context import get_context
from cr_service.info import ServiceInfo
from cr_service.settings import ServiceSettings

_ENV_CONTEXT: dict[str, Any] = {}

_RESERVED_LOG_RECORD_KEYS = frozenset(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}


def build_env_context(service: ServiceInfo, environment: str) -> dict[str, Any]:
    """Return the static fields stamped on every log line."""
    fields = {
        "service": service.name,
        "version": service.version,
        "commit": os.environ.get("GIT_COMMIT") or os.environ.get("IMAGE_TAG") or None,
        "env": environment,
        "instance_id": os.environ.get("HOSTNAME"),
    }
    return {key: value for key, value in fields.items() if value is not None}


def _record_fields(record: logging.LogRecord) -> dict[str, Any]:
    """Merge the request context with the record's ``extra``, which wins on a clash."""
    fields = get_context()
    for key, value in record.__dict__.items():
        if key in _RESERVED_LOG_RECORD_KEYS or key.startswith("_"):
            continue
        fields[key] = value
    return redact.redact_fields(fields)


class JsonFormatter(logging.Formatter):
    """Single-line JSON formatter that flattens ``extra`` and merges the service and request context."""

    def format(self, record: logging.LogRecord) -> str:
        """Render the record as a single-line JSON object."""
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update(_ENV_CONTEXT)
        payload.update(_record_fields(record))
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


class TextFormatter(logging.Formatter):
    """Human-readable formatter that appends the structured fields as ``key=value`` pairs."""

    def __init__(self) -> None:
        super().__init__(fmt="%(asctime)s %(levelname)-5s %(name)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        """Render the record as ``<ts> <level> <logger> <message> | k=v ...``."""
        base = super().format(record)
        extras = [f"{key}={value!r}" for key, value in _record_fields(record).items()]
        if extras:
            base = f"{base} | {' '.join(extras)}"
        return base


def merge_request_context(
    _logger: Any, _method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Structlog processor that adds the request context, for services that log through structlog."""
    for key, value in redact.redact_fields(get_context()).items():
        event_dict.setdefault(key, value)
    return event_dict


def configure_logging(service: ServiceInfo, settings: ServiceSettings | None = None) -> None:
    """Install structured logging on the root logger and silence uvicorn's access log.

    Idempotent, and meant to be called twice: once at import so startup is captured,
    and again by :func:`cr_service.setup`, because uvicorn applies its own config in between.
    Without ``settings`` it reads ``LOG_LEVEL``, ``LOG_FORMAT`` and ``ENVIRONMENT`` itself.
    Handlers installed by anything else, such as pytest, are left alone.
    """
    settings = settings or ServiceSettings()
    redact.configure(settings.log_redact_keys)
    _ENV_CONTEXT.clear()
    _ENV_CONTEXT.update(build_env_context(service, settings.environment))

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(TextFormatter() if settings.log_format == "text" else JsonFormatter())

    root = logging.getLogger()
    root.handlers = [h for h in root.handlers if not isinstance(h.formatter, JsonFormatter | TextFormatter)]
    root.addHandler(handler)
    root.setLevel(settings.log_level)

    access = logging.getLogger("uvicorn.access")
    access.handlers = []
    access.propagate = False

    for name in ("uvicorn", "uvicorn.error", "fastapi"):
        log = logging.getLogger(name)
        log.handlers = []
        log.propagate = True
