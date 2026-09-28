"""OpenTelemetry tracing, on once ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set.

The tracing dependencies live in the optional ``tracing`` extra,
so every helper here degrades to a no-op when they are missing.
"""

import logging
import os
import types
from typing import Any

import fastapi

from cr_service.info import ServiceInfo

trace: types.ModuleType | None
try:
    from opentelemetry import trace
except ImportError:  # the optional tracing extra is not installed
    trace = None

logger = logging.getLogger(__name__)

_SPAN_ATTRIBUTE_TYPES = (str, bool, int, float)
_provider_installed = False


def tracing_enabled() -> bool:
    """Tracing is opt-in through the OTLP endpoint, so local runs stay quiet."""
    return bool(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"))


def instrument_app(app: fastapi.FastAPI, service: ServiceInfo) -> None:
    """Install the tracer provider, once per process, and a span per HTTP request."""
    global _provider_installed  # noqa: PLW0603
    if not tracing_enabled():
        return

    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter  # noqa: PLC0415
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # noqa: PLC0415
        from opentelemetry.sdk.resources import Resource  # noqa: PLC0415
        from opentelemetry.sdk.trace import TracerProvider  # noqa: PLC0415
        from opentelemetry.sdk.trace.export import BatchSpanProcessor  # noqa: PLC0415
    except ImportError:
        logger.warning("OTEL_EXPORTER_OTLP_ENDPOINT is set but the tracing extra is not installed")
        return
    assert trace is not None

    if not _provider_installed:
        service_name = os.environ.get("OTEL_SERVICE_NAME", service.name)
        resource = Resource.create({"service.name": service_name, "service.version": service.version})
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
        _provider_installed = True
    # Added last, so the request span is open before the wide-event middleware runs.
    FastAPIInstrumentor.instrument_app(app, excluded_urls="livez,readyz,metrics")


def instrument_sqlalchemy(engine: Any) -> None:
    """Emit a child span for every statement a SQLAlchemy engine runs.

    Takes a sync ``Engine``, so pass ``async_engine.sync_engine`` for an async one.
    Needs ``opentelemetry-instrumentation-sqlalchemy`` installed alongside the ``tracing`` extra.
    """
    if not tracing_enabled():
        return

    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor  # noqa: PLC0415
    except ImportError:
        logger.warning(
            "OTEL_EXPORTER_OTLP_ENDPOINT is set but opentelemetry-instrumentation-sqlalchemy is not"
        )
        return

    SQLAlchemyInstrumentor().instrument(engine=engine, enable_commenter=True)


def current_trace_context() -> dict[str, str]:
    """Return the active ``trace_id`` and ``span_id``, or nothing outside a recorded span."""
    if trace is None:
        return {}
    span_context = trace.get_current_span().get_span_context()
    if not span_context.is_valid:
        return {}
    return {
        "trace_id": trace.format_trace_id(span_context.trace_id),
        "span_id": trace.format_span_id(span_context.span_id),
    }


def set_span_attributes(**attributes: Any) -> None:
    """Stamp attributes on the active span, dropping anything OpenTelemetry cannot carry."""
    if trace is None:
        return
    span = trace.get_current_span()
    if not span.is_recording():
        return
    for key, value in attributes.items():
        if isinstance(value, _SPAN_ATTRIBUTE_TYPES):
            span.set_attribute(key, value)
