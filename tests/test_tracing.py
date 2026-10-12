import json
import logging
import sys

import pytest
import sqlalchemy
from fastapi.testclient import TestClient
from opentelemetry import trace
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk import trace as sdk_trace
from opentelemetry.sdk.trace import export
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from sqlalchemy.ext.asyncio import create_async_engine

from cr_service import tracing
from cr_service.logging_config import JsonFormatter
from cr_service.tracing import current_trace_context, instrument_sqlalchemy, set_span_attributes
from tests.conftest import build_app, make_settings


def test_trace_context_and_attributes():
    tracer = sdk_trace.TracerProvider().get_tracer("test")
    assert current_trace_context() == {}
    with tracer.start_as_current_span("span") as span:
        set_span_attributes(request_id="req-1", dropped={"a": 1})
        context = current_trace_context()
        assert context["trace_id"] == trace.format_trace_id(span.get_span_context().trace_id)
        assert span.attributes == {"request_id": "req-1"}


def test_sqlalchemy_is_a_noop_without_endpoint():
    instrument_sqlalchemy(object())


def test_sqlalchemy_warns_without_instrumentation(monkeypatch, caplog):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    monkeypatch.setitem(sys.modules, "opentelemetry.instrumentation.sqlalchemy", None)
    instrument_sqlalchemy(object())
    assert "opentelemetry-instrumentation-sqlalchemy is not" in caplog.text


@pytest.fixture
def spans(monkeypatch):
    """Export the spans of the provider ``install_provider`` builds to memory."""
    exporter = InMemorySpanExporter()
    installed = []
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    monkeypatch.setattr(tracing, "_provider_installed", False)
    monkeypatch.setattr(export, "BatchSpanProcessor", lambda _: export.SimpleSpanProcessor(exporter))
    monkeypatch.setattr(trace, "set_tracer_provider", installed.append)
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: installed[-1])
    return exporter


def test_native_request_spans_skip_probes(spans, access_records):
    app = build_app(make_settings(), auth=None)

    @app.get("/items/{item_id}")
    def item(item_id: int) -> dict[str, int]:
        return {"item_id": item_id}

    client = TestClient(app)
    client.get("/items/3")
    for probe in ("/livez", "/readyz", "/metrics"):
        client.get(probe)

    finished = spans.get_finished_spans()
    assert {span.instrumentation_scope.name for span in finished} == {"fastapi"}
    (request,) = [span for span in finished if span.parent is None]
    assert request.name == "GET /items/{item_id}"
    event = next(record for record in access_records() if record.path == "/items/3")
    assert event.trace_id == trace.format_trace_id(request.context.trace_id)


@pytest.mark.parametrize("probe", ["/livez", "/readyz", "/metrics"])
def test_probes_stay_untraced_under_a_sampled_parent(spans, probe):
    upstream_trace_id = "0af7651916cd43dd8448eb211c80319c"
    headers = {"traceparent": f"00-{upstream_trace_id}-b7ad6b7169203331-01"}
    client = TestClient(build_app(make_settings(), auth=None))

    client.get(probe, headers=headers)
    assert spans.get_finished_spans() == ()

    client.get("/missing", headers=headers)
    assert {trace.format_trace_id(span.context.trace_id) for span in spans.get_finished_spans()} == {
        upstream_trace_id
    }


def span_named(spans, name):
    (span,) = [span for span in spans.get_finished_spans() if span.name == name]
    return span


def test_app_logs_point_at_the_endpoint_span(spans):
    app = build_app(make_settings(), auth=None)
    lines = []

    @app.get("/work")
    def work() -> dict[str, str]:
        lines.append(json.loads(JsonFormatter().format(logging.makeLogRecord({"msg": "working"}))))
        return {}

    TestClient(app).get("/work")

    endpoint = span_named(spans, "fastapi.endpoint")
    assert lines[0]["trace_id"] == trace.format_trace_id(endpoint.context.trace_id)
    assert lines[0]["span_id"] == trace.format_span_id(endpoint.context.span_id)


def assert_query_under_endpoint(spans):
    query = span_named(spans, "select")
    assert query.parent.span_id == span_named(spans, "fastapi.endpoint").context.span_id
    assert query.attributes["db.statement"].startswith("select 1")


@pytest.fixture
def uninstrument_sqlalchemy():
    yield
    SQLAlchemyInstrumentor().uninstrument()


def test_sqlalchemy_spans_nest_under_the_endpoint(spans, uninstrument_sqlalchemy):
    app = build_app(make_settings(), auth=None)
    engine = sqlalchemy.create_engine("sqlite://")
    instrument_sqlalchemy(engine)

    @app.get("/rows")
    def rows() -> dict[str, int]:
        with engine.connect() as connection:
            return {"value": connection.execute(sqlalchemy.text("select 1")).scalar_one()}

    assert TestClient(app).get("/rows").json() == {"value": 1}

    assert_query_under_endpoint(spans)


async def test_async_sqlalchemy_spans_nest_under_the_endpoint(spans, uninstrument_sqlalchemy):
    app = build_app(make_settings(), auth=None)
    engine = create_async_engine("sqlite+aiosqlite://")
    instrument_sqlalchemy(engine.sync_engine)

    @app.get("/rows")
    async def rows() -> dict[str, int]:
        async with engine.connect() as connection:
            return {"value": (await connection.execute(sqlalchemy.text("select 1"))).scalar_one()}

    assert TestClient(app).get("/rows").json() == {"value": 1}
    await engine.dispose()

    assert_query_under_endpoint(spans)
