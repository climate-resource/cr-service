import pytest

from cr_service.tracing import current_trace_context, instrument_sqlalchemy, set_span_attributes

sdk_trace = pytest.importorskip("opentelemetry.sdk.trace")


def test_trace_context_and_attributes():
    tracer = sdk_trace.TracerProvider().get_tracer("test")
    assert current_trace_context() == {}
    with tracer.start_as_current_span("span") as span:
        set_span_attributes(request_id="req-1", dropped={"a": 1})
        context = current_trace_context()
        assert context["trace_id"] == format(span.get_span_context().trace_id, "032x")
        assert span.attributes == {"request_id": "req-1"}


def test_sqlalchemy_is_a_noop_without_endpoint():
    instrument_sqlalchemy(object())


def test_sqlalchemy_warns_without_instrumentation(monkeypatch, caplog):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    instrument_sqlalchemy(object())
    assert "not installed" in caplog.text or "opentelemetry-instrumentation-sqlalchemy" in caplog.text
