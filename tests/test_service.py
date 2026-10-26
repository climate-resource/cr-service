import asyncio
import threading

import anyio.to_thread
import fastapi
import httpx
from fastapi.testclient import TestClient

from cr_service import ServiceSettings, setup, tracing
from cr_service.sentry import init_sentry
from tests.conftest import SERVICE, build_app, make_settings


def test_health_probes():
    client = TestClient(build_app(make_settings()))
    assert client.get("/livez").json() == {"status": "alive"}
    assert client.get("/readyz").json() == {"status": "ready"}


def test_readiness_checks():
    async def database() -> bool:
        return False

    def cache() -> bool:
        raise RuntimeError("cache down")

    app = fastapi.FastAPI()
    app.state.readiness_checks = [lambda: True]
    setup(app, service=SERVICE, settings=make_settings(), readiness_checks=[database, cache])
    response = TestClient(app).get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"detail": {"database": "check returned a falsy result", "cache": "cache down"}}


async def test_probes_answer_while_request_threads_are_busy():
    # Every request thread is held by a slow sync route, as under load on a cold service.
    release = threading.Event()
    app = fastapi.FastAPI()

    @app.get("/slow")
    def slow() -> None:
        release.wait(5)

    def off_event_loop() -> bool:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return True
        return False

    setup(app, service=SERVICE, settings=make_settings(), readiness_checks=[off_event_loop])
    limiter = anyio.to_thread.current_default_thread_limiter()
    original_tokens = limiter.total_tokens
    limiter.total_tokens = 1
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            slow_request = asyncio.create_task(client.get("/slow"))
            while limiter.borrowed_tokens < 1:
                await asyncio.sleep(0.01)
            with anyio.fail_after(1):
                assert (await client.get("/livez")).json() == {"status": "alive"}
                assert (await client.get("/readyz")).json() == {"status": "ready"}
            release.set()
            await slow_request
    finally:
        release.set()
        limiter.total_tokens = original_tokens


def test_metrics():
    client = TestClient(build_app(make_settings()))
    client.get("/livez")
    assert "http_requests_total" in client.get("/metrics").text


def test_auth_off():
    app = build_app(make_settings(workos_client_id=None), auth=None)
    assert not hasattr(app.state, "cr_service_auth")


def test_sentry(monkeypatch):
    calls = []
    monkeypatch.setattr("sentry_sdk.init", lambda **kwargs: calls.append(kwargs))
    assert not init_sentry(ServiceSettings(_env_file=None), SERVICE)

    settings = ServiceSettings(_env_file=None, sentry_dsn="https://key@sentry.example.com/1")
    assert init_sentry(settings, SERVICE, before_send=None)
    assert calls[-1]["release"] == "test-service@1.2.3"
    assert calls[-1]["send_default_pii"] is False
    assert calls[-1]["before_send"] is None

    monkeypatch.setenv("SENTRY_RELEASE", "abc123")
    init_sentry(settings, SERVICE)
    assert calls[-1]["release"] == "abc123"


def test_tracing_needs_endpoint(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
    monkeypatch.setattr(tracing, "_provider_installed", True)
    app = build_app(make_settings())
    assert TestClient(app).get("/livez").status_code == 200
