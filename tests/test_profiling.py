import contextlib
import sys
import types

import pytest
from fastapi.testclient import TestClient

from cr_service import profiling
from tests.conftest import SERVICE, build_app, make_settings


@pytest.fixture
def fake_pyroscope(monkeypatch):
    calls: dict[str, list] = {"configure": [], "tags": []}

    @contextlib.contextmanager
    def tag_wrapper(tags):
        calls["tags"].append(tags)
        yield

    module = types.SimpleNamespace(
        configure=lambda **kwargs: calls["configure"].append(kwargs), tag_wrapper=tag_wrapper
    )
    monkeypatch.setitem(sys.modules, "pyroscope", module)
    monkeypatch.setattr(profiling, "_started", False)
    return calls


def test_off_without_server(fake_pyroscope):
    profiling.start_profiler(SERVICE, "local")
    assert fake_pyroscope["configure"] == []


def test_tags_routes(fake_pyroscope, monkeypatch):
    monkeypatch.setenv("PYROSCOPE_SERVER_ADDRESS", "http://pyroscope:4040")
    app = build_app(make_settings(), auth=None)

    @app.get("/things/{thing_id}")
    def thing(thing_id: str) -> None:
        return None

    TestClient(app).get("/things/1")
    assert fake_pyroscope["configure"][0]["application_name"] == "test-service"
    assert {"endpoint": "/things/{thing_id}", "method": "GET"} in fake_pyroscope["tags"]
