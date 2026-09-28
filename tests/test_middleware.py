import logging

import fastapi
import pydantic
import pytest
from fastapi.testclient import TestClient

from cr_service import bind
from tests.conftest import build_app, make_settings


@pytest.fixture
def app():
    app = build_app(make_settings(), auth=None)

    @app.get("/hello")
    def hello() -> dict[str, str]:
        logging.getLogger("svc").info("inside")
        bind(thing_id="t1")
        return {"hello": "world"}

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("boom")

    class Body(pydantic.BaseModel):
        count: int

    @app.post("/items")
    def items(body: Body) -> Body:
        return body

    @app.get("/root")
    def root(request: fastapi.Request) -> dict[str, str]:
        return {"root_path": request.scope.get("root_path", "")}

    return app


def test_correlation_headers(app):
    response = TestClient(app).get("/hello")
    assert len(response.headers["x-request-id"]) == 32
    assert float(response.headers["x-process-time"]) >= 0


def test_reuses_upstream_request_id(app):
    response = TestClient(app).get("/hello", headers={"x-request-id": "upstream"})
    assert response.headers["x-request-id"] == "upstream"


def test_wide_event(app, access_records, caplog):
    TestClient(app).get(
        "/hello?x=1", headers={"x-request-id": "req-1", "x-forwarded-for": "1.2.3.4, 10.0.0.1"}
    )
    event = access_records()[-1]
    assert event.msg == "http_request"
    assert event.request_id == "req-1"
    assert event.method == "GET"
    assert event.path == "/hello"
    assert event.query == {"x": "1"}
    assert event.status == 200
    assert event.client_ip == "1.2.3.4"
    assert event.thing_id == "t1"
    inside = next(record for record in caplog.records if record.msg == "inside")
    assert inside.name == "svc"


def test_validation_errors_on_wide_event(app, access_records):
    response = TestClient(app).post("/items", json={"count": "many"})
    assert response.status_code == 422
    event = access_records()[-1]
    assert event.validation_errors == [
        {"loc": ["body", "count"], "type": "int_parsing", "msg": response.json()["detail"][0]["msg"]}
    ]


def test_unhandled_error(app, access_records):
    response = TestClient(app, raise_server_exceptions=False).get("/boom")
    assert response.status_code == 500
    event = access_records()[-1]
    assert event.levelno == logging.ERROR
    assert event.error_type == "RuntimeError"
    assert event.status == 500


def test_probes_log_at_debug(app, access_records):
    TestClient(app).get("/livez")
    assert access_records()[-1].levelno == logging.DEBUG


def test_forwarded_prefix(app):
    client = TestClient(app)
    assert client.get("/root", headers={"x-forwarded-prefix": "/svc/"}).json() == {"root_path": "/svc"}
    assert client.get("/root", headers={"x-forwarded-prefix": "svc"}).json() == {"root_path": ""}
