import json
import logging
import sys

import pytest

from cr_service import bind, get_context, log_scope, unbind
from cr_service.logging_config import (
    JsonFormatter,
    TextFormatter,
    build_env_context,
    configure_logging,
    merge_request_context,
)
from tests.conftest import SERVICE, make_settings


def make_record(**extra) -> logging.LogRecord:
    record = logging.LogRecord("svc", logging.INFO, __file__, 1, "hello %s", ("world",), None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


@pytest.fixture(autouse=True)
def env_context():
    configure_logging(SERVICE, make_settings(environment="staging"))


def test_json_merges_service_request_and_extra():
    with log_scope(request_id="req-1", user_id="user_1"):
        payload = json.loads(JsonFormatter().format(make_record(user_id="override", count=3)))
    assert payload["message"] == "hello world"
    assert payload["level"] == "info"
    assert payload["service"] == "test-service"
    assert payload["version"] == "1.2.3"
    assert payload["env"] == "staging"
    assert payload["request_id"] == "req-1"
    assert payload["user_id"] == "override"
    assert payload["count"] == 3


def test_json_exception():
    record = make_record()
    try:
        int("boom")
    except ValueError:
        record.exc_info = sys.exc_info()
    assert "ValueError: invalid literal" in json.loads(JsonFormatter().format(record))["exc"]


def test_text_format():
    with log_scope(request_id="req-1"):
        line = TextFormatter().format(make_record())
    assert "hello world | request_id='req-1'" in line


def test_bind_outside_scope_is_ignored():
    bind(user_id="nobody")
    assert get_context() == {}


def test_scope_nesting_and_unbind():
    with log_scope(a=1):
        bind(b=2)
        with log_scope(c=3):
            assert get_context() == {"c": 3}
        unbind("a", "missing")
        assert get_context() == {"b": 2}


def test_structlog_processor():
    with log_scope(request_id="req-1", user_id="user_1"):
        event = merge_request_context(None, "info", {"event": "x", "user_id": "kept"})
    assert event == {"event": "x", "request_id": "req-1", "user_id": "kept"}


def test_env_context(monkeypatch):
    monkeypatch.setenv("GIT_COMMIT", "abc123")
    monkeypatch.setenv("HOSTNAME", "pod-1")
    assert build_env_context(SERVICE, "preview") == {
        "service": "test-service",
        "version": "1.2.3",
        "commit": "abc123",
        "env": "preview",
        "instance_id": "pod-1",
    }


def test_configure_logging_is_idempotent_and_keeps_foreign_handlers(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("LOG_FORMAT", "text")
    root = logging.getLogger()
    saved = root.handlers[:]
    foreign = logging.NullHandler()
    root.addHandler(foreign)
    try:
        configure_logging(SERVICE)
        configure_logging(SERVICE)
        ours = [h for h in root.handlers if isinstance(h.formatter, JsonFormatter | TextFormatter)]
        assert len(ours) == 1
        assert isinstance(ours[0].formatter, TextFormatter)
        assert foreign in root.handlers
        assert root.level == logging.DEBUG
        assert logging.getLogger("uvicorn.access").propagate is False
    finally:
        root.handlers = saved
        root.setLevel(logging.WARNING)
