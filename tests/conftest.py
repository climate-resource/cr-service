import dataclasses
import logging
import os

import fastapi
import pytest
from fastapi.testclient import TestClient

from cr_service import AuthConfig, ServiceInfo, ServiceSettings, setup
from cr_service.auth import clear_auth_caches
from cr_service.auth.testing import TokenFactory

SERVICE = ServiceInfo(name="test-service", version="1.2.3")

_ENV_PREFIXES = ("AUTH_", "WORKOS_", "SENTRY_", "LOG_", "OTEL_", "PYROSCOPE_")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    """Keep the developer's environment and any .env out of the tests."""
    for name in list(os.environ):
        if name.startswith(_ENV_PREFIXES) or name in {"ENVIRONMENT", "GIT_COMMIT", "IMAGE_TAG"}:
            monkeypatch.delenv(name)
    monkeypatch.chdir(tmp_path)


@pytest.fixture(autouse=True)
def fresh_auth_caches():
    clear_auth_caches()
    yield
    clear_auth_caches()


def make_settings(**overrides) -> ServiceSettings:
    values = {"workos_client_id": "client_service"} | overrides
    return ServiceSettings(_env_file=None, **values)


@pytest.fixture
def settings() -> ServiceSettings:
    return make_settings()


@pytest.fixture
def tokens(settings) -> TokenFactory:
    return TokenFactory.for_settings(settings)


def build_app(
    settings: ServiceSettings,
    tokens: TokenFactory | None = None,
    auth: AuthConfig | None = AuthConfig(),
    **kwargs,
) -> fastapi.FastAPI:
    app = fastapi.FastAPI()
    if auth is not None and tokens is not None:
        auth = dataclasses.replace(auth, authenticator=tokens.authenticator(settings))
    setup(app, service=SERVICE, settings=settings, auth=auth, **kwargs)
    return app


@pytest.fixture
def access_records(caplog):
    caplog.set_level(logging.DEBUG, logger="access")

    def records():
        return [record for record in caplog.records if record.name == "access"]

    return records


@pytest.fixture
def client_for():
    def make(app: fastapi.FastAPI, **kwargs) -> TestClient:
        return TestClient(app, **kwargs)

    return make
