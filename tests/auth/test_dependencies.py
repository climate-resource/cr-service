import typing

import fastapi
import pytest
from fastapi.testclient import TestClient

from cr_service import AuthConfig, setup
from cr_service.auth import (
    CurrentPrincipal,
    OptionalPrincipal,
    Principal,
    require_feature_flag,
    require_permission,
)
from tests.conftest import SERVICE, build_app, make_settings


def add_routes(app: fastapi.FastAPI) -> fastapi.FastAPI:
    @app.get("/me")
    def me(principal: CurrentPrincipal) -> dict[str, typing.Any]:
        return {"id": principal.id, "kind": principal.kind}

    @app.get("/maybe")
    async def maybe(principal: OptionalPrincipal) -> dict[str, str | None]:
        return {"id": principal.id if principal else None}

    @app.post("/things", dependencies=[fastapi.Depends(require_permission("things:write"))])
    def write() -> dict[str, bool]:
        return {"ok": True}

    @app.get("/flagged")
    def flagged(
        principal: typing.Annotated[Principal, fastapi.Depends(require_feature_flag("app:things"))],
    ) -> dict[str, str]:
        return {"id": principal.id}

    return app


@pytest.fixture
def client(settings, tokens):
    return TestClient(add_routes(build_app(settings, tokens)))


def test_valid_token(client, tokens):
    response = client.get("/me", headers=tokens.headers(user_id="user_1"))
    assert response.status_code == 200
    assert response.json() == {"id": "user_1", "kind": "user"}


def test_missing_token(client):
    response = client.get("/me")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_invalid_token(client, tokens):
    response = client.get("/me", headers=tokens.headers(tokens.user_token(expires_in=-60)))
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'
    assert response.json() == {"detail": "Access token has expired"}


def test_optional_principal(client, tokens):
    assert client.get("/maybe").json() == {"id": None}
    assert client.get("/maybe", headers=tokens.headers(user_id="user_1")).json() == {"id": "user_1"}
    assert client.get("/maybe", headers=tokens.headers("junk")).status_code == 401


def test_require_permission(client, tokens):
    assert client.post("/things", headers=tokens.headers()).status_code == 403
    response = client.post("/things", headers=tokens.headers(permissions=["things:write"]))
    assert response.status_code == 200


def test_require_feature_flag(client, tokens):
    assert client.get("/flagged", headers=tokens.headers()).status_code == 403
    assert client.get("/flagged", headers=tokens.headers(feature_flags=["app:things"])).status_code == 200


def test_security_scheme_in_openapi(client):
    schema = client.get("/openapi.json").json()
    assert schema["components"]["securitySchemes"]["WorkOS"] == {
        "type": "http",
        "scheme": "bearer",
        "description": "WorkOS access token",
    }


def test_resource_metadata_hint(tokens):
    settings = make_settings()
    app = add_routes(
        build_app(settings, tokens, auth=AuthConfig(resource_metadata_url="https://svc/.well-known/prm"))
    )
    response = TestClient(app).get("/me", headers=tokens.headers("junk"))
    assert response.headers["www-authenticate"] == (
        'Bearer error="invalid_token", resource_metadata="https://svc/.well-known/prm"'
    )


def test_shadow_mode_lets_failures_through(tokens, caplog):
    settings = make_settings(environment="staging", auth_enforce=False)
    client = TestClient(add_routes(build_app(settings, tokens)))
    assert client.get("/me").json() == {"id": "anonymous", "kind": "anonymous"}
    assert client.post("/things", headers=tokens.headers()).status_code == 200
    assert client.get("/maybe", headers=tokens.headers("junk")).json() == {"id": None}
    assert [record.auth_error for record in caplog.records if record.msg == "auth_failed"] == [
        "AuthenticationError",
        "AuthorizationError",
        "AuthenticationError",
    ]


def test_local_provider():
    settings = make_settings(auth_provider="local", auth_local_permissions=("things:write",))
    client = TestClient(add_routes(build_app(settings)))
    assert client.get("/me").json() == {"id": "user_local", "kind": "local"}
    assert client.post("/things").status_code == 200


def test_hooks_run(settings, tokens):
    seen: list[tuple[str, str]] = []
    auth = AuthConfig(
        on_success=[lambda request, principal: seen.append(("ok", principal.id))],
        on_failure=[lambda request, error: seen.append(("fail", type(error).__name__))],
    )
    client = TestClient(add_routes(build_app(settings, tokens, auth=auth)))
    client.get("/me", headers=tokens.headers(user_id="user_1"))
    client.get("/me")
    assert seen == [("ok", "user_1"), ("fail", "AuthenticationError")]


def test_authenticates_once_per_request(settings, tokens):
    calls = []
    auth = AuthConfig(on_success=[lambda request, principal: calls.append(principal.id)])
    app = build_app(settings, tokens, auth=auth)

    @app.get("/both")
    def both(first: CurrentPrincipal, second: OptionalPrincipal) -> None:
        assert first is second

    TestClient(app).get("/both", headers=tokens.headers())
    assert calls == ["user_test"]


def test_principal_on_wide_event(client, tokens, access_records):
    client.get("/me", headers=tokens.headers(user_id="user_1", organization_id="org_1"))
    event = access_records()[-1]
    assert event.user_id == "user_1"
    assert event.organization_id == "org_1"
    assert event.auth_kind == "user"
    assert event.auth_outcome == "pass"
    assert not hasattr(event, "email")


def test_failure_on_wide_event(client, access_records):
    client.get("/me")
    event = access_records()[-1]
    assert event.auth_outcome == "fail"
    assert event.auth_error == "AuthenticationError"


def test_sentry_user(client, tokens, monkeypatch):
    calls = {}
    monkeypatch.setattr("sentry_sdk.set_user", lambda user: calls.setdefault("user", user))
    monkeypatch.setattr("sentry_sdk.set_tag", calls.setdefault)
    client.get("/me", headers=tokens.headers(user_id="user_1", organization_id="org_1"))
    assert calls["user"] == {"id": "user_1"}
    assert calls["organization_id"] == "org_1"


def test_not_installed():
    app = add_routes(fastapi.FastAPI())
    with pytest.raises(RuntimeError, match="not installed"):
        TestClient(app).get("/me")


def test_token_factory_install_keeps_hooks(settings, tokens):
    seen = []
    app = add_routes(fastapi.FastAPI())
    setup(
        app, service=SERVICE, settings=settings, auth=AuthConfig(on_success=[lambda r, p: seen.append(p.id)])
    )
    tokens.install(app, settings)
    assert TestClient(app).get("/me", headers=tokens.headers()).status_code == 200
    assert seen == ["user_test"]


def test_token_factory_install(settings, tokens):
    app = add_routes(fastapi.FastAPI())
    tokens.install(app, settings)
    assert TestClient(app).get("/me", headers=tokens.headers()).status_code == 200
