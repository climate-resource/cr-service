import typing

import fastapi
import pytest
from fastapi.testclient import TestClient

from cr_service import AuthConfig, setup
from cr_service.auth import (
    AuthorizationError,
    CurrentPrincipal,
    OptionalPrincipal,
    Principal,
    base_authenticator,
    install_auth,
    require_feature_flag,
    require_permission,
    try_authenticate,
)
from cr_service.auth.authenticator import Authenticator, LocalAuthenticator
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


def test_auth_status_header(client, tokens):
    assert client.get("/me", headers=tokens.headers()).headers["x-auth-status"] == "pass"
    assert client.get("/me").headers["x-auth-status"] == "fail"
    assert client.post("/things", headers=tokens.headers()).headers["x-auth-status"] == "fail"
    assert "x-auth-status" not in client.get("/maybe").headers


def test_try_authenticate(settings, tokens):
    app = build_app(settings, tokens)

    @app.get("/graphql")
    async def graphql(request: fastapi.Request) -> dict[str, str | None]:
        principal = await try_authenticate(request)
        return {"id": principal.id if principal else None}

    client = TestClient(app)
    assert client.get("/graphql", headers=tokens.headers(user_id="user_1")).json() == {"id": "user_1"}
    response = client.get("/graphql", headers=tokens.headers("junk"))
    assert response.status_code == 200
    assert response.json() == {"id": None}
    assert response.headers["x-auth-status"] == "fail"
    response = client.get("/graphql")
    assert response.json() == {"id": None}
    assert "x-auth-status" not in response.headers


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
    assert schema["components"]["securitySchemes"]["HTTPBearer"] == {
        "type": "http",
        "scheme": "bearer",
        "description": "Access token",
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


def test_resource_metadata_hint_from_the_request(tokens):
    def metadata_url(request: fastapi.Request) -> str:
        return f"{request.base_url}.well-known/prm"

    app = add_routes(build_app(make_settings(), tokens, auth=AuthConfig(resource_metadata_url=metadata_url)))
    response = TestClient(app, base_url="https://reached.example").get("/me")
    assert (
        response.headers["www-authenticate"]
        == 'Bearer resource_metadata="https://reached.example/.well-known/prm"'
    )


def test_shadow_mode_lets_unauthenticated_callers_through(tokens, caplog):
    settings = make_settings(environment="staging", auth_enforce=False)
    client = TestClient(add_routes(build_app(settings, tokens)))
    assert any(record.msg.startswith("Auth is in shadow mode") for record in caplog.records)
    response = client.get("/me")
    assert response.json() == {"id": "anonymous", "kind": "anonymous"}
    assert response.headers["x-auth-status"] == "fail"
    assert client.get("/me", headers=tokens.headers("junk")).json()["kind"] == "anonymous"
    assert client.get("/maybe", headers=tokens.headers("junk")).json() == {"id": None}
    assert [record.auth_error for record in caplog.records if record.msg == "auth_failed"] == [
        "AuthenticationError",
        "AuthenticationError",
        "AuthenticationError",
    ]


def test_shadow_mode_still_refuses_unauthorised_callers(tokens, access_records):
    settings = make_settings(environment="staging", auth_enforce=False)
    client = TestClient(add_routes(build_app(settings, tokens)))
    response = client.post("/things")
    assert response.status_code == 403
    assert response.headers["x-auth-status"] == "fail"
    assert access_records()[-1].auth_outcome == "fail"
    assert client.post("/things", headers=tokens.headers()).status_code == 403
    assert client.post("/things", headers=tokens.headers(permissions=["things:write"])).status_code == 200
    assert client.get("/flagged", headers=tokens.headers()).status_code == 403


def test_shadow_mode_still_applies_the_organisation_gate(tokens):
    settings = make_settings(
        environment="staging", auth_enforce=False, workos_allowed_organization_ids=("org_allowed",)
    )
    client = TestClient(add_routes(build_app(settings, tokens)))
    assert client.get("/me", headers=tokens.headers(organization_id="org_other")).status_code == 403
    assert client.get("/maybe", headers=tokens.headers(organization_id="org_other")).status_code == 403
    assert client.get("/me", headers=tokens.headers(organization_id="org_allowed")).status_code == 200


def test_local_provider():
    settings = make_settings(auth_provider="local", auth_local_permissions=("things:write",))
    client = TestClient(add_routes(build_app(settings)))
    response = client.get("/me")
    assert response.json() == {"id": "user_local", "kind": "local"}
    assert response.headers["x-auth-status"] == "skipped"
    assert client.post("/things").status_code == 200


def test_fake_provider():
    settings = make_settings(auth_provider="fake", auth_local_permissions=("things:write",))
    client = TestClient(add_routes(build_app(settings)))
    headers = {"Authorization": "Bearer fake-access-token"}
    assert client.get("/me", headers=headers).json() == {"id": "user_local", "kind": "local"}
    assert client.get("/me", headers=headers).headers["x-auth-status"] == "pass"
    assert client.post("/things", headers=headers).status_code == 200
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers={"Authorization": "Bearer junk"}).status_code == 401


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


def test_install_auth_without_setup(settings, tokens):
    app = add_routes(fastapi.FastAPI())

    @app.get("/outcome")
    def outcome(request: fastapi.Request, principal: CurrentPrincipal) -> dict[str, str]:
        return {"outcome": request.state.auth_outcome}

    install_auth(app, settings, AuthConfig(authenticator=tokens.authenticator(settings)))
    install_auth(app, settings, AuthConfig(authenticator=tokens.authenticator(settings)))
    assert app.user_middleware == []
    client = TestClient(app)
    assert client.get("/me", headers=tokens.headers(user_id="user_1")).json()["id"] == "user_1"
    assert client.get("/outcome", headers=tokens.headers()).json() == {"outcome": "pass"}
    assert client.get("/me").status_code == 401


class AgentAuthenticator:
    """Recognises one opaque agent token, deferring anything else to the app's authenticator."""

    def __init__(self, base: Authenticator, session: list[str], request: fastapi.Request) -> None:
        self.base = base
        self.session = session
        self.request = request

    async def authenticate(self, token: str | None) -> Principal:
        if token == "agent-token":
            self.session.append(f"query {self.request.method} {self.request.url.path}")
            return Principal(kind="agent", id="agent_1", delegated_user_id="user_1", organization_id="org_1")
        return await self.base.authenticate(token)


@pytest.fixture
def events() -> list[str]:
    return []


@pytest.fixture
def dependency_app(settings, tokens, events):
    async def agent_authenticator(
        request: fastapi.Request, base: typing.Annotated[Authenticator, fastapi.Depends(base_authenticator)]
    ) -> typing.AsyncIterator[Authenticator]:
        session = events
        session.append("open")
        yield AgentAuthenticator(base, session, request)
        session.append("close")

    app = add_routes(fastapi.FastAPI())

    @app.get("/both")
    def both(first: CurrentPrincipal, second: OptionalPrincipal) -> dict[str, str | None]:
        assert first is second
        return {"kind": first.kind, "delegated": first.delegated_user_id}

    setup(
        app, service=SERVICE, settings=settings, auth=AuthConfig(authenticator_dependency=agent_authenticator)
    )
    tokens.install(app, settings)
    return app


def test_authenticator_dependency_per_request(dependency_app, tokens, events):
    client = TestClient(dependency_app)
    agent = {"Authorization": "Bearer agent-token"}
    assert client.get("/both", headers=agent).json() == {"kind": "agent", "delegated": "user_1"}
    assert events == ["open", "query GET /both", "close"]
    assert client.get("/me", headers=tokens.headers(user_id="user_2")).json()["id"] == "user_2"
    assert events[3:] == ["open", "close"]


def test_agent_on_wide_event(dependency_app, access_records):
    TestClient(dependency_app).get("/me", headers={"Authorization": "Bearer agent-token"})
    event = access_records()[-1]
    assert event.auth_kind == "agent"
    assert event.user_id == "agent_1"
    assert event.auth_delegated_user_id == "user_1"


def test_authenticator_dependency_override_removed(dependency_app):
    dependency_app.dependency_overrides.clear()
    with pytest.raises(RuntimeError, match="authenticator_dependency"):
        TestClient(dependency_app).get("/me")


def test_install_auth_again_drops_the_dependency(dependency_app, settings, tokens):
    install_auth(dependency_app, settings, AuthConfig(authenticator=tokens.authenticator(settings)))
    assert dependency_app.dependency_overrides == {}
    assert (
        TestClient(dependency_app).get("/me", headers={"Authorization": "Bearer agent-token"}).status_code
        == 401
    )


def test_try_authenticate_with_authenticator_dependency(dependency_app, settings, tokens):
    @dependency_app.get("/graphql")
    async def graphql(request: fastapi.Request) -> dict[str, str | None]:
        principal = await try_authenticate(request, authenticator=tokens.authenticator(settings))
        return {"id": principal.id if principal else None}

    @dependency_app.get("/graphql-unwired")
    async def unwired(request: fastapi.Request) -> None:
        await try_authenticate(request)

    client = TestClient(dependency_app)
    assert client.get("/graphql", headers=tokens.headers(user_id="user_1")).json() == {"id": "user_1"}
    with pytest.raises(RuntimeError, match="needs an authenticator"):
        client.get("/graphql-unwired")


def write_implies_read(principal: Principal, permission: str) -> bool:
    return principal.has_permission(permission) or (
        permission == "things:read" and principal.has_permission("things:write")
    )


def test_has_permission_policy(settings, tokens):
    app = build_app(settings, tokens, auth=AuthConfig(has_permission=write_implies_read))

    @app.get("/things", dependencies=[fastapi.Depends(require_permission("things:read"))])
    def read() -> None: ...

    client = TestClient(app)
    assert client.get("/things", headers=tokens.headers(permissions=["things:write"])).status_code == 200
    assert client.get("/things", headers=tokens.headers(permissions=["things:read"])).status_code == 200
    assert client.get("/things", headers=tokens.headers(permissions=["other"])).status_code == 403


def read_only_machines(request: fastapi.Request, principal: Principal) -> None:
    if principal.kind == "machine" and request.method not in {"GET", "HEAD"}:
        raise AuthorizationError("This credential can only read")


@pytest.fixture
def restricted_settings():
    return make_settings(workos_machine_clients={"client_machine_test": ["things:write"]})


@pytest.fixture
def restricted_app(restricted_settings, tokens):
    app = add_routes(
        build_app(restricted_settings, tokens, auth=AuthConfig(request_checks=[read_only_machines]))
    )

    @app.post("/graphql")
    async def graphql(request: fastapi.Request) -> dict[str, typing.Any]:
        principal = await try_authenticate(request)
        return {"id": principal.id if principal else None, "cached": hasattr(request.state, "principal")}

    return app


def test_request_checks(restricted_app, tokens):
    client = TestClient(restricted_app)
    machine = tokens.headers(tokens.machine_token())
    assert client.get("/me", headers=machine).json()["kind"] == "machine"
    response = client.post("/things", headers=machine)
    assert response.status_code == 403
    assert response.json() == {"detail": "This credential can only read"}
    assert response.headers["x-auth-status"] == "fail"
    assert client.post("/things", headers=tokens.headers(permissions=["things:write"])).status_code == 200


def test_request_checks_in_shadow_mode(tokens):
    settings = make_settings(
        environment="staging",
        auth_enforce=False,
        workos_machine_clients={"client_machine_test": ["things:write"]},
    )
    app = add_routes(build_app(settings, tokens, auth=AuthConfig(request_checks=[read_only_machines])))
    assert TestClient(app).post("/things", headers=tokens.headers(tokens.machine_token())).status_code == 403


def test_refused_caller_is_not_cached(restricted_app, tokens):
    response = TestClient(restricted_app).post("/graphql", headers=tokens.headers(tokens.machine_token()))
    assert response.json() == {"id": None, "cached": False}


def test_request_checks_apply_to_a_cached_principal(restricted_app, tokens):
    @restricted_app.middleware("http")
    async def preset(request: fastapi.Request, call_next):
        request.state.principal = Principal(kind="machine", id="client_machine_test")
        return await call_next(request)

    client = TestClient(restricted_app)
    assert client.get("/me").json() == {"id": "client_machine_test", "kind": "machine"}
    assert client.post("/things").json() == {"detail": "This credential can only read"}


class WrappingAuthenticator:
    def __init__(self, inner: Authenticator) -> None:
        self.inner = inner

    async def authenticate(self, token: str | None) -> Principal:
        return await self.inner.authenticate(token)


def test_wrapped_local_authenticator_is_skipped():
    settings = make_settings(auth_provider="local")
    local = LocalAuthenticator(Principal(kind="local", id="user_local"))
    app = add_routes(build_app(settings, auth=AuthConfig(authenticator=WrappingAuthenticator(local))))
    response = TestClient(app).get("/me")
    assert response.json() == {"id": "user_local", "kind": "local"}
    assert response.headers["x-auth-status"] == "skipped"
