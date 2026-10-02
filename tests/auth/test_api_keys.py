import json
import typing

import httpx
import pytest
from fastapi.testclient import TestClient

from cr_service.auth import AuthConfig, AuthenticationError, AuthUnavailableError, CurrentPrincipal, Principal
from cr_service.auth.api_keys import ApiKeyVerifier
from cr_service.auth.authenticator import build_authenticator, clear_auth_caches
from cr_service.auth.dependencies import install_auth
from tests.conftest import build_app, make_settings

USER_KEY = {
    "object": "api_key",
    "id": "api_key_user",
    "owner": {"type": "user", "id": "user_1", "organization_id": "org_1"},
    "name": "Laptop",
    "expires_at": None,
    "permissions": ["things:read", "things:write"],
}
ORG_KEY = {
    "object": "api_key",
    "id": "api_key_org",
    "owner": {"type": "organization", "id": "org_1"},
    "name": "CI",
    "expires_at": None,
    "permissions": ["things:read"],
}
USER = {"id": "user_1", "email": "person@example.com", "email_verified": True, "first_name": "Pat"}


class FakeWorkOS:
    """Answers the WorkOS endpoints the verifier calls, recording each request."""

    def __init__(
        self, keys: dict[str, typing.Any] | None = None, *, user: dict[str, typing.Any] = USER
    ) -> None:
        self.keys = {"sk_user": USER_KEY, "sk_org": ORG_KEY} if keys is None else keys
        self.user = user
        self.flags = [{"slug": "app:things"}]
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/api_keys/validations":
            return httpx.Response(200, json={"api_key": self.keys.get(json.loads(request.content)["value"])})
        if path == "/user_management/users/user_1":
            return httpx.Response(200, json=self.user)
        if path == "/organizations/org_1/feature-flags":
            return httpx.Response(200, json={"data": self.flags, "list_metadata": {"after": None}})
        return httpx.Response(404)

    @property
    def validations(self) -> int:
        return sum(request.url.path == "/api_keys/validations" for request in self.requests)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def verifier(workos: FakeWorkOS, **kwargs: typing.Any) -> ApiKeyVerifier:
    return ApiKeyVerifier("sk_management", transport=httpx.MockTransport(workos), **kwargs)


async def test_user_key_acts_as_the_user():
    workos = FakeWorkOS()
    principal = await verifier(workos).verify("sk_user")
    assert principal.kind == "user"
    assert principal.id == "user_1"
    assert principal.organization_id == "org_1"
    assert principal.permissions == {"things:read", "things:write"}
    assert principal.feature_flags == {"app:things"}
    assert principal.email == "person@example.com"
    assert principal.email_verified
    assert principal.first_name == "Pat"
    assert principal.credential == "api_key"
    assert principal.token_id == "api_key_user"
    assert principal.role is None
    assert workos.requests[0].headers["authorization"] == "Bearer sk_management"


async def test_organization_key_is_a_machine():
    principal = await verifier(FakeWorkOS()).verify("sk_org")
    assert principal.kind == "machine"
    assert principal.id == "api_key_org"
    assert principal.organization_id == "org_1"
    assert principal.permissions == {"things:read"}
    assert principal.feature_flags == {"app:things"}
    assert principal.credential == "api_key"


async def test_unknown_key_is_refused_and_not_cached():
    workos = FakeWorkOS()
    keys = verifier(workos)
    for _ in range(2):
        with pytest.raises(AuthenticationError, match="invalid, expired or revoked"):
            await keys.verify("sk_unknown")
    assert workos.validations == 2


async def test_accepted_key_is_cached_until_the_ttl():
    workos = FakeWorkOS()
    clock = Clock()
    keys = verifier(workos, ttl=60.0, clock=clock)
    await keys.verify("sk_org")
    clock.now = 59.0
    await keys.verify("sk_org")
    assert workos.validations == 1

    workos.keys = {}
    clock.now = 61.0
    with pytest.raises(AuthenticationError):
        await keys.verify("sk_org")


async def test_cache_is_bounded():
    workos = FakeWorkOS()
    keys = verifier(workos, max_entries=1)
    await keys.verify("sk_user")
    await keys.verify("sk_org")
    await keys.verify("sk_user")
    assert workos.validations == 3


@pytest.mark.parametrize(
    ("expires_at", "accepted"), [("2020-01-01T00:00:00.000Z", False), ("2999-01-01T00:00:00.000Z", True)]
)
async def test_expiry(expires_at, accepted):
    keys = verifier(FakeWorkOS({"sk_org": {**ORG_KEY, "expires_at": expires_at}}))
    if accepted:
        assert (await keys.verify("sk_org")).id == "api_key_org"
    else:
        with pytest.raises(AuthenticationError, match="expired"):
            await keys.verify("sk_org")


async def test_unsupported_owner_is_refused():
    keys = verifier(FakeWorkOS({"sk_team": {**ORG_KEY, "owner": {"type": "team", "id": "team_1"}}}))
    with pytest.raises(AuthenticationError, match="unsupported owner"):
        await keys.verify("sk_team")


@pytest.mark.parametrize(
    "key",
    [
        {**USER_KEY, "owner": {"type": "user", "id": "user_1"}},
        {**ORG_KEY, "owner": None},
        {**ORG_KEY, "permissions": "things:read"},
        {**ORG_KEY, "id": None},
    ],
)
async def test_malformed_key_is_unavailable(key):
    with pytest.raises(AuthUnavailableError):
        await verifier(FakeWorkOS({"sk_bad": key})).verify("sk_bad")


async def test_workos_outage_is_unavailable():
    keys = ApiKeyVerifier("sk_management", transport=httpx.MockTransport(lambda request: httpx.Response(500)))
    with pytest.raises(AuthUnavailableError):
        await keys.verify("sk_user")


async def test_require_email():
    keys = verifier(FakeWorkOS(user={"id": "user_1"}), require_email=True)
    with pytest.raises(AuthenticationError, match="no email"):
        await keys.verify("sk_user")


def test_build_authenticator_with_api_keys():
    assert build_authenticator(make_settings(workos_accept_api_keys=True, workos_api_key="sk_test"))


def test_api_key_verifier_is_shared_per_key():
    settings = make_settings(workos_accept_api_keys=True, workos_api_key="sk_one")
    first = build_authenticator(settings)._api_keys
    assert first is not None
    assert build_authenticator(settings)._api_keys is first
    rotated = build_authenticator(make_settings(workos_accept_api_keys=True, workos_api_key="sk_two"))
    assert rotated._api_keys is not first
    clear_auth_caches()
    assert build_authenticator(settings)._api_keys is not first


def test_api_keys_override_the_shared_verifier():
    override = ApiKeyVerifier("sk_override")
    settings = make_settings(workos_accept_api_keys=True, workos_api_key="sk_one")
    assert build_authenticator(settings, api_keys=override)._api_keys is override


def api_key_client(workos: FakeWorkOS, **settings: typing.Any) -> TestClient:
    settings = make_settings(workos_accept_api_keys=True, workos_api_key="sk_management", **settings)
    app = build_app(settings, auth=None)
    install_auth(
        app, settings, AuthConfig(authenticator=build_authenticator(settings, api_keys=verifier(workos)))
    )

    @app.get("/me")
    def me(principal: CurrentPrincipal) -> dict[str, typing.Any]:
        return {"id": principal.id, "kind": principal.kind, "credential": principal.credential}

    return TestClient(app)


def test_api_key_bearer():
    client = api_key_client(FakeWorkOS())
    response = client.get("/me", headers={"Authorization": "Bearer sk_user"})
    assert response.json() == {"id": "user_1", "kind": "user", "credential": "api_key"}
    assert client.get("/me", headers={"Authorization": "Bearer sk_unknown"}).status_code == 401


def test_api_keys_pass_the_organisation_and_feature_flag_gates():
    workos = FakeWorkOS()
    allowed = api_key_client(workos, workos_required_feature_flag="app:things")
    assert allowed.get("/me", headers={"Authorization": "Bearer sk_user"}).status_code == 200

    assert allowed.get("/me", headers={"Authorization": "Bearer sk_org"}).status_code == 200

    workos.flags = []
    unflagged = api_key_client(workos, workos_required_feature_flag="app:things")
    assert unflagged.get("/me", headers={"Authorization": "Bearer sk_user"}).status_code == 403
    assert unflagged.get("/me", headers={"Authorization": "Bearer sk_org"}).status_code == 403

    elsewhere = api_key_client(FakeWorkOS(), workos_allowed_organization_ids="org_other")
    assert elsewhere.get("/me", headers={"Authorization": "Bearer sk_org"}).status_code == 403


def test_api_keys_refused_unless_accepted(settings, tokens):
    app = build_app(settings, tokens)

    @app.get("/me")
    def me(principal: CurrentPrincipal) -> dict[str, str]:
        return {"id": principal.id}

    response = TestClient(app).get("/me", headers={"Authorization": "Bearer sk_user"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Access token is not a valid JWT"}


def test_principal_default_credential():
    assert Principal(kind="user", id="user_1").credential == "access_token"
