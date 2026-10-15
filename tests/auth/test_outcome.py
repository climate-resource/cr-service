import json

import fastapi
import pytest

from cr_service import AuthConfig, context
from cr_service.auth import AuthenticationError, AuthorizationError, Principal, install_auth
from cr_service.auth.dependencies import authenticate_request, installed_config, refuse_request
from cr_service.auth.outcome import AuthOutcome, auth_status_header
from tests.conftest import make_settings

USER = Principal(kind="user", id="user_1")


class StubAuthenticator:
    """Accepts ``good`` and refuses anything else, counting calls."""

    def __init__(self) -> None:
        self.calls = 0

    async def authenticate(self, token: str | None) -> Principal:
        self.calls += 1
        if token is None:
            raise AuthenticationError("Missing access token", missing=True)
        if token != "good":
            raise AuthenticationError("Invalid access token")
        return USER


def make_request(*, enforce: bool = True, **config) -> fastapi.Request:
    app = fastapi.FastAPI()
    settings = make_settings(environment="staging", auth_enforce=enforce)
    install_auth(app, settings, AuthConfig(authenticator=StubAuthenticator(), **config))
    return fastapi.Request({"type": "http", "app": app, "method": "GET", "headers": [], "query_string": b""})


@pytest.mark.parametrize(
    ("outcome", "header"),
    [("pass", b"pass"), ("skipped", b"skipped"), ("fail", b"fail"), ("shadow_fail", b"fail"), (None, None)],
)
def test_auth_status_header(outcome, header):
    assert auth_status_header(outcome) == header
    assert auth_status_header("other") is None


def test_outcome_serialises_as_its_value():
    assert AuthOutcome.SHADOW_FAIL == "shadow_fail"
    assert json.dumps({"auth_outcome": AuthOutcome.PASS}) == '{"auth_outcome": "pass"}'


async def test_pass_is_recorded_and_cached():
    request = make_request()
    with context.log_scope():
        attempt = await authenticate_request(request, StubAuthenticator(), "good")
        assert context.get_context()["auth_outcome"] == "pass"
    assert attempt.principal is USER
    assert attempt.outcome is AuthOutcome.PASS
    assert not attempt.enforced
    assert request.state.principal is USER
    assert request.state.auth_outcome == "pass"


async def test_enforced_failure():
    attempt = await authenticate_request(make_request(), StubAuthenticator(), "junk")
    assert attempt.outcome is AuthOutcome.FAIL
    with pytest.raises(fastapi.HTTPException) as raised:
        attempt.enforce()
    assert raised.value.status_code == 401
    assert raised.value.headers == {"WWW-Authenticate": 'Bearer error="invalid_token"'}


async def test_shadow_mode_lets_authentication_failures_through():
    request = make_request(enforce=False)
    attempt = await authenticate_request(request, StubAuthenticator(), "junk")
    assert attempt.outcome is AuthOutcome.SHADOW_FAIL
    assert attempt.enforce() is None
    assert request.state.auth_outcome == "shadow_fail"


def test_shadow_mode_still_enforces_authorisation_failures():
    attempt = refuse_request(make_request(enforce=False), AuthorizationError("Missing permission: x"))
    assert attempt.outcome is AuthOutcome.FAIL
    with pytest.raises(fastapi.HTTPException) as raised:
        attempt.enforce()
    assert raised.value.status_code == 403


async def test_missing_token_on_an_optional_route_records_nothing():
    request = make_request()
    attempt = await authenticate_request(request, StubAuthenticator(), None, allow_missing=True)
    assert attempt.outcome is None
    assert attempt.enforce() is None
    assert not hasattr(request.state, "auth_outcome")
    required = await authenticate_request(request, StubAuthenticator(), None)
    assert required.outcome is AuthOutcome.FAIL


async def test_cached_principal_still_runs_request_checks():
    checked: list[str] = []

    def check(request: fastapi.Request, principal: Principal) -> None:
        checked.append(principal.id)
        if len(checked) > 1:
            raise AuthorizationError("Second look refused")

    request = make_request(request_checks=[check])
    authenticator = StubAuthenticator()
    assert (await authenticate_request(request, authenticator, "good")).principal is USER
    attempt = await authenticate_request(request, authenticator, "good")
    assert authenticator.calls == 1
    assert checked == ["user_1", "user_1"]
    assert attempt.outcome is AuthOutcome.FAIL
    assert attempt.enforced


def test_installed_config():
    app = fastapi.FastAPI()
    assert installed_config(app) is None
    config = AuthConfig(authenticator=StubAuthenticator())
    install_auth(app, make_settings(), config)
    assert installed_config(app) is config
