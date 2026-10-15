import json

import fastapi
import pytest

from cr_service import AuthConfig, context
from cr_service.auth import AuthorizationError, Principal, install_auth
from cr_service.auth.authenticator import FakeAuthenticator
from cr_service.auth.dependencies import authenticate_request, installed_config
from cr_service.auth.outcome import AuthOutcome, auth_status_header
from tests.conftest import make_settings

USER = Principal(kind="user", id="user_1")
AUTHENTICATOR = FakeAuthenticator(USER, token="good")


def make_request(*, enforce: bool = True, **config) -> fastapi.Request:
    app = fastapi.FastAPI()
    settings = make_settings(environment="staging", auth_enforce=enforce)
    install_auth(app, settings, AuthConfig(authenticator=AUTHENTICATOR, **config))
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
        attempt = await authenticate_request(request, AUTHENTICATOR, "good")
        assert context.get_context()["auth_outcome"] == "pass"
    assert attempt.principal is USER
    assert attempt.outcome is AuthOutcome.PASS
    assert not attempt.enforced
    assert request.state.principal is USER
    assert request.state.auth_outcome == "pass"


async def test_enforced_failure():
    attempt = await authenticate_request(make_request(), AUTHENTICATOR, "junk")
    assert attempt.outcome is AuthOutcome.FAIL
    with pytest.raises(fastapi.HTTPException) as raised:
        attempt.enforce()
    assert raised.value.status_code == 401
    assert raised.value.headers == {"WWW-Authenticate": 'Bearer error="invalid_token"'}


async def test_shadow_mode_lets_authentication_failures_through():
    request = make_request(enforce=False)
    attempt = await authenticate_request(request, AUTHENTICATOR, "junk")
    assert attempt.outcome is AuthOutcome.SHADOW_FAIL
    assert attempt.enforce() is None
    assert request.state.auth_outcome == "shadow_fail"


async def test_shadow_mode_still_enforces_authorisation_failures():
    def refuse(request: fastapi.Request, principal: Principal) -> None:
        raise AuthorizationError("Read-only credential")

    request = make_request(enforce=False, request_checks=[refuse])
    attempt = await authenticate_request(request, AUTHENTICATOR, "good")
    assert attempt.outcome is AuthOutcome.FAIL
    with pytest.raises(fastapi.HTTPException) as raised:
        attempt.enforce()
    assert raised.value.status_code == 403


async def test_missing_token_on_an_optional_route_records_nothing():
    request = make_request()
    attempt = await authenticate_request(request, AUTHENTICATOR, None, allow_missing=True)
    assert attempt.outcome is None
    assert attempt.enforce() is None
    assert not hasattr(request.state, "auth_outcome")
    required = await authenticate_request(request, AUTHENTICATOR, None)
    assert required.outcome is AuthOutcome.FAIL


async def test_cached_principal_still_runs_request_checks():
    checked: list[str] = []

    def check(request: fastapi.Request, principal: Principal) -> None:
        checked.append(principal.id)
        if len(checked) > 1:
            raise AuthorizationError("Second look refused")

    authenticated: list[str] = []
    request = make_request(
        request_checks=[check], on_success=[lambda _, principal: authenticated.append(principal.id)]
    )
    assert (await authenticate_request(request, AUTHENTICATOR, "good")).principal is USER
    attempt = await authenticate_request(request, AUTHENTICATOR, "good")
    assert authenticated == ["user_1"]
    assert checked == ["user_1", "user_1"]
    assert attempt.outcome is AuthOutcome.FAIL
    assert attempt.enforced


def test_installed_config():
    app = fastapi.FastAPI()
    assert installed_config(app) is None
    config = AuthConfig(authenticator=AUTHENTICATOR)
    install_auth(app, make_settings(), config)
    assert installed_config(app) is config
