import time

import jwt
import pytest

from cr_service.auth import (
    AuthConfigurationError,
    AuthenticationError,
    AuthorizationError,
    build_authenticator,
)
from cr_service.auth.testing import TokenFactory
from cr_service.workos import STAGING
from tests.conftest import make_settings


@pytest.fixture
def machine_settings():
    return make_settings(workos_machine_clients={"client_publisher": ["things:write"]})


async def test_user_token(settings, tokens):
    authenticator = tokens.authenticator(settings)
    principal = await authenticator.authenticate(
        tokens.user_token(permissions=["things:read"], feature_flags=["app:things"], user_id="user_1")
    )
    assert principal.kind == "user"
    assert principal.id == "user_1"
    assert principal.organization_id == "org_test"
    assert principal.permissions == {"things:read"}
    assert principal.has_permission("things:read")
    assert principal.has_feature_flag("app:things")
    assert principal.email_verified is True
    assert principal.display_name == "Test User"
    assert principal.client_id == "client_service"
    assert principal.roles == ("member",)
    assert principal.claims["sub"] == "user_1"


async def test_missing_token(settings, tokens):
    with pytest.raises(AuthenticationError) as excinfo:
        await tokens.authenticator(settings).authenticate(None)
    assert excinfo.value.missing


@pytest.mark.parametrize(
    ("token_kwargs", "message"),
    [
        ({"expires_in": -60}, "expired"),
        ({"client_id": "client_other_app"}, "different application"),
        ({"iss": "https://api.workos.com/user_management/client_service"}, "untrusted issuer"),
        ({"roles": "member"}, "malformed roles"),
    ],
)
async def test_rejected_user_tokens(settings, tokens, token_kwargs, message):
    with pytest.raises(AuthenticationError, match=message):
        await tokens.authenticator(settings).authenticate(tokens.user_token(**token_kwargs))


async def test_additional_client_ids_accepted(tokens):
    settings = make_settings(workos_additional_client_ids=("client_cli",))
    principal = await tokens.authenticator(settings).authenticate(tokens.user_token(client_id="client_cli"))
    assert principal.client_id == "client_cli"


async def test_bookshelf_tokens(tokens):
    bookshelf_token = tokens.user_token(client_id=STAGING.bookshelf_client_id)
    with pytest.raises(AuthenticationError, match="different application"):
        await tokens.authenticator(make_settings()).authenticate(bookshelf_token)
    settings = make_settings(workos_accept_bookshelf_tokens=True)
    principal = await tokens.authenticator(settings).authenticate(bookshelf_token)
    assert principal.client_id == STAGING.bookshelf_client_id


async def test_token_from_another_environment(settings, tokens):
    production_tokens = TokenFactory.for_settings(make_settings(environment="production"))
    with pytest.raises(AuthenticationError, match="untrusted issuer"):
        await tokens.authenticator(settings).authenticate(production_tokens.user_token())


async def test_signed_by_another_key(settings, tokens):
    impostor = TokenFactory.for_settings(settings)
    with pytest.raises(AuthenticationError, match="Signature verification failed"):
        await tokens.authenticator(settings).authenticate(impostor.user_token())


async def test_unknown_kid(settings, tokens):
    with pytest.raises(AuthenticationError, match="unknown key"):
        await tokens.authenticator(settings).authenticate(
            tokens.sign({"iss": tokens.environment.user_token_issuer, "sub": "u"}, kid="other")
        )


@pytest.mark.parametrize("missing", ["sub", "iat", "exp"])
async def test_required_claims(settings, tokens, missing):
    now = int(time.time())
    claims = {"iss": tokens.environment.user_token_issuer, "sub": "user_1", "iat": now, "exp": now + 60}
    del claims[missing]
    with pytest.raises(AuthenticationError):
        await tokens.authenticator(settings).authenticate(tokens.sign(claims))


async def test_blank_subject(settings, tokens):
    with pytest.raises(AuthenticationError, match="no subject"):
        await tokens.authenticator(settings).authenticate(tokens.user_token(user_id=" "))


async def test_rejects_symmetric_algorithms(settings, tokens):
    token = jwt.encode(
        {"iss": tokens.environment.user_token_issuer, "sub": "u"},
        "secret-that-is-long-enough-for-hs256",
        algorithm="HS256",
        headers={"kid": tokens.kid},
    )
    with pytest.raises(AuthenticationError, match="RS256"):
        await tokens.authenticator(settings).authenticate(token)


async def test_rejects_garbage(settings, tokens):
    with pytest.raises(AuthenticationError, match="not a valid JWT"):
        await tokens.authenticator(settings).authenticate("not-a-jwt")


async def test_rejects_missing_kid(settings, tokens):
    token = jwt.encode({"iss": "x"}, tokens._private_key, algorithm="RS256")
    with pytest.raises(AuthenticationError, match="no key id"):
        await tokens.authenticator(settings).authenticate(token)


async def test_email_verified_false(settings, tokens):
    principal = await tokens.authenticator(settings).authenticate(tokens.user_token(email_verified="false"))
    assert principal.email_verified is False


async def test_machine_token(machine_settings, tokens):
    principal = await tokens.authenticator(machine_settings).authenticate(
        tokens.machine_token(client_id="client_publisher")
    )
    assert principal.kind == "machine"
    assert principal.id == "client_publisher"
    assert principal.permissions == {"things:write"}
    assert principal.organization_id == "org_test"


async def test_machine_token_not_allowed(machine_settings, tokens):
    with pytest.raises(AuthenticationError, match="not allowed"):
        await tokens.authenticator(machine_settings).authenticate(
            tokens.machine_token(client_id="client_other")
        )


async def test_machine_token_wrong_audience(machine_settings, tokens):
    with pytest.raises(AuthenticationError, match="Audience"):
        await tokens.authenticator(machine_settings).authenticate(
            tokens.machine_token(client_id="client_publisher", aud="client_other")
        )


async def test_machine_tokens_off_by_default(settings, tokens):
    with pytest.raises(AuthenticationError, match="untrusted issuer"):
        await tokens.authenticator(settings).authenticate(tokens.machine_token())


async def test_organization_gate(tokens):
    settings = make_settings(workos_allowed_organization_ids=("org_allowed",))
    authenticator = tokens.authenticator(settings)
    assert (await authenticator.authenticate(tokens.user_token(organization_id="org_allowed"))).id
    with pytest.raises(AuthorizationError, match="Organisation"):
        await authenticator.authenticate(tokens.user_token(organization_id="org_test"))


async def test_feature_flag_gate(tokens):
    settings = make_settings(
        workos_required_feature_flag="app:things", workos_machine_clients={"client_publisher": []}
    )
    authenticator = tokens.authenticator(settings)
    assert await authenticator.authenticate(tokens.user_token(feature_flags=["app:things"]))
    with pytest.raises(AuthorizationError, match="feature flag"):
        await authenticator.authenticate(tokens.user_token())
    # Machines carry no feature flags, so the gate does not apply to them.
    assert await authenticator.authenticate(tokens.machine_token(client_id="client_publisher"))


async def test_local_provider():
    settings = make_settings(auth_provider="local", auth_local_permissions=("things:read",))
    authenticator = build_authenticator(settings)
    principal = await authenticator.authenticate(None)
    assert principal.kind == "local"
    assert principal.permissions == {"things:read"}


async def test_fake_provider():
    settings = make_settings(
        auth_provider="fake", auth_fake_token="let-me-in", auth_local_roles=("org-staff",)
    )
    authenticator = build_authenticator(settings)
    principal = await authenticator.authenticate("let-me-in")
    assert principal.kind == "local"
    assert principal.roles == ("org-staff",)
    with pytest.raises(AuthenticationError, match="fake token"):
        await authenticator.authenticate("fake-access-token")
    with pytest.raises(AuthenticationError) as missing:
        await authenticator.authenticate(None)
    assert missing.value.missing


def test_workos_needs_client_id():
    with pytest.raises(AuthConfigurationError, match="WORKOS_CLIENT_ID"):
        build_authenticator(make_settings(workos_client_id=None))


def test_builds_jwks_caches():
    authenticator = build_authenticator(make_settings(workos_machine_clients={"client_m2m": []}))
    profiles = authenticator._verifier._profiles
    assert {profile.keys.url for profile in profiles.values()} == {
        "https://auth-api.climateresource.com.au/sso/jwks/client_01KABZE0E62YS9H7BMV6YZGMD1",
        "https://balanced-universe-28-staging.authkit.app/oauth2/jwks",
    }
