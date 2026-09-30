"""Turning a bearer token into a :class:`Principal`."""

import secrets
import typing

from cr_service.auth.api_keys import ApiKeyVerifier
from cr_service.auth.errors import AuthConfigurationError, AuthenticationError, AuthorizationError
from cr_service.auth.keys import JWKSCache, KeySource
from cr_service.auth.principal import Principal
from cr_service.auth.verifier import TokenVerifier, TrustProfile
from cr_service.settings import ServiceSettings


class Authenticator(typing.Protocol):
    """Authenticates the bearer token on a request."""

    async def authenticate(self, token: str | None) -> Principal:
        """Return the caller, raising :class:`cr_service.auth.AuthError` if they are not let in.

        A missing token raises :class:`AuthenticationError` with ``missing=True``,
        so optional routes can let the request through.
        """
        ...


class WorkOSAuthenticator:
    """Verifies WorkOS access tokens and API keys, then applies the organisation and feature-flag gates."""

    def __init__(
        self,
        verifier: TokenVerifier,
        *,
        api_keys: ApiKeyVerifier | None = None,
        allowed_organization_ids: typing.Iterable[str] = (),
        required_feature_flag: str | None = None,
    ) -> None:
        self._verifier = verifier
        self._api_keys = api_keys
        self._allowed_organization_ids = frozenset(allowed_organization_ids)
        self._required_feature_flag = required_feature_flag

    async def authenticate(self, token: str | None) -> Principal:
        """Verify the token and check the caller against the gates."""
        if not token:
            raise AuthenticationError("Missing bearer token", missing=True)
        if self._api_keys is not None and self._api_keys.recognises(token):
            principal = await self._api_keys.verify(token)
        else:
            principal = await self._verifier.verify(token)
        if self._allowed_organization_ids and principal.organization_id not in self._allowed_organization_ids:
            raise AuthorizationError("Organisation is not allowed to use this service")
        # Feature flags are targeted at organisations a person belongs to, so machines are exempt.
        if (
            self._required_feature_flag
            and principal.kind == "user"
            and not principal.has_feature_flag(self._required_feature_flag)
        ):
            raise AuthorizationError(
                f"Organisation does not have the {self._required_feature_flag!r} feature flag"
            )
        return principal


class LocalAuthenticator:
    """Lets every request through as one fixed identity, for local development."""

    def __init__(self, principal: Principal) -> None:
        self.principal = principal

    async def authenticate(self, token: str | None) -> Principal:
        """Return the fixed identity, whatever the token."""
        return self.principal


class FakeAuthenticator:
    """Returns one fixed identity for one known token, so tests and demos still send a bearer token."""

    def __init__(self, principal: Principal, *, token: str) -> None:
        self.principal = principal
        self._token = token

    async def authenticate(self, token: str | None) -> Principal:
        """Return the fixed identity if ``token`` is the known one."""
        if not token:
            raise AuthenticationError("Missing bearer token", missing=True)
        if not secrets.compare_digest(token, self._token):
            raise AuthenticationError("Access token is not the fake token")
        return self.principal


def _local_principal(settings: ServiceSettings) -> Principal:
    return Principal(
        kind="local",
        id=settings.auth_local_user_id,
        email=settings.auth_local_email,
        email_verified=True,
        organization_id=settings.auth_local_organization_id,
        permissions=frozenset(settings.auth_local_permissions),
        feature_flags=frozenset(settings.auth_local_feature_flags),
        roles=tuple(sorted(set(settings.auth_local_roles))),
    )


def build_authenticator(
    settings: ServiceSettings, *, keys: KeySource | None = None, api_keys: ApiKeyVerifier | None = None
) -> Authenticator:
    """Build the authenticator the settings describe.

    ``keys`` replaces the JWKS fetched from WorkOS, which is how tests sign tokens.
    ``api_keys`` replaces the API key verifier built when ``WORKOS_ACCEPT_API_KEYS`` is set.
    """
    if settings.auth_provider == "local":
        return LocalAuthenticator(_local_principal(settings))
    if settings.auth_provider == "fake":
        return FakeAuthenticator(_local_principal(settings), token=settings.auth_fake_token)

    if not settings.workos_client_id:
        raise AuthConfigurationError("WORKOS_CLIENT_ID must be set when AUTH_PROVIDER=workos")

    workos = settings.workos
    profiles = [
        TrustProfile(
            kind="user",
            issuer=workos.user_token_issuer,
            keys=keys or JWKSCache(workos.user_jwks_url),
            audience=None,
        )
    ]
    if settings.workos_machine_clients:
        profiles.append(
            TrustProfile(
                kind="machine",
                issuer=workos.machine_token_issuer,
                keys=keys or JWKSCache(workos.machine_jwks_url),
                audience=workos.machine_token_audience,
            )
        )
    verifier = TokenVerifier(
        profiles,
        accepted_client_ids=settings.accepted_client_ids,
        machine_clients=settings.workos_machine_clients,
        machine_organizations=settings.workos_machine_client_organizations,
        require_email=settings.workos_require_email,
    )
    if api_keys is None and settings.workos_accept_api_keys:
        if settings.workos_api_key is None:
            raise AuthConfigurationError("WORKOS_API_KEY must be set when WORKOS_ACCEPT_API_KEYS=true")
        api_keys = ApiKeyVerifier(
            settings.workos_api_key.get_secret_value(), require_email=settings.workos_require_email
        )
    return WorkOSAuthenticator(
        verifier,
        api_keys=api_keys,
        allowed_organization_ids=settings.workos_allowed_organization_ids,
        required_feature_flag=settings.workos_required_feature_flag,
    )
