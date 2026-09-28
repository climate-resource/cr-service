"""Turning a bearer token into a :class:`Principal`."""

import typing

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
    """Verifies WorkOS access tokens, then applies the organisation and feature-flag gates."""

    def __init__(
        self,
        verifier: TokenVerifier,
        *,
        allowed_organization_ids: typing.Iterable[str] = (),
        required_feature_flag: str | None = None,
    ) -> None:
        self._verifier = verifier
        self._allowed_organization_ids = frozenset(allowed_organization_ids)
        self._required_feature_flag = required_feature_flag

    async def authenticate(self, token: str | None) -> Principal:
        """Verify the token and check the caller against the gates."""
        if not token:
            raise AuthenticationError("Missing bearer token", missing=True)
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


def build_authenticator(settings: ServiceSettings, *, keys: KeySource | None = None) -> Authenticator:
    """Build the authenticator the settings describe.

    ``keys`` replaces the JWKS fetched from WorkOS, which is how tests sign tokens.
    """
    if settings.auth_provider == "local":
        return LocalAuthenticator(
            Principal(
                kind="local",
                id=settings.auth_local_user_id,
                email=settings.auth_local_email,
                email_verified=True,
                organization_id=settings.auth_local_organization_id,
                permissions=frozenset(settings.auth_local_permissions),
                feature_flags=frozenset(settings.auth_local_feature_flags),
            )
        )

    if not settings.accepted_client_ids:
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
    )
    return WorkOSAuthenticator(
        verifier,
        allowed_organization_ids=settings.workos_allowed_organization_ids,
        required_feature_flag=settings.workos_required_feature_flag,
    )
