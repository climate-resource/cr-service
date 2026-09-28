"""FastAPI dependencies that authenticate and authorise the caller."""

import dataclasses
import logging
import typing
from collections.abc import Awaitable, Callable, Sequence

import fastapi
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from cr_service import context
from cr_service.auth.authenticator import Authenticator, LocalAuthenticator, build_authenticator
from cr_service.auth.errors import AuthenticationError, AuthError, AuthorizationError
from cr_service.auth.hooks import FailureHook, SuccessHook, log_auth_failure, observe_principal
from cr_service.auth.principal import ANONYMOUS, Principal
from cr_service.settings import ServiceSettings

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=False, description="WorkOS access token")


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class AuthConfig:
    """How :func:`cr_service.setup` installs auth. Every field is optional.

    ``on_success`` and ``on_failure`` run after the built-in hooks,
    which put the caller's ids on the logs, Sentry and the trace.
    """

    authenticator: Authenticator | None = None
    """Replaces the one built from the settings, for extra token types or tests."""

    on_success: Sequence[SuccessHook] = ()
    on_failure: Sequence[FailureHook] = ()

    resource_metadata_url: str | None = None
    """Advertised on 401s, for clients that discover the authorisation server (RFC 9728)."""


@dataclasses.dataclass(frozen=True, slots=True)
class _InstalledAuth:
    authenticator: Authenticator
    enforce: bool
    config: AuthConfig


def install_auth(app: fastapi.FastAPI, settings: ServiceSettings, config: AuthConfig | None = None) -> None:
    """Make the auth dependencies work on ``app``. :func:`cr_service.setup` calls this."""
    config = config or AuthConfig()
    if not settings.auth_enforce:
        logger.warning(
            "Auth is in shadow mode: failures are logged but not refused",
            extra={"environment": settings.environment},
        )
    app.state.cr_service_auth = _InstalledAuth(
        authenticator=config.authenticator or build_authenticator(settings),
        enforce=settings.auth_enforce,
        config=config,
    )


def _installed(request: fastapi.Request) -> _InstalledAuth:
    installed = getattr(request.app.state, "cr_service_auth", None)
    if installed is None:
        raise RuntimeError("cr_service auth is not installed, call setup() when building the app")
    return typing.cast(_InstalledAuth, installed)


def _http_error(installed: _InstalledAuth, error: AuthError) -> fastapi.HTTPException:
    headers: dict[str, str] | None = None
    if isinstance(error, AuthenticationError):
        params = [] if error.missing else ['error="invalid_token"']
        if url := installed.config.resource_metadata_url:
            params.append(f'resource_metadata="{url}"')
        headers = {"WWW-Authenticate": " ".join(["Bearer", ", ".join(params)]).strip()}
    return fastapi.HTTPException(status_code=error.status_code, detail=str(error), headers=headers)


def _record_failure(request: fastapi.Request, error: AuthError, outcome: str) -> None:
    context.bind(auth_outcome=outcome)
    for hook in (log_auth_failure, *_installed(request).config.on_failure):
        hook(request, error)


def _refuse(request: fastapi.Request, error: AuthError) -> None:
    """Run the failure hooks, then raise unless in shadow mode."""
    installed = _installed(request)
    _record_failure(request, error, "fail" if installed.enforce else "shadow_fail")
    if installed.enforce:
        raise _http_error(installed, error)


async def _authenticate(
    request: fastapi.Request,
    credentials: HTTPAuthorizationCredentials | None,
    *,
    required: bool,
    refuse: bool = True,
) -> Principal | None:
    cached = getattr(request.state, "principal", None)
    if isinstance(cached, Principal):
        return cached

    installed = _installed(request)
    try:
        principal = await installed.authenticator.authenticate(
            credentials.credentials if credentials else None
        )
    except AuthError as error:
        if not required and isinstance(error, AuthenticationError) and error.missing:
            return None
        if not refuse:
            _record_failure(request, error, "fail" if installed.enforce else "shadow_fail")
            return None
        _refuse(request, error)
        return ANONYMOUS if required else None

    skipped = isinstance(installed.authenticator, LocalAuthenticator)
    context.bind(auth_outcome="skipped" if skipped else "pass")
    for hook in (observe_principal, *installed.config.on_success):
        hook(request, principal)
    request.state.principal = principal
    return principal


async def require_principal(
    request: fastapi.Request,
    credentials: typing.Annotated[HTTPAuthorizationCredentials | None, fastapi.Security(bearer_scheme)],
) -> Principal:
    """Return the caller, answering 401 if they are not authenticated.

    In shadow mode an unauthenticated caller gets :data:`ANONYMOUS` instead.
    """
    principal = await _authenticate(request, credentials, required=True)
    assert principal is not None
    return principal


async def optional_principal(
    request: fastapi.Request,
    credentials: typing.Annotated[HTTPAuthorizationCredentials | None, fastapi.Security(bearer_scheme)],
) -> Principal | None:
    """Return the caller, or ``None`` if the request carries no token. An invalid token is still refused."""
    return await _authenticate(request, credentials, required=False)


async def try_authenticate(request: fastapi.Request) -> Principal | None:
    """Return the caller, or ``None`` without a valid token, never refusing the request.

    For code that decides access itself, such as a GraphQL context.
    Failures, including a JWKS outage, still run the failure hooks and set ``x-auth-status``.
    """
    return await _authenticate(request, await bearer_scheme(request), required=False, refuse=False)


CurrentPrincipal = typing.Annotated[Principal, fastapi.Depends(require_principal)]
OptionalPrincipal = typing.Annotated[Principal | None, fastapi.Depends(optional_principal)]


def require_permission(*permissions: str) -> Callable[..., Awaitable[Principal]]:
    """Build a dependency that answers 403 unless the caller holds every one of ``permissions``.

    Use it as ``dependencies=[Depends(require_permission("ndc:commit"))]`` on a route or router,
    or as a parameter type to also receive the caller.
    """

    async def check_permissions(request: fastapi.Request, principal: CurrentPrincipal) -> Principal:
        missing = sorted(permission for permission in permissions if not principal.has_permission(permission))
        if missing:
            _refuse(request, AuthorizationError(f"Missing permission: {', '.join(missing)}"))
        return principal

    return check_permissions


def require_feature_flag(flag: str) -> Callable[..., Awaitable[Principal]]:
    """Build a dependency that answers 403 unless the caller's organisation has ``flag``."""

    async def check_feature_flag(request: fastapi.Request, principal: CurrentPrincipal) -> Principal:
        if not principal.has_feature_flag(flag):
            _refuse(request, AuthorizationError(f"Missing feature flag: {flag}"))
        return principal

    return check_feature_flag
