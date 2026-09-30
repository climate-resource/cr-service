"""FastAPI dependencies that authenticate and authorise the caller."""

import dataclasses
import logging
import typing
from collections.abc import Awaitable, Callable, Sequence

import fastapi
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from cr_service import context
from cr_service.auth.authenticator import Authenticator, build_authenticator
from cr_service.auth.errors import AuthenticationError, AuthError, AuthorizationError
from cr_service.auth.hooks import FailureHook, SuccessHook, log_auth_failure, observe_principal
from cr_service.auth.principal import ANONYMOUS, Principal
from cr_service.settings import ServiceSettings

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=False, description="Access token")

PermissionCheck = Callable[[Principal, str], bool]
RequestCheck = Callable[[fastapi.Request, Principal], None]
ResourceMetadataUrl = str | Callable[[fastapi.Request], str]


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class AuthConfig:
    """How :func:`install_auth` installs auth. Every field is optional.

    ``on_success`` and ``on_failure`` run after the built-in hooks,
    which put the caller's ids on the logs, Sentry and the trace.
    They observe attempts and never decide access.
    ``has_permission`` and ``request_checks`` do.
    """

    authenticator: Authenticator | None = None
    """Replaces the one built from the settings, for extra token types or tests.

    With ``authenticator_dependency`` set, this is the app's authenticator the dependency can wrap.
    """

    authenticator_dependency: Callable[..., typing.Any] | None = None
    """A FastAPI dependency that returns or yields the authenticator for one request.

    It can take the request, depend on :func:`base_authenticator` to wrap the app's authenticator,
    and depend on request-scoped resources such as a database session, which FastAPI cleans up.
    """

    has_permission: PermissionCheck | None = None
    """Decides whether a caller holds a permission for :func:`require_permission`.

    Defaults to :meth:`Principal.has_permission`.
    Set it when one permission implies another, such as write implying read.
    """

    request_checks: Sequence[RequestCheck] = ()
    """Run against every authenticated caller before a dependency returns them.

    Raise :class:`AuthorizationError` to refuse the request, such as a read-only credential on a POST.
    They run each time a dependency asks for the caller, so keep them free of side effects.
    """

    on_success: Sequence[SuccessHook] = ()
    on_failure: Sequence[FailureHook] = ()

    resource_metadata_url: ResourceMetadataUrl | None = None
    """Advertised on 401s, for clients that discover the authorisation server (RFC 9728).

    A callable builds it from the request, for a service whose public origin depends on how it was reached.
    """


@dataclasses.dataclass(frozen=True, slots=True)
class _InstalledAuth:
    authenticator: Authenticator
    enforce: bool
    config: AuthConfig


def install_auth(app: fastapi.FastAPI, settings: ServiceSettings, config: AuthConfig | None = None) -> None:
    """Make the auth dependencies work on ``app``.

    :func:`cr_service.setup` calls this.
    A service with its own logging and middleware can call it alone.
    It adds no middleware, so calling it again replaces the earlier installation.
    """
    config = config or AuthConfig()
    if not settings.auth_enforce:
        logger.warning(
            "Auth is in shadow mode: authentication failures are logged but not refused",
            extra={"environment": settings.environment},
        )
    app.dependency_overrides.pop(_request_authenticator, None)
    if config.authenticator_dependency is not None:
        app.dependency_overrides[_request_authenticator] = config.authenticator_dependency
    app.state.cr_service_auth = _InstalledAuth(
        authenticator=config.authenticator or build_authenticator(settings),
        enforce=settings.auth_enforce,
        config=config,
    )


def _installed(request: fastapi.Request) -> _InstalledAuth:
    installed = getattr(request.app.state, "cr_service_auth", None)
    if installed is None:
        raise RuntimeError(
            "cr_service auth is not installed, call setup() or install_auth() when building the app"
        )
    return typing.cast(_InstalledAuth, installed)


async def base_authenticator(request: fastapi.Request) -> Authenticator:
    """Return the app's authenticator, for an ``authenticator_dependency`` to wrap."""
    return _installed(request).authenticator


async def _request_authenticator(request: fastapi.Request) -> Authenticator:
    # install_auth overrides this with AuthConfig.authenticator_dependency.
    installed = _installed(request)
    if installed.config.authenticator_dependency is not None:
        raise RuntimeError("The auth authenticator_dependency is missing from app.dependency_overrides")
    return installed.authenticator


def _http_error(
    request: fastapi.Request, installed: _InstalledAuth, error: AuthError
) -> fastapi.HTTPException:
    headers: dict[str, str] | None = None
    if isinstance(error, AuthenticationError):
        params = [] if error.missing else ['error="invalid_token"']
        url = installed.config.resource_metadata_url
        if callable(url):
            url = url(request)
        if url:
            params.append(f'resource_metadata="{url}"')
        headers = {"WWW-Authenticate": " ".join(["Bearer", ", ".join(params)]).strip()}
    return fastapi.HTTPException(status_code=error.status_code, detail=str(error), headers=headers)


def _enforced(installed: _InstalledAuth, error: AuthError) -> bool:
    # Shadow mode only lets unauthenticated callers through, never unauthorised ones.
    return installed.enforce or isinstance(error, AuthorizationError)


def _record_outcome(request: fastapi.Request, outcome: str) -> None:
    context.bind(auth_outcome=outcome)
    request.state.auth_outcome = outcome


def _record_failure(request: fastapi.Request, error: AuthError) -> None:
    installed = _installed(request)
    _record_outcome(request, "fail" if _enforced(installed, error) else "shadow_fail")
    for hook in (log_auth_failure, *installed.config.on_failure):
        hook(request, error)


def _refuse(request: fastapi.Request, error: AuthError) -> None:
    """Run the failure hooks, then raise unless shadow mode lets an authentication failure through."""
    _record_failure(request, error)
    installed = _installed(request)
    if _enforced(installed, error):
        raise _http_error(request, installed, error)


def _failed(request: fastapi.Request, error: AuthError, *, required: bool, refuse: bool) -> Principal | None:
    if not required and isinstance(error, AuthenticationError) and error.missing:
        return None
    if not refuse:
        _record_failure(request, error)
        return None
    _refuse(request, error)
    return ANONYMOUS if required else None


async def _authenticate(
    request: fastapi.Request,
    authenticator: Authenticator,
    credentials: HTTPAuthorizationCredentials | None,
    *,
    required: bool,
    refuse: bool = True,
) -> Principal | None:
    installed = _installed(request)
    state = getattr(request.state, "principal", None)
    cached = state if isinstance(state, Principal) else None
    try:
        if cached is not None:
            principal = cached
        else:
            principal = await authenticator.authenticate(credentials.credentials if credentials else None)
        # Checked on every call, so a principal cached by any means cannot skip them.
        for check in installed.config.request_checks:
            check(request, principal)
    except AuthError as error:
        return _failed(request, error, required=required, refuse=refuse)

    if principal is cached:
        return principal
    _record_outcome(request, "skipped" if principal.credential == "none" else "pass")
    for hook in (observe_principal, *installed.config.on_success):
        hook(request, principal)
    request.state.principal = principal
    return principal


RequestAuthenticator = typing.Annotated[Authenticator, fastapi.Depends(_request_authenticator)]
Credentials = typing.Annotated[HTTPAuthorizationCredentials | None, fastapi.Security(bearer_scheme)]


async def require_principal(
    request: fastapi.Request, credentials: Credentials, authenticator: RequestAuthenticator
) -> Principal:
    """Return the caller, answering 401 if they are not authenticated.

    In shadow mode an unauthenticated caller gets :data:`ANONYMOUS` instead.
    """
    principal = await _authenticate(request, authenticator, credentials, required=True)
    assert principal is not None
    return principal


async def optional_principal(
    request: fastapi.Request, credentials: Credentials, authenticator: RequestAuthenticator
) -> Principal | None:
    """Return the caller, or ``None`` if the request carries no token. An invalid token is still refused."""
    return await _authenticate(request, authenticator, credentials, required=False)


async def try_authenticate(
    request: fastapi.Request, *, authenticator: Authenticator | None = None
) -> Principal | None:
    """Return the caller, or ``None`` without a valid token, never refusing the request.

    For code that decides access itself, such as a GraphQL context.
    Failures, including a JWKS outage, still run the failure hooks and set ``x-auth-status``.
    With an ``authenticator_dependency`` configured, pass the request's ``authenticator``.
    """
    installed = _installed(request)
    if authenticator is None:
        if installed.config.authenticator_dependency is not None:
            raise RuntimeError("try_authenticate needs an authenticator when authenticator_dependency is set")
        authenticator = installed.authenticator
    credentials = await bearer_scheme(request)
    return await _authenticate(request, authenticator, credentials, required=False, refuse=False)


CurrentPrincipal = typing.Annotated[Principal, fastapi.Depends(require_principal)]
OptionalPrincipal = typing.Annotated[Principal | None, fastapi.Depends(optional_principal)]


def require_permission(*permissions: str) -> Callable[..., Awaitable[Principal]]:
    """Build a dependency that answers 403 unless the caller holds every one of ``permissions``.

    Use it as ``dependencies=[Depends(require_permission("ndc:commit"))]`` on a route or router,
    or as a parameter type to also receive the caller.
    ``AuthConfig.has_permission`` decides what the caller holds.
    """

    async def check_permissions(request: fastapi.Request, principal: CurrentPrincipal) -> Principal:
        has_permission = _installed(request).config.has_permission or Principal.has_permission
        missing = sorted(
            permission for permission in permissions if not has_permission(principal, permission)
        )
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
