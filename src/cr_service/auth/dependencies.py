"""FastAPI dependencies that authenticate and authorise the caller."""

import dataclasses
import functools
import logging
import typing
from collections.abc import Awaitable, Callable, Sequence

import fastapi
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from cr_service import context
from cr_service.auth.authenticator import Authenticator, build_authenticator
from cr_service.auth.errors import AuthenticationError, AuthError, AuthorizationError
from cr_service.auth.hooks import FailureHook, SuccessHook, log_auth_failure, observe_principal
from cr_service.auth.outcome import AuthOutcome
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

    has_permission: PermissionCheck = Principal.has_permission
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


def installed_config(app: fastapi.FastAPI) -> AuthConfig | None:
    """Return the config :func:`install_auth` installed on ``app``, or ``None`` before it runs."""
    installed = getattr(app.state, "cr_service_auth", None)
    return typing.cast(_InstalledAuth, installed).config if installed is not None else None


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


def _default_authenticator(request: fastapi.Request) -> Authenticator:
    installed = _installed(request)
    if installed.config.authenticator_dependency is not None:
        raise RuntimeError(
            "The app authenticator is not used when authenticator_dependency is set, "
            "check app.dependency_overrides or pass try_authenticate an authenticator"
        )
    return installed.authenticator


async def _request_authenticator(request: fastapi.Request) -> Authenticator:
    # install_auth overrides this with AuthConfig.authenticator_dependency.
    return _default_authenticator(request)


@dataclasses.dataclass(frozen=True, slots=True)
class AuthAttempt:
    """What one authentication attempt decided for a request.

    ``outcome`` is ``None`` when nothing was recorded, such as a missing token on an optional route.
    """

    principal: Principal | None = None
    outcome: AuthOutcome | None = None
    error: AuthError | None = None
    refusal: Callable[[], fastapi.HTTPException] | None = None
    """Builds the response to raise, set only when the failure is enforced."""

    @property
    def enforced(self) -> bool:
        """Whether the request must be refused."""
        return self.refusal is not None

    def enforce(self) -> Principal | None:
        """Raise the refusal if the failure is enforced, otherwise return the principal."""
        if self.refusal is not None:
            raise self.refusal()
        return self.principal


async def authenticate_request(
    request: fastapi.Request, authenticator: Authenticator, token: str | None, *, allow_missing: bool = False
) -> AuthAttempt:
    """Authenticate the caller once per request, run ``request_checks`` every time and record the outcome.

    With ``allow_missing``, a request without a token gets an empty attempt and records nothing.
    """
    installed = _installed(request)
    state = getattr(request.state, "principal", None)
    cached = state if isinstance(state, Principal) else None
    try:
        principal = cached if cached is not None else await authenticator.authenticate(token)
        # Checked on every call, so a principal cached by any means cannot skip them.
        for check in installed.config.request_checks:
            check(request, principal)
    except AuthError as error:
        if allow_missing and isinstance(error, AuthenticationError) and error.missing:
            return AuthAttempt()
        return _fail(request, installed, error)

    outcome = AuthOutcome.SKIPPED if principal.credential == "none" else AuthOutcome.PASS
    if principal is not cached:
        _record(request, outcome)
        for hook in (observe_principal, *installed.config.on_success):
            hook(request, principal)
        request.state.principal = principal
    return AuthAttempt(principal=principal, outcome=outcome)


def refuse_request(request: fastapi.Request, error: AuthError) -> AuthAttempt:
    """Record a failure decided outside the authenticator, such as a missing permission."""
    return _fail(request, _installed(request), error)


def _fail(request: fastapi.Request, installed: _InstalledAuth, error: AuthError) -> AuthAttempt:
    # Shadow mode only lets unauthenticated callers through, never unauthorised ones.
    enforced = installed.enforce or isinstance(error, AuthorizationError)
    outcome = AuthOutcome.FAIL if enforced else AuthOutcome.SHADOW_FAIL
    _record(request, outcome)
    for hook in (log_auth_failure, *installed.config.on_failure):
        hook(request, error)
    refusal = functools.partial(_http_error, request, installed.config, error) if enforced else None
    return AuthAttempt(outcome=outcome, error=error, refusal=refusal)


def _record(request: fastapi.Request, outcome: AuthOutcome) -> None:
    # Bound as the plain string so text logs and request.state keep the same values.
    context.bind(auth_outcome=outcome.value)
    request.state.auth_outcome = outcome.value


def _http_error(request: fastapi.Request, config: AuthConfig, error: AuthError) -> fastapi.HTTPException:
    headers: dict[str, str] | None = None
    if isinstance(error, AuthenticationError):
        params = [] if error.missing else ['error="invalid_token"']
        url = config.resource_metadata_url
        if callable(url):
            url = url(request)
        if url:
            params.append(f'resource_metadata="{url}"')
        headers = {"WWW-Authenticate": " ".join(["Bearer", ", ".join(params)]).strip()}
    return fastapi.HTTPException(status_code=error.status_code, detail=str(error), headers=headers)


RequestAuthenticator = typing.Annotated[Authenticator, fastapi.Depends(_request_authenticator)]
Credentials = typing.Annotated[HTTPAuthorizationCredentials | None, fastapi.Security(bearer_scheme)]


def _token(credentials: HTTPAuthorizationCredentials | None) -> str | None:
    return credentials.credentials if credentials else None


async def require_principal(
    request: fastapi.Request, credentials: Credentials, authenticator: RequestAuthenticator
) -> Principal:
    """Return the caller, answering 401 if they are not authenticated.

    In shadow mode an unauthenticated caller gets :data:`ANONYMOUS` instead.
    """
    attempt = await authenticate_request(request, authenticator, _token(credentials))
    return attempt.enforce() or ANONYMOUS


async def optional_principal(
    request: fastapi.Request, credentials: Credentials, authenticator: RequestAuthenticator
) -> Principal | None:
    """Return the caller, or ``None`` if the request carries no token. An invalid token is still refused."""
    attempt = await authenticate_request(request, authenticator, _token(credentials), allow_missing=True)
    return attempt.enforce()


async def try_authenticate(
    request: fastapi.Request, *, authenticator: Authenticator | None = None
) -> Principal | None:
    """Return the caller, or ``None`` without a valid token, never refusing the request.

    For code that decides access itself, such as a GraphQL context.
    Failures, including a JWKS outage, still run the failure hooks and set ``x-auth-status``.
    With an ``authenticator_dependency`` configured, pass the request's ``authenticator``.
    """
    if authenticator is None:
        authenticator = _default_authenticator(request)
    credentials = await bearer_scheme(request)
    attempt = await authenticate_request(request, authenticator, _token(credentials), allow_missing=True)
    return attempt.principal


CurrentPrincipal = typing.Annotated[Principal, fastapi.Depends(require_principal)]
OptionalPrincipal = typing.Annotated[Principal | None, fastapi.Depends(optional_principal)]


def require_permission(*permissions: str) -> Callable[..., Awaitable[Principal]]:
    """Build a dependency that answers 403 unless the caller holds every one of ``permissions``.

    Use it as ``dependencies=[Depends(require_permission("ndc:commit"))]`` on a route or router,
    or as a parameter type to also receive the caller.
    ``AuthConfig.has_permission`` decides what the caller holds.
    """

    async def check_permissions(request: fastapi.Request, principal: CurrentPrincipal) -> Principal:
        has_permission = _installed(request).config.has_permission
        missing = sorted(
            permission for permission in permissions if not has_permission(principal, permission)
        )
        if missing:
            refuse_request(request, AuthorizationError(f"Missing permission: {', '.join(missing)}")).enforce()
        return principal

    return check_permissions


def require_feature_flag(flag: str) -> Callable[..., Awaitable[Principal]]:
    """Build a dependency that answers 403 unless the caller's organisation has ``flag``."""

    async def check_feature_flag(request: fastapi.Request, principal: CurrentPrincipal) -> Principal:
        if not principal.has_feature_flag(flag):
            refuse_request(request, AuthorizationError(f"Missing feature flag: {flag}")).enforce()
        return principal

    return check_feature_flag
