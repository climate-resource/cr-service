"""What happens after each authentication attempt, beyond answering the request."""

import logging
from collections.abc import Callable

import fastapi
import sentry_sdk

from cr_service import context
from cr_service.auth.errors import AuthError
from cr_service.auth.principal import Principal
from cr_service.tracing import set_span_attributes

logger = logging.getLogger("cr_service.auth")

SuccessHook = Callable[[fastapi.Request, Principal], None]
FailureHook = Callable[[fastapi.Request, AuthError], None]


def observe_principal(request: fastapi.Request, principal: Principal) -> None:
    """Attach the caller's ids, never their email or name, to the log context, Sentry and the span."""
    context.bind(
        user_id=principal.id,
        organization_id=principal.organization_id,
        auth_kind=principal.kind,
        auth_client_id=principal.client_id,
        auth_credential=principal.credential,
    )
    sentry_sdk.set_user({"id": principal.id})
    if principal.organization_id:
        sentry_sdk.set_tag("organization_id", principal.organization_id)
    set_span_attributes(**{"enduser.id": principal.id, "enduser.organization_id": principal.organization_id})


def log_auth_failure(request: fastapi.Request, error: AuthError) -> None:
    """Log why a caller was refused."""
    context.bind(auth_error=type(error).__name__)
    logger.info(
        "auth_failed",
        extra={"auth_error": type(error).__name__, "auth_reason": str(error), "status": error.status_code},
    )
