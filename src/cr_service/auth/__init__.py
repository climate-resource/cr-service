"""WorkOS authentication for Climate Resource services.

Everything a service needs is exported here.
The lower-level pieces (the verifier, key sources and WorkOS environments) stay importable from their modules.
"""

from cr_service.auth.authenticator import Authenticator, build_authenticator
from cr_service.auth.dependencies import (
    AuthConfig,
    CurrentPrincipal,
    OptionalPrincipal,
    require_feature_flag,
    require_permission,
)
from cr_service.auth.errors import (
    AuthConfigurationError,
    AuthenticationError,
    AuthError,
    AuthorizationError,
    AuthUnavailableError,
)
from cr_service.auth.hooks import FailureHook, SuccessHook
from cr_service.auth.principal import Principal

__all__ = [
    "AuthConfig",
    "AuthConfigurationError",
    "AuthError",
    "AuthUnavailableError",
    "AuthenticationError",
    "Authenticator",
    "AuthorizationError",
    "CurrentPrincipal",
    "FailureHook",
    "OptionalPrincipal",
    "Principal",
    "SuccessHook",
    "build_authenticator",
    "require_feature_flag",
    "require_permission",
]
