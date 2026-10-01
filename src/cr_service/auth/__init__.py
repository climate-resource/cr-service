"""WorkOS authentication for Climate Resource services.

Everything a service needs is exported here.
The lower-level pieces (the verifier, key sources and WorkOS environments) stay importable from their modules.
"""

from cr_service.auth.authenticator import Authenticator, build_authenticator, clear_auth_caches
from cr_service.auth.dependencies import (
    AuthConfig,
    CurrentPrincipal,
    OptionalPrincipal,
    PermissionCheck,
    RequestCheck,
    base_authenticator,
    install_auth,
    require_feature_flag,
    require_permission,
    try_authenticate,
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
    "PermissionCheck",
    "Principal",
    "RequestCheck",
    "SuccessHook",
    "base_authenticator",
    "build_authenticator",
    "clear_auth_caches",
    "install_auth",
    "require_feature_flag",
    "require_permission",
    "try_authenticate",
]
