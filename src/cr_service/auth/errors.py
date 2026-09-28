"""Errors raised while authenticating or authorising a caller."""


class AuthError(Exception):
    """Base class, carrying the HTTP status the failure maps to."""

    status_code: int = 401


class AuthenticationError(AuthError):
    """The caller's credentials are missing or invalid."""

    status_code = 401

    def __init__(self, message: str, *, missing: bool = False) -> None:
        super().__init__(message)
        self.missing = missing


class AuthorizationError(AuthError):
    """The caller is known but not allowed to do this."""

    status_code = 403


class AuthUnavailableError(AuthError):
    """Credentials cannot be checked right now, for example because the JWKS cannot be fetched."""

    status_code = 503


class AuthConfigurationError(ValueError):
    """The auth settings cannot produce a working authenticator."""
