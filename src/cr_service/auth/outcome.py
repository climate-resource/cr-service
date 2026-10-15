"""The outcome of one request's authentication, and how responses report it."""

import enum


class AuthOutcome(enum.StrEnum):
    """What an authentication attempt decided, as bound to ``auth_outcome``."""

    PASS = "pass"  # noqa: S105
    SKIPPED = "skipped"
    FAIL = "fail"
    SHADOW_FAIL = "shadow_fail"

    @property
    def reported(self) -> "AuthOutcome":
        """The outcome clients see, which is the one enforcement would have given."""
        return AuthOutcome.FAIL if self is AuthOutcome.SHADOW_FAIL else self


def auth_status_header(outcome: str | None) -> bytes | None:
    """Return the ``x-auth-status`` value for a bound ``auth_outcome``, or ``None`` for no header."""
    if outcome is None or outcome not in AuthOutcome:
        return None
    return AuthOutcome(outcome).reported.value.encode()
