"""The outcome of one request's authentication, and how responses report it."""

import enum


class AuthOutcome(enum.StrEnum):
    """What an authentication attempt decided, as bound to ``auth_outcome``."""

    PASS = "pass"  # noqa: S105
    SKIPPED = "skipped"
    FAIL = "fail"
    SHADOW_FAIL = "shadow_fail"


# Shadow failures report as fail, so clients see the outcome enforcement would have given.
_HEADER_VALUES = {
    outcome.value: (AuthOutcome.FAIL if outcome is AuthOutcome.SHADOW_FAIL else outcome).encode()
    for outcome in AuthOutcome
}


def auth_status_header(outcome: str | None) -> bytes | None:
    """Return the ``x-auth-status`` value for a bound ``auth_outcome``, or ``None`` for no header."""
    return _HEADER_VALUES.get(outcome) if outcome is not None else None
