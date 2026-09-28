"""The authenticated caller."""

import dataclasses
import typing
from collections.abc import Mapping

PrincipalKind = typing.Literal["user", "machine", "local", "anonymous"]


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Principal:
    """Who is calling, and what they may do.

    ``kind`` is ``user`` for a person signed in through WorkOS,
    ``machine`` for a client-credentials application,
    ``local`` for the fixed identity used when ``AUTH_PROVIDER`` is ``local`` or ``fake``,
    and ``anonymous`` for a caller let through by shadow mode.
    """

    kind: PrincipalKind
    id: str
    """WorkOS user id, or the machine application's client id."""

    organization_id: str | None = None
    permissions: frozenset[str] = frozenset()
    feature_flags: frozenset[str] = frozenset()
    role: str | None = None
    roles: tuple[str, ...] = ()
    email: str | None = None
    email_verified: bool = False
    first_name: str | None = None
    last_name: str | None = None
    organization_name: str | None = None
    client_id: str | None = None
    """Application the token was minted for."""

    session_id: str | None = None
    token_id: str | None = None
    claims: Mapping[str, typing.Any] = dataclasses.field(default_factory=dict, repr=False, compare=False)
    """Every verified claim, for anything the typed fields do not cover."""

    @property
    def is_authenticated(self) -> bool:
        """Whether the caller proved an identity."""
        return self.kind != "anonymous"

    @property
    def display_name(self) -> str | None:
        """First and last name, if the token carries either."""
        name = " ".join(part for part in (self.first_name, self.last_name) if part)
        return name or None

    def has_permission(self, permission: str) -> bool:
        """Whether the caller holds ``permission``. Guard on permissions, never on role names."""
        return permission in self.permissions

    def has_feature_flag(self, flag: str) -> bool:
        """Whether ``flag`` is enabled for the caller's organisation."""
        return flag in self.feature_flags


ANONYMOUS = Principal(kind="anonymous", id="anonymous")
