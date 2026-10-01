"""Feature flags a service relies on, declared in code.

The infrastructure repository is the source of truth for every flag:
its slug, name, description, owner and kind.
A service only declares the flags it checks and the kind it expects,
and warns when WorkOS does not match::

    class BookshelfFlags(FlagSet):
        ACCESS = Flag("app:bookshelf", FlagKind.ENTITLEMENT)
        PUBLISH = Flag("bookshelf:publish", FlagKind.ENTITLEMENT, requires=ACCESS)

A :class:`Flag` is a ``str``,
so it goes wherever a slug does, such as :func:`cr_service.auth.require_feature_flag`.
"""

import enum
import re
import typing

_SLUG = re.compile(r"^[a-z0-9][a-z0-9:._-]*$")

KIND_TAG_PREFIX = "kind:"


class FlagKind(enum.StrEnum):
    """How long a flag lives and who flips it. WorkOS records it as a ``kind:<kind>`` tag."""

    ENTITLEMENT = "entitlement"
    """What an organisation may use. Long-lived and targeted at organisations."""

    RELEASE = "release"
    """Rolls out a change. Removed from the code and WorkOS once the rollout finishes."""

    OPS = "ops"
    """Operational switch, such as turning off an expensive path."""

    @property
    def tag(self) -> str:
        """The WorkOS tag that marks a flag as this kind."""
        return f"{KIND_TAG_PREFIX}{self.value}"


def validate_flag_slug(slug: str) -> str:
    """Return ``slug``, raising :class:`ValueError` unless it is a valid flag slug."""
    if not _SLUG.fullmatch(slug):
        raise ValueError(f"Feature flag slug {slug!r} must be lowercase letters, digits and ':._-'")
    return slug


class Flag(str):
    """A feature flag slug with the kind the service expects.

    Parameters
    ----------
    slug
        The WorkOS slug, such as ``app:bookshelf``.
    kind
        The kind the service expects the registry to give it.
    requires
        A flag an organisation must also have for this one to be useful,
        such as publishing requiring access.
    """

    kind: FlagKind
    requires: "Flag | None"

    def __new__(cls, slug: str, kind: FlagKind, *, requires: "Flag | None" = None) -> "Flag":
        """Validate and build the flag."""
        validate_flag_slug(slug)
        if requires is not None and requires == slug:
            raise ValueError(f"Feature flag {slug!r} cannot require itself")
        flag = super().__new__(cls, slug)
        flag.kind = FlagKind(kind)
        flag.requires = requires
        return flag

    @property
    def slug(self) -> str:
        """The flag's slug as a plain string."""
        return str.__str__(self)

    def __repr__(self) -> str:
        """Show the slug and kind."""
        return f"Flag({self.slug!r}, {self.kind.value})"

    def __reduce__(self) -> tuple[typing.Any, ...]:
        """Copy and pickle with the declared fields."""
        return (_rebuild_flag, (self.slug, self.kind, self.requires))


def _rebuild_flag(slug: str, kind: FlagKind, requires: Flag | None) -> Flag:
    return Flag(slug, kind, requires=requires)


class FlagSet:
    """The flags one service checks, declared as class attributes."""

    _flags: typing.ClassVar[tuple[Flag, ...]] = ()

    def __init_subclass__(cls, **kwargs: typing.Any) -> None:
        """Collect the flags declared on the subclass."""
        super().__init_subclass__(**kwargs)
        flags = [value for value in vars(cls).values() if isinstance(value, Flag)]
        duplicates = sorted({flag.slug for flag in flags if flags.count(flag) > 1})
        if duplicates:
            raise ValueError(f"{cls.__name__} declares {', '.join(duplicates)} more than once")
        cls._flags = tuple(flags)

    @classmethod
    def flags(cls) -> tuple[Flag, ...]:
        """Every flag the set declares, in declaration order."""
        return cls._flags
