"""Feature flags declared in code.

A service lists the flags it checks on a :class:`FlagSet`,
and ``cr-service flags check`` compares the declaration with WorkOS::

    class BookshelfFlags(FlagSet, owner="bookshelf"):
        ACCESS = Flag("app:bookshelf", FlagKind.ENTITLEMENT, "Access Bookshelf")
        PUBLISH = Flag("bookshelf:publish", FlagKind.ENTITLEMENT, "Publish to Bookshelf", requires=ACCESS)

A :class:`Flag` is a ``str``,
so it goes wherever a slug does, such as :func:`cr_service.auth.require_feature_flag`.

WorkOS flags are defined once per project and tagged there.
Each declared flag carries two tags: its set's ``owner`` and ``kind:<kind>``.
The owner tag is how the check finds flags the code no longer declares.
"""

import enum
import re
import typing

_SLUG = re.compile(r"^[a-z0-9][a-z0-9:._-]*$")
_OWNER = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

KIND_TAG_PREFIX = "kind:"


class FlagKind(enum.StrEnum):
    """How long a flag lives and who flips it."""

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


class Flag(str):
    """A feature flag slug with what WorkOS should hold for it.

    Parameters
    ----------
    slug
        The WorkOS slug, such as ``app:bookshelf``.
    kind
        What sort of flag this is, which becomes the ``kind:`` tag.
    name
        Display name in the WorkOS dashboard.
    description
        What turning the flag on does.
    requires
        A flag an organisation must also have for this one to be useful,
        such as publishing requiring access.
    """

    kind: FlagKind
    name: str
    description: str | None
    requires: "Flag | None"

    def __new__(
        cls,
        slug: str,
        kind: FlagKind,
        name: str,
        description: str | None = None,
        *,
        requires: "Flag | None" = None,
    ) -> "Flag":
        """Validate and build the flag."""
        if not _SLUG.fullmatch(slug):
            raise ValueError(f"Feature flag slug {slug!r} must be lowercase letters, digits and ':._-'")
        if requires is not None and requires == slug:
            raise ValueError(f"Feature flag {slug!r} cannot require itself")
        flag = super().__new__(cls, slug)
        flag.kind = FlagKind(kind)
        flag.name = name
        flag.description = description or None
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
        """Pickle with the declared fields."""
        return (_rebuild_flag, (self.slug, self.kind, self.name, self.description, self.requires))


def _rebuild_flag(
    slug: str, kind: FlagKind, name: str, description: str | None, requires: Flag | None
) -> Flag:
    return Flag(slug, kind, name, description, requires=requires)


class FlagSet:
    """The flags one service owns, declared as class attributes.

    Subclass it with ``owner``, the WorkOS tag that marks a flag as this service's.
    """

    owner: typing.ClassVar[str]
    _flags: typing.ClassVar[tuple[Flag, ...]] = ()

    def __init_subclass__(cls, *, owner: str, **kwargs: typing.Any) -> None:
        """Collect the flags declared on the subclass."""
        super().__init_subclass__(**kwargs)
        if not _OWNER.fullmatch(owner) or owner.startswith(KIND_TAG_PREFIX):
            raise ValueError(f"FlagSet owner {owner!r} must be a lowercase tag such as 'bookshelf'")
        flags = [value for value in vars(cls).values() if isinstance(value, Flag)]
        duplicates = sorted({flag.slug for flag in flags if flags.count(flag) > 1})
        if duplicates:
            raise ValueError(f"{cls.__name__} declares {', '.join(duplicates)} more than once")
        cls.owner = owner
        cls._flags = tuple(flags)

    @classmethod
    def flags(cls) -> tuple[Flag, ...]:
        """Every flag the set declares, in declaration order."""
        return cls._flags

    @classmethod
    def tags_for(cls, flag: Flag) -> frozenset[str]:
        """Return the tags WorkOS should carry for ``flag``."""
        return frozenset({cls.owner, flag.kind.tag})
