"""The feature flag registry kept in the infrastructure repository.

The registry is the source of truth for every WorkOS flag.
WorkOS cannot be configured from it, since its API cannot create flags or set their tags,
so ``cr-service flags check --registry`` reports what to change in the dashboard instead.
The file is TOML, one table per flag keyed by slug::

    [flags."app:bookshelf"]
    name = "Access Bookshelf"
    description = "Use Bookshelf at all"
    owner = "bookshelf"
    kind = "entitlement"
    requires = []            # optional, slugs this flag is useless without
"""

import dataclasses
import re
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cr_service.flags import KIND_TAG_PREFIX, FlagKind, validate_flag_slug

_OWNER = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


@dataclasses.dataclass(frozen=True, slots=True)
class RegisteredFlag:
    """One flag as the registry defines it."""

    slug: str
    name: str
    owner: str
    """Tag naming the service or product that owns the flag."""
    kind: FlagKind
    description: str | None = None
    requires: tuple[str, ...] = ()

    @property
    def tags(self) -> frozenset[str]:
        """The tags WorkOS should carry for this flag."""
        return frozenset({self.owner, self.kind.tag})


def parse_registry(data: Mapping[str, Any]) -> tuple[RegisteredFlag, ...]:
    """Build the flags from a parsed registry, raising :class:`ValueError` on anything malformed."""
    flags = data.get("flags")
    if not isinstance(flags, Mapping):
        raise ValueError("The registry needs a [flags] table")  # noqa: TRY004
    parsed = []
    for slug, entry in flags.items():
        if not isinstance(entry, Mapping):
            raise ValueError(f"Flag {slug!r} must be a table")  # noqa: TRY004
        unknown = sorted(set(entry) - {"name", "description", "owner", "kind", "requires"})
        if unknown:
            raise ValueError(f"Flag {slug!r} has unknown keys: {', '.join(unknown)}")
        for key in ("name", "owner", "kind"):
            if not isinstance(entry.get(key), str) or not entry[key]:
                raise ValueError(f"Flag {slug!r} needs a {key}")
        owner = entry["owner"]
        if not _OWNER.fullmatch(owner) or owner.startswith(KIND_TAG_PREFIX):
            raise ValueError(f"Flag {slug!r} owner {owner!r} must be a lowercase tag such as 'bookshelf'")
        try:
            kind = FlagKind(entry["kind"])
        except ValueError:
            kinds = ", ".join(kind.value for kind in FlagKind)
            raise ValueError(f"Flag {slug!r} kind must be one of {kinds}") from None
        requires = entry.get("requires", [])
        if not isinstance(requires, list) or not all(isinstance(item, str) for item in requires):
            raise ValueError(f"Flag {slug!r} requires must be a list of slugs")
        description = entry.get("description")
        if description is not None and not isinstance(description, str):
            raise ValueError(f"Flag {slug!r} description must be a string")
        parsed.append(
            RegisteredFlag(
                slug=validate_flag_slug(slug),
                name=entry["name"],
                owner=owner,
                kind=kind,
                description=description or None,
                requires=tuple(requires),
            )
        )
    slugs = {flag.slug for flag in parsed}
    for flag in parsed:
        if unknown_requires := sorted(set(flag.requires) - slugs):
            raise ValueError(f"Flag {flag.slug!r} requires unregistered {', '.join(unknown_requires)}")
    return tuple(parsed)


def load_registry(path: str | Path) -> tuple[RegisteredFlag, ...]:
    """Read and parse a registry file."""
    with Path(path).open("rb") as file:
        return parse_registry(tomllib.load(file))
