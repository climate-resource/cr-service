"""RBAC permissions declared in code.

A service lists the permissions it guards on a :class:`PermissionSet`,
and ``cr-service permissions sync`` creates or updates them in WorkOS::

    class BookshelfPermissions(PermissionSet, namespace="bookshelf"):
        READ = Permission("bookshelf:read", "Read Bookshelf data")
        WRITE = Permission("bookshelf:write", "Write Bookshelf data")

A :class:`Permission` is a ``str``,
so it goes wherever a slug does, such as :func:`cr_service.auth.require_permission`.

Every slug starts with ``<namespace>:``.
The namespace is how the check finds permissions the code no longer declares.
Which roles grant a permission is not declared here:
roles span services and organisations, so the infrastructure repository binds them.
"""

import re
import typing

_SLUG = re.compile(r"^[a-z0-9][a-z0-9:._*-]*$")
_NAMESPACE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


class Permission(str):
    """A permission slug with the name and description WorkOS should hold for it."""

    name: str
    description: str | None

    def __new__(cls, slug: str, name: str, description: str | None = None) -> "Permission":
        """Validate and build the permission."""
        if not _SLUG.fullmatch(slug):
            raise ValueError(f"Permission slug {slug!r} must be lowercase letters, digits and ':._*-'")
        permission = super().__new__(cls, slug)
        permission.name = name
        permission.description = description or None
        return permission

    @property
    def slug(self) -> str:
        """The permission's slug as a plain string."""
        return str.__str__(self)

    def __repr__(self) -> str:
        """Show the slug."""
        return f"Permission({self.slug!r})"

    def __reduce__(self) -> tuple[typing.Any, ...]:
        """Pickle with the declared fields."""
        return (Permission, (self.slug, self.name, self.description))


class PermissionSet:
    """The permissions one service owns, declared as class attributes.

    Subclass it with ``namespace``, the prefix every slug in the set starts with.
    """

    namespace: typing.ClassVar[str]
    _permissions: typing.ClassVar[tuple[Permission, ...]] = ()

    def __init_subclass__(cls, *, namespace: str, **kwargs: typing.Any) -> None:
        """Collect the permissions declared on the subclass."""
        super().__init_subclass__(**kwargs)
        if not _NAMESPACE.fullmatch(namespace):
            raise ValueError(f"PermissionSet namespace {namespace!r} must be lowercase, such as 'bookshelf'")
        permissions = [value for value in vars(cls).values() if isinstance(value, Permission)]
        outside = sorted(p.slug for p in permissions if not p.slug.startswith(f"{namespace}:"))
        if outside:
            raise ValueError(
                f"{cls.__name__} slugs must start with {namespace + ':'!r}: {', '.join(outside)}"
            )
        duplicates = sorted({p.slug for p in permissions if permissions.count(p) > 1})
        if duplicates:
            raise ValueError(f"{cls.__name__} declares {', '.join(duplicates)} more than once")
        cls.namespace = namespace
        cls._permissions = tuple(permissions)

    @classmethod
    def permissions(cls) -> tuple[Permission, ...]:
        """Every permission the set declares, in declaration order."""
        return cls._permissions

    @classmethod
    def owns(cls, slug: str) -> bool:
        """Whether ``slug`` falls in this set's namespace."""
        return slug.startswith(f"{cls.namespace}:")
