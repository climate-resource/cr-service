"""RBAC permissions a service relies on, declared in code.

The infrastructure repository creates every permission and binds it to roles.
A service only declares the slugs it guards, and warns when WorkOS lacks one::

    class BookshelfPermissions(PermissionSet):
        READ = "bookshelf:read"
        WRITE = "bookshelf:write"

The attributes stay plain strings,
so they go wherever a slug does, such as :func:`cr_service.auth.require_permission`.
"""

import re
import typing

_SLUG = re.compile(r"^[a-z0-9][a-z0-9:._*-]*$")


class PermissionSet:
    """The permissions one service guards, declared as public ``str`` class attributes."""

    _permissions: typing.ClassVar[tuple[str, ...]] = ()

    def __init_subclass__(cls, **kwargs: typing.Any) -> None:
        """Collect and validate the permissions declared on the subclass."""
        super().__init_subclass__(**kwargs)
        permissions = [
            value for name, value in vars(cls).items() if not name.startswith("_") and isinstance(value, str)
        ]
        invalid = sorted(slug for slug in permissions if not _SLUG.fullmatch(slug))
        if invalid:
            raise ValueError(
                f"{cls.__name__} permission slugs must be lowercase letters, digits and ':._*-': "
                f"{', '.join(invalid)}"
            )
        duplicates = sorted({slug for slug in permissions if permissions.count(slug) > 1})
        if duplicates:
            raise ValueError(f"{cls.__name__} declares {', '.join(duplicates)} more than once")
        cls._permissions = tuple(permissions)

    @classmethod
    def permissions(cls) -> tuple[str, ...]:
        """Every permission the set declares, in declaration order."""
        return cls._permissions
