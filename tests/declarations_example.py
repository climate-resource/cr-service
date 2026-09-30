"""Sets the CLI tests load by module reference."""

from cr_service.flags import Flag, FlagKind, FlagSet
from cr_service.permissions import Permission, PermissionSet


class ThingsFlags(FlagSet, owner="things"):
    ACCESS = Flag("app:things", FlagKind.ENTITLEMENT, "Access Things", "Shows Things")
    PUBLISH = Flag("things:publish", FlagKind.ENTITLEMENT, "Publish Things", requires=ACCESS)
    NEW_VIEW = Flag("release:things-view", FlagKind.RELEASE, "New view")


class ThingsPermissions(PermissionSet, namespace="things"):
    READ = Permission("things:read", "Read things")
    WRITE = Permission("things:write", "Write things", "Create and edit things")
