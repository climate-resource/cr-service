"""Sets the CLI tests load by module reference."""

from cr_service.flags import Flag, FlagKind, FlagSet
from cr_service.permissions import PermissionSet


class ThingsFlags(FlagSet):
    ACCESS = Flag("app:things", FlagKind.ENTITLEMENT)
    PUBLISH = Flag("things:publish", FlagKind.ENTITLEMENT, requires=ACCESS)
    NEW_VIEW = Flag("release:things-view", FlagKind.RELEASE)


class ThingsPermissions(PermissionSet):
    READ = "things:read"
    WRITE = "things:write"
