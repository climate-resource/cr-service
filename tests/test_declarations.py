import copy

import pytest

from cr_service.auth.testing import TokenFactory
from cr_service.flags import Flag, FlagKind, FlagSet
from cr_service.permissions import PermissionSet
from tests.declarations_example import ThingsFlags, ThingsPermissions


def test_flag_is_its_slug():
    flag = ThingsFlags.PUBLISH
    assert flag == "things:publish"
    assert flag.slug == "things:publish"
    assert type(flag.slug) is str
    assert flag in frozenset({"things:publish"})
    assert flag.requires is ThingsFlags.ACCESS
    assert repr(flag) == "Flag('things:publish', entitlement)"


def test_flag_set_collects_flags():
    assert ThingsFlags.flags() == (ThingsFlags.ACCESS, ThingsFlags.PUBLISH, ThingsFlags.NEW_VIEW)
    assert FlagKind.OPS.tag == "kind:ops"


def test_flags_survive_copying():
    flag = copy.deepcopy(ThingsFlags.PUBLISH)
    assert (flag.slug, flag.kind, flag.requires) == ("things:publish", FlagKind.ENTITLEMENT, "app:things")


def test_tokens_accept_declared_values():
    assert TokenFactory().user_token(feature_flags=[ThingsFlags.ACCESS], permissions=[ThingsPermissions.READ])


@pytest.mark.parametrize("slug", ["", "App:things", "app things", ":leading"])
def test_flag_rejects_bad_slugs(slug):
    with pytest.raises(ValueError, match="slug"):
        Flag(slug, FlagKind.RELEASE)


def test_flag_cannot_require_itself():
    with pytest.raises(ValueError, match="require itself"):
        Flag("a", FlagKind.RELEASE, requires=Flag("a", FlagKind.RELEASE))


def test_flag_set_rejects_duplicates():
    with pytest.raises(ValueError, match="more than once"):

        class Twice(FlagSet):
            A = Flag("a", FlagKind.OPS)
            B = Flag("a", FlagKind.OPS)


def test_permission_set_collects_public_strings():
    class Mixed(PermissionSet):
        READ = "mixed:read"
        _PRIVATE = "not:collected"
        COUNT = 3

    assert ThingsPermissions.permissions() == ("things:read", "things:write")
    assert Mixed.permissions() == ("mixed:read",)
    assert ThingsPermissions.READ == "things:read"


def test_permission_set_validates():
    with pytest.raises(ValueError, match="lowercase"):

        class Bad(PermissionSet):
            READ = "Things:Read"

    with pytest.raises(ValueError, match="more than once"):

        class Twice(PermissionSet):
            A = "twice:a"
            B = "twice:a"
