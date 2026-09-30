import copy

import pytest

from cr_service.auth.testing import TokenFactory
from cr_service.flags import Flag, FlagKind, FlagSet
from cr_service.permissions import Permission, PermissionSet
from tests.declarations_example import ThingsFlags, ThingsPermissions


def test_flag_is_its_slug():
    flag = ThingsFlags.PUBLISH
    assert flag == "things:publish"
    assert flag.slug == "things:publish"
    assert type(flag.slug) is str
    assert flag in frozenset({"things:publish"})
    assert flag.requires is ThingsFlags.ACCESS
    assert repr(flag) == "Flag('things:publish', entitlement)"


def test_flag_set_collects_flags_and_tags():
    assert ThingsFlags.owner == "things"
    assert ThingsFlags.flags() == (ThingsFlags.ACCESS, ThingsFlags.PUBLISH, ThingsFlags.NEW_VIEW)
    assert ThingsFlags.tags_for(ThingsFlags.NEW_VIEW) == {"things", "kind:release"}
    assert FlagKind.OPS.tag == "kind:ops"


def test_declared_values_survive_copying():
    flag = copy.deepcopy(ThingsFlags.PUBLISH)
    assert (flag.slug, flag.kind, flag.name, flag.requires) == (
        "things:publish",
        FlagKind.ENTITLEMENT,
        "Publish Things",
        "app:things",
    )
    permission = copy.deepcopy(ThingsPermissions.WRITE)
    assert (permission.slug, permission.name, permission.description) == (
        "things:write",
        "Write things",
        "Create and edit things",
    )


def test_tokens_accept_declared_values():
    tokens = TokenFactory()
    assert tokens.user_token(feature_flags=[ThingsFlags.ACCESS], permissions=[ThingsPermissions.READ])


@pytest.mark.parametrize("slug", ["", "App:things", "app things", ":leading"])
def test_flag_rejects_bad_slugs(slug):
    with pytest.raises(ValueError, match="slug"):
        Flag(slug, FlagKind.RELEASE, "Bad")


def test_flag_cannot_require_itself():
    with pytest.raises(ValueError, match="require itself"):
        Flag("a", FlagKind.RELEASE, "A", requires=Flag("a", FlagKind.RELEASE, "A"))


def test_flag_set_rejects_bad_owner_and_duplicates():
    with pytest.raises(ValueError, match="owner"):

        class KindOwner(FlagSet, owner="kind:things"):
            pass

    with pytest.raises(ValueError, match="more than once"):

        class Twice(FlagSet, owner="twice"):
            A = Flag("a", FlagKind.OPS, "A")
            B = Flag("a", FlagKind.OPS, "B")


def test_permission_set_collects_permissions():
    assert ThingsPermissions.namespace == "things"
    assert ThingsPermissions.permissions() == ("things:read", "things:write")
    assert ThingsPermissions.owns("things:anything")
    assert not ThingsPermissions.owns("thingsx:read")
    assert repr(ThingsPermissions.READ) == "Permission('things:read')"


def test_permission_set_enforces_namespace():
    with pytest.raises(ValueError, match="must start with 'things:'"):

        class Stray(PermissionSet, namespace="things"):
            OTHER = Permission("other:read", "Read other")

    with pytest.raises(ValueError, match="namespace"):

        class Bad(PermissionSet, namespace="Things"):
            pass

    with pytest.raises(ValueError, match="more than once"):

        class Twice(PermissionSet, namespace="twice"):
            A = Permission("twice:a", "A")
            B = Permission("twice:a", "B")

    with pytest.raises(ValueError, match="slug"):
        Permission("things:Read", "Read")
