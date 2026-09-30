import httpx

from cr_service.auth.workos_api import WorkOSClient
from cr_service.flags import Flag, FlagKind, FlagSet
from cr_service.permissions import Permission, PermissionSet
from cr_service.reconcile import (
    check_flag_targeting,
    check_flag_targeting_remote,
    check_flags,
    check_flags_remote,
    check_permissions_remote,
    list_flags,
    plan_permissions,
    sync_permissions,
)
from tests.declarations_example import ThingsFlags, ThingsPermissions


def remote_flag(slug, *tags, name=None, description=None, enabled=True):
    return {"slug": slug, "name": name, "description": description, "tags": list(tags), "enabled": enabled}


IN_SYNC = [
    remote_flag("app:things", "things", "kind:entitlement", name="Access Things", description="Shows Things"),
    remote_flag("things:publish", "things", "kind:entitlement", name="Publish Things"),
    remote_flag("release:things-view", "things", "kind:release", name="New view", enabled=False),
]


def codes(findings):
    return sorted((finding.code, finding.slug) for finding in findings)


def test_flags_in_sync_have_no_findings():
    assert check_flags([ThingsFlags], IN_SYNC) == []


def test_extra_tags_other_than_kinds_are_allowed():
    remote = [dict(IN_SYNC[0], tags=["things", "kind:entitlement", "app"]), *IN_SYNC[1:]]
    assert check_flags([ThingsFlags], remote) == []


def test_missing_flag_says_how_to_create_it():
    [finding] = check_flags([ThingsFlags], IN_SYNC[1:])
    assert (finding.level, finding.code, finding.slug) == ("error", "missing", "app:things")
    assert finding.fix == (
        "Create it in the WorkOS dashboard with slug 'app:things'; name 'Access Things'; "
        "description 'Shows Things'; tags kind:entitlement, things"
    )


def test_wrong_tags():
    remote = [
        remote_flag("app:things", "kind:release", name="Access Things", description="Shows Things"),
        *IN_SYNC[1:],
    ]
    [finding] = check_flags([ThingsFlags], remote)
    assert (finding.code, finding.slug) == ("tags", "app:things")
    assert finding.fix == "In the dashboard, add kind:entitlement, things; remove kind:release"


def test_changed_name_is_a_warning():
    remote = [dict(IN_SYNC[0], name="Old name"), *IN_SYNC[1:]]
    [finding] = check_flags([ThingsFlags], remote)
    assert (finding.level, finding.code) == ("warning", "details")


def test_undeclared_flag_with_owner_tag():
    remote = [*IN_SYNC, remote_flag("things:old", "things", "kind:release"), remote_flag("other", "other")]
    [finding] = check_flags([ThingsFlags], remote)
    assert (finding.level, finding.code, finding.slug) == ("warning", "undeclared", "things:old")


def test_required_flag_outside_the_sets():
    access = Flag("app:elsewhere", FlagKind.ENTITLEMENT, "Elsewhere")

    class Needy(FlagSet, owner="needy"):
        EXTRA = Flag("needy:extra", FlagKind.ENTITLEMENT, "Extra", requires=access)

    remote = [remote_flag("needy:extra", "needy", "kind:entitlement", name="Extra")]
    assert codes(check_flags([Needy], remote)) == [("requires", "needy:extra")]
    assert check_flags([Needy], [*remote, remote_flag("app:elsewhere")]) == []


def test_same_slug_with_two_owners_conflicts():
    class Other(FlagSet, owner="other"):
        ACCESS = Flag("app:things", FlagKind.ENTITLEMENT, "Access Things", "Shows Things")

    assert ("conflict", "app:things") in codes(check_flags([ThingsFlags, Other], IN_SYNC))


def test_targeting_reports_organisations_missing_the_required_flag():
    served = {"org_ok": ["app:things", "things:publish"], "org_bad": ["things:publish"], "org_none": []}
    [finding] = check_flag_targeting([ThingsFlags], served, {"org_bad": "Bad Org"})
    assert (finding.code, finding.slug) == ("targeting", "things:publish")
    assert "Bad Org (org_bad)" in finding.message


def test_list_flags_statuses():
    remote = [
        dict(IN_SYNC[0], tags=["kind:entitlement"]),
        IN_SYNC[2],
        remote_flag("things:old", "things", "kind:ops"),
        remote_flag("unowned"),
    ]
    rows = {row.slug: row for row in list_flags([ThingsFlags], remote)}
    assert {slug: row.status for slug, row in rows.items()} == {
        "app:things": "drift",
        "release:things-view": "ok",
        "things:old": "undeclared",
        "unowned": "-",
        "things:publish": "missing",
    }
    assert rows["things:old"].kind == "ops"
    assert rows["things:old"].owner is None
    assert rows["things:publish"].enabled is None
    assert rows["release:things-view"].enabled is False


REMOTE_PERMISSIONS = [
    {"slug": "things:read", "name": "Read things", "description": None, "system": False},
    {"slug": "things:write", "name": "Old", "description": None, "system": False},
    {"slug": "things:legacy", "name": "Legacy", "description": None, "system": False},
    {"slug": "other:read", "name": "Other", "description": None, "system": False},
    {"slug": "widgets:api-keys:manage", "name": "Widgets", "description": None, "system": True},
]


def test_plan_permissions():
    changes, findings = plan_permissions([ThingsPermissions], REMOTE_PERMISSIONS)
    assert [(change.action, change.permission.slug) for change in changes] == [("update", "things:write")]
    assert codes(findings) == [("undeclared", "things:legacy")]

    changes, findings = plan_permissions([ThingsPermissions], [])
    assert [(change.action, change.permission.slug) for change in changes] == [
        ("create", "things:read"),
        ("create", "things:write"),
    ]
    assert findings == []


def test_plan_permissions_refuses_system_and_conflicting_declarations():
    class Widgets(PermissionSet, namespace="widgets"):
        MANAGE = Permission("widgets:api-keys:manage", "Widgets")

    class Again(PermissionSet, namespace="things"):
        READ = Permission("things:read", "Another name")

    _changes, findings = plan_permissions([Widgets, ThingsPermissions, Again], REMOTE_PERMISSIONS)
    assert ("system", "widgets:api-keys:manage") in codes(findings)
    assert ("conflict", "things:read") in codes(findings)


class FakeWorkOS:
    """Serves the list endpoints from memory and records writes."""

    def __init__(self, flags=(), permissions=(), organizations=(), served=None):
        self.flags = list(flags)
        self.permissions = list(permissions)
        self.organizations = list(organizations)
        self.served = served or {}
        self.writes: list[tuple[str, str, bytes]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method != "GET":
            self.writes.append((request.method, path, request.content))
            return httpx.Response(200, json={})
        if path == "/feature-flags":
            data = self.flags
        elif path == "/authorization/permissions":
            data = self.permissions
        elif path == "/organizations":
            data = self.organizations
        elif path.startswith("/organizations/") and path.endswith("/feature-flags"):
            data = [{"slug": slug} for slug in self.served[path.split("/")[2]]]
        else:
            return httpx.Response(404)
        return httpx.Response(200, json={"data": data, "list_metadata": {"after": None}})

    def client(self) -> WorkOSClient:
        return WorkOSClient("sk_test", transport=httpx.MockTransport(self))


async def test_remote_checks():
    fake = FakeWorkOS(
        flags=IN_SYNC,
        permissions=REMOTE_PERMISSIONS,
        organizations=[{"id": "org_1", "name": "One"}],
        served={"org_1": ["things:publish"]},
    )
    async with fake.client() as client:
        assert await check_flags_remote(client, ThingsFlags) == []
        assert codes(await check_flag_targeting_remote(client, ThingsFlags)) == [
            ("targeting", "things:publish")
        ]
        assert codes(await check_permissions_remote(client, ThingsPermissions)) == [
            ("outdated", "things:write"),
            ("undeclared", "things:legacy"),
        ]


async def test_targeting_skips_sets_without_requirements():
    class Plain(FlagSet, owner="plain"):
        A = Flag("plain:a", FlagKind.OPS, "A")

    fake = FakeWorkOS()
    async with fake.client() as client:
        assert await check_flag_targeting_remote(client, Plain) == []


async def test_sync_permissions_creates_and_updates():
    fake = FakeWorkOS(permissions=REMOTE_PERMISSIONS[1:2])
    async with fake.client() as client:
        changes, _ = await sync_permissions(client, ThingsPermissions, dry_run=True)
        assert len(changes) == 2
        assert fake.writes == []
        await sync_permissions(client, ThingsPermissions)
    assert fake.writes == [
        (
            "POST",
            "/authorization/permissions",
            b'{"slug":"things:read","name":"Read things","resource_type_slug":"organization"}',
        ),
        (
            "PATCH",
            "/authorization/permissions/things:write",
            b'{"name":"Write things","description":"Create and edit things"}',
        ),
    ]
