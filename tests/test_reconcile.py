import logging

import httpx

from cr_service.auth.workos_api import WorkOSClient
from cr_service.flags import Flag, FlagKind, FlagSet
from cr_service.reconcile import (
    check_flag_targeting,
    check_flag_targeting_remote,
    check_flags,
    check_flags_remote,
    check_permissions,
    check_registry,
    check_registry_remote,
    list_flags,
    requirements_of,
    warn_on_drift,
)
from tests.declarations_example import ThingsFlags, ThingsPermissions
from tests.test_registry import EXAMPLE, load_registry

REGISTRY = load_registry(EXAMPLE)


def remote_flag(slug, *tags, name=None, description=None, enabled=True):
    return {"slug": slug, "name": name, "description": description, "tags": list(tags), "enabled": enabled}


IN_SYNC = [
    remote_flag(
        "app:things", "things", "kind:entitlement", name="Access Things", description="Use Things at all"
    ),
    remote_flag("things:publish", "things", "kind:entitlement", name="Publish Things"),
    remote_flag("release:things-view", "things", "kind:release", name="New view", enabled=False),
]

PERMISSIONS = [
    {"slug": "things:read", "name": "Read things", "system": False},
    {"slug": "other:read", "name": "Other", "system": False},
    {"slug": "widgets:api-keys:manage", "name": "Widgets", "system": True},
]


def codes(findings):
    return sorted((finding.code, finding.slug) for finding in findings)


def test_declared_flags_in_sync():
    assert check_flags([ThingsFlags], IN_SYNC) == []


def test_declared_flag_missing_or_wrong_kind():
    remote = [
        remote_flag("app:things", "things"),
        remote_flag("things:publish", "kind:release", "kind:entitlement"),
    ]
    findings = check_flags([ThingsFlags], remote)
    assert codes(findings) == [
        ("kind", "app:things"),
        ("kind", "things:publish"),
        ("missing", "release:things-view"),
    ]
    assert findings[0].message == "the code expects kind:entitlement but WorkOS has no kind tag"


def test_required_flag_missing():
    class Needy(FlagSet):
        EXTRA = Flag("needy:extra", FlagKind.OPS, requires=Flag("needy:base", FlagKind.OPS))

    assert codes(check_flags([Needy], [remote_flag("needy:extra", "kind:ops")])) == [
        ("requires", "needy:extra")
    ]


def test_conflicting_declarations():
    class Other(FlagSet):
        ACCESS = Flag("app:things", FlagKind.RELEASE)

    assert ("conflict", "app:things") in codes(check_flags([ThingsFlags, Other], IN_SYNC))


def test_permissions():
    assert codes(check_permissions([ThingsPermissions], PERMISSIONS)) == [("missing", "things:write")]


def test_registry_in_sync_allows_extra_tags():
    remote = [dict(IN_SYNC[0], tags=["things", "kind:entitlement", "app"]), *IN_SYNC[1:]]
    assert check_registry(REGISTRY, remote) == []


def test_registry_differences():
    remote = [
        remote_flag("app:things", "kind:release", name="Access Things", description="Use Things at all"),
        dict(IN_SYNC[1], name="Old name"),
        remote_flag("stray"),
    ]
    findings = {finding.slug: finding for finding in check_registry(REGISTRY, remote)}
    assert findings["app:things"].fix == "In the dashboard, add kind:entitlement, things; remove kind:release"
    assert findings["things:publish"].code == "details"
    assert findings["release:things-view"].fix == (
        "Create it in the WorkOS dashboard with slug 'release:things-view'; name 'New view'; "
        "tags kind:release, things"
    )
    assert (findings["stray"].level, findings["stray"].code) == ("warning", "unregistered")


def test_requirements_and_targeting():
    class Extra(FlagSet):
        BETA = Flag("things:beta", FlagKind.RELEASE, requires=ThingsFlags.PUBLISH)

    assert requirements_of([ThingsFlags, Extra], REGISTRY) == {
        "things:publish": ("app:things",),
        "things:beta": ("things:publish",),
    }
    served = {"org_ok": ["app:things", "things:publish"], "org_bad": ["things:publish"], "org_none": []}
    [finding] = check_flag_targeting({"things:publish": ["app:things"]}, served, {"org_bad": "Bad Org"})
    assert (finding.code, finding.slug) == ("targeting", "things:publish")
    assert "Bad Org (org_bad)" in finding.message


def test_list_flags_statuses():
    remote = [
        dict(IN_SYNC[0], tags=["kind:entitlement"]),
        IN_SYNC[2],
        remote_flag("legacy", "kind:ops"),
    ]
    rows = {row.slug: row for row in list_flags(remote, [ThingsFlags], REGISTRY)}
    assert {slug: row.status for slug, row in rows.items()} == {
        "app:things": "drift",
        "release:things-view": "ok",
        "legacy": "unregistered",
        "things:publish": "missing",
    }
    assert (rows["legacy"].kind, rows["legacy"].owner) == ("ops", None)
    assert (rows["things:publish"].owner, rows["things:publish"].enabled) == ("things", None)
    assert rows["release:things-view"].enabled is False

    rows = {row.slug: row for row in list_flags(remote, [ThingsFlags])}
    assert rows["legacy"].status == "-"
    assert rows["things:publish"].owner is None


class FakeWorkOS:
    """Serves the list endpoints from memory and refuses writes."""

    def __init__(self, flags=(), permissions=(), organizations=(), served=None, status=200):
        self.flags = list(flags)
        self.permissions = list(permissions)
        self.organizations = list(organizations)
        self.served = served or {}
        self.status = status

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.method == "GET", "cr-service must only read WorkOS"
        if self.status != 200:
            return httpx.Response(self.status, text="nope")
        path = request.url.path
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
    fake = FakeWorkOS(flags=IN_SYNC, organizations=[{"id": "org_1"}], served={"org_1": ["things:publish"]})
    async with fake.client() as client:
        assert await check_flags_remote(client, ThingsFlags) == []
        assert await check_registry_remote(client, REGISTRY) == []
        [finding] = await check_flag_targeting_remote(client, requirements_of([ThingsFlags]))
        assert "org_1 (org_1)" in finding.message
        assert await check_flag_targeting_remote(client, {}) == []


async def test_warn_on_drift_logs_each_finding(caplog):
    fake = FakeWorkOS(flags=IN_SYNC[:2], permissions=PERMISSIONS)
    with caplog.at_level(logging.WARNING, logger="cr_service.reconcile"):
        async with fake.client() as client:
            findings = await warn_on_drift(client, flags=[ThingsFlags], permissions=[ThingsPermissions])
    assert codes(findings) == [("missing", "release:things-view"), ("missing", "things:write")]
    assert [record.workos_slug for record in caplog.records] == ["release:things-view", "things:write"]
    assert caplog.records[0].workos_drift == "missing"


async def test_warn_on_drift_never_raises(caplog):
    with caplog.at_level(logging.WARNING, logger="cr_service.reconcile"):
        async with FakeWorkOS(status=500).client() as client:
            assert await warn_on_drift(client, flags=[ThingsFlags]) == []
        async with FakeWorkOS().client() as client:
            assert await warn_on_drift(client) == []
    assert caplog.records[0].getMessage() == "Could not compare flags and permissions with WorkOS"
