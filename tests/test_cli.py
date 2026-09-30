import json

import httpx
import pytest

from cr_service import cli
from cr_service.flags import FlagSet
from cr_service.permissions import PermissionSet
from tests.declarations_example import ThingsFlags, ThingsPermissions
from tests.test_reconcile import IN_SYNC, REMOTE_PERMISSIONS, FakeWorkOS, remote_flag

MODULE = "tests.declarations_example"


@pytest.fixture
def workos(monkeypatch):
    fake = FakeWorkOS(flags=IN_SYNC, permissions=REMOTE_PERMISSIONS)
    monkeypatch.setattr(cli, "_client", fake.client)
    return fake


def test_load_sets_by_module_and_class():
    assert cli.load_sets([MODULE], FlagSet) == [ThingsFlags]
    assert cli.load_sets([f"{MODULE}:ThingsPermissions", MODULE], PermissionSet) == [ThingsPermissions]


@pytest.mark.parametrize(
    ("reference", "message"),
    [
        ("tests.no_such_module", "Cannot import"),
        (f"{MODULE}:ThingsPermissions", "not a FlagSet"),
        ("tests.conftest", "defines no FlagSet"),
    ],
)
def test_load_sets_errors(reference, message):
    with pytest.raises(cli.UsageError, match=message):
        cli.load_sets([reference], FlagSet)


def test_missing_api_key(capsys):
    assert cli.main(["flags", "check", MODULE]) == 2
    assert "WORKOS_API_KEY" in capsys.readouterr().err


def test_client_reads_api_key(monkeypatch):
    monkeypatch.setenv("WORKOS_API_KEY", "sk_test")
    assert isinstance(cli._client(), cli.WorkOSClient)


def test_flags_list(workos, capsys):
    workos.flags = [*IN_SYNC[1:], remote_flag("other", "other")]
    assert cli.main(["flags", "list", MODULE]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["SLUG", "STATUS", "KIND", "OWNER", "ENABLED", "TAGS"]
    assert lines[1].split() == ["other", "-", "-", "-", "on", "other"]
    assert lines[-1].split() == ["app:things", "missing", "entitlement", "things", "-", "-"]


def test_flags_list_without_declarations_filtered_by_owner(workos, capsys):
    workos.flags = [*IN_SYNC, remote_flag("other", "other")]
    assert cli.main(["flags", "list", "--owner", "other", "--json"]) == 0
    assert [row["slug"] for row in json.loads(capsys.readouterr().out)] == ["other"]
    assert cli.main(["flags", "list", "--owner", "nobody"]) == 0
    assert capsys.readouterr().out == "No flags.\n"


def test_flags_check(workos, capsys):
    assert cli.main(["flags", "check", MODULE]) == 0
    assert capsys.readouterr().out == "No differences.\n"

    workos.flags = [*IN_SYNC[1:], remote_flag("things:old", "things")]
    assert cli.main(["flags", "check", MODULE]) == 1
    out = capsys.readouterr().out
    assert out.index("ERROR   app:things: missing from WorkOS") < out.index("WARNING things:old")
    assert "Create it in the WorkOS dashboard" in out


def test_flags_check_strict_and_targeting(workos, capsys):
    workos.flags = [*IN_SYNC, remote_flag("things:old", "things")]
    assert cli.main(["flags", "check", MODULE]) == 0
    assert cli.main(["flags", "check", MODULE, "--strict"]) == 1
    capsys.readouterr()

    workos.flags = IN_SYNC
    workos.organizations = [{"id": "org_1", "name": "One"}]
    workos.served = {"org_1": ["things:publish"]}
    assert cli.main(["flags", "check", MODULE, "--targeting", "--json"]) == 0
    [finding] = json.loads(capsys.readouterr().out)
    assert finding["code"] == "targeting"


def test_permissions_list(workos, capsys):
    assert cli.main(["permissions", "list", MODULE]) == 0
    rows = [line.split()[:2] for line in capsys.readouterr().out.splitlines()]
    assert rows == [
        ["SLUG", "STATUS"],
        ["things:legacy", "undeclared"],
        ["things:read", "ok"],
        ["things:write", "outdated"],
    ]

    workos.permissions = REMOTE_PERMISSIONS[3:]
    assert cli.main(["permissions", "list", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == [
        {"slug": "other:read", "status": "-", "name": "Other"},
        {"slug": "widgets:api-keys:manage", "status": "system", "name": "Widgets"},
    ]
    workos.permissions = []
    assert cli.main(["permissions", "list"]) == 0
    assert capsys.readouterr().out == "No permissions.\n"
    assert cli.main(["permissions", "list", MODULE]) == 0
    assert "missing" in capsys.readouterr().out


def test_permissions_check_and_sync(workos, capsys):
    assert cli.main(["permissions", "check", MODULE]) == 1
    assert "ERROR   things:write: name or description differs" in capsys.readouterr().out

    assert cli.main(["permissions", "sync", MODULE, "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "Would update things:write (Write things)" in out
    assert "WARNING things:legacy" in out
    assert workos.writes == []

    assert cli.main(["permissions", "sync", MODULE, "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["changes"] == [{"action": "update", "slug": "things:write"}]
    assert len(workos.writes) == 1

    workos.permissions = [
        {"slug": "things:read", "name": "Read things", "description": None},
        {"slug": "things:write", "name": "Write things", "description": "Create and edit things"},
    ]
    assert cli.main(["permissions", "sync", MODULE]) == 0
    assert capsys.readouterr().out == "Permissions are up to date.\n"
    workos.permissions = []
    assert cli.main(["permissions", "sync", MODULE]) == 0
    assert "Created things:read (Read things)" in capsys.readouterr().out


def test_workos_errors_are_reported(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "_client",
        lambda: cli.WorkOSClient(
            "sk", transport=httpx.MockTransport(lambda r: httpx.Response(401, text="nope"))
        ),
    )
    assert cli.main(["flags", "check", MODULE]) == 1
    assert "WorkOS answered 401 to GET /feature-flags: nope" in capsys.readouterr().err
