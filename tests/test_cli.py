import json

import pytest

from cr_service import cli
from cr_service.flags import FlagSet
from cr_service.permissions import PermissionSet
from tests.declarations_example import ThingsFlags, ThingsPermissions
from tests.test_reconcile import IN_SYNC, PERMISSIONS, FakeWorkOS, remote_flag
from tests.test_registry import EXAMPLE

MODULE = "tests.declarations_example"
REGISTRY = str(EXAMPLE)


@pytest.fixture
def workos(monkeypatch):
    fake = FakeWorkOS(flags=IN_SYNC, permissions=PERMISSIONS)
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


def test_flags_check_needs_something_to_check(workos, capsys):
    assert cli.main(["flags", "check"]) == 2
    assert "--registry" in capsys.readouterr().err


def test_bad_registry(workos, tmp_path, capsys):
    assert cli.main(["flags", "check", "--registry", str(tmp_path / "missing.toml")]) == 2
    (tmp_path / "bad.toml").write_text("flags = 3\n")
    assert cli.main(["flags", "check", "--registry", str(tmp_path / "bad.toml")]) == 2
    assert "[flags] table" in capsys.readouterr().err


def test_flags_list(workos, capsys):
    workos.flags = [*IN_SYNC[1:], remote_flag("other", "other")]
    assert cli.main(["flags", "list", "--registry", REGISTRY]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].split() == ["SLUG", "STATUS", "KIND", "OWNER", "ENABLED", "TAGS"]
    assert lines[1].split() == ["other", "unregistered", "-", "-", "on", "other"]
    assert lines[-1].split() == ["app:things", "missing", "entitlement", "things", "-", "-"]


def test_flags_list_filters_and_json(workos, capsys):
    workos.flags = [*IN_SYNC, remote_flag("other", "other")]
    assert cli.main(["flags", "list", "--owner", "other", "--json"]) == 0
    assert [row["slug"] for row in json.loads(capsys.readouterr().out)] == ["other"]
    assert cli.main(["flags", "list", MODULE, "--owner", "nobody"]) == 0
    assert capsys.readouterr().out == "No flags.\n"


def test_flags_check_declarations(workos, capsys):
    assert cli.main(["flags", "check", MODULE]) == 0
    assert capsys.readouterr().out == "No differences.\n"

    workos.flags = IN_SYNC[1:]
    assert cli.main(["flags", "check", MODULE]) == 1
    assert "ERROR   app:things: missing from WorkOS" in capsys.readouterr().out


def test_flags_check_registry_strict_and_targeting(workos, capsys):
    workos.flags = [*IN_SYNC, remote_flag("stray")]
    assert cli.main(["flags", "check", "--registry", REGISTRY]) == 0
    assert "WARNING stray: in WorkOS but not in the registry" in capsys.readouterr().out
    assert cli.main(["flags", "check", "--registry", REGISTRY, "--strict"]) == 1
    capsys.readouterr()

    workos.flags = IN_SYNC
    workos.organizations = [{"id": "org_1", "name": "One"}]
    workos.served = {"org_1": ["things:publish"]}
    assert cli.main(["flags", "check", MODULE, "--registry", REGISTRY, "--targeting", "--json"]) == 0
    [finding] = json.loads(capsys.readouterr().out)
    assert finding["code"] == "targeting"


def test_permissions(workos, capsys):
    assert cli.main(["permissions", "list", MODULE]) == 0
    rows = [line.split()[:2] for line in capsys.readouterr().out.splitlines()]
    assert rows == [
        ["SLUG", "STATUS"],
        ["other:read", "-"],
        ["things:read", "ok"],
        ["things:write", "missing"],
        ["widgets:api-keys:manage", "system"],
    ]
    assert cli.main(["permissions", "list", "--json"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 3
    assert cli.main(["permissions", "check", MODULE]) == 1
    assert "ERROR   things:write: missing from WorkOS" in capsys.readouterr().out

    workos.permissions = []
    assert cli.main(["permissions", "list"]) == 0
    assert capsys.readouterr().out == "No permissions.\n"


def test_workos_errors_are_reported(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_client", FakeWorkOS(status=401).client)
    assert cli.main(["flags", "check", MODULE]) == 1
    assert "WorkOS answered 401 to GET /feature-flags: nope" in capsys.readouterr().err
