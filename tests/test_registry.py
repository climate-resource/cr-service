from pathlib import Path

import pytest

from cr_service.flags import FlagKind
from cr_service.registry import RegisteredFlag, load_registry, parse_registry

EXAMPLE = Path(__file__).with_name("registry_example.toml")


def test_load_registry():
    access, publish, view = load_registry(EXAMPLE)
    assert access == RegisteredFlag(
        "app:things", "Access Things", "things", FlagKind.ENTITLEMENT, "Use Things at all"
    )
    assert access.tags == {"things", "kind:entitlement"}
    assert publish.requires == ("app:things",)
    assert view.description is None


def entry(**overrides):
    return {"name": "A", "owner": "things", "kind": "ops"} | overrides


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({}, r"\[flags\] table"),
        ({"flags": {"a": "nope"}}, "must be a table"),
        ({"flags": {"a": entry(extra=1)}}, "unknown keys: extra"),
        ({"flags": {"a": entry(name="")}}, "needs a name"),
        ({"flags": {"a": entry(owner="kind:x")}}, "lowercase tag"),
        ({"flags": {"a": entry(kind="forever")}}, "kind must be one of entitlement, release, ops"),
        ({"flags": {"a": entry(requires="b")}}, "list of slugs"),
        ({"flags": {"a": entry(description=3)}}, "description must be a string"),
        ({"flags": {"a": entry(requires=["b"])}}, "requires unregistered b"),
        ({"flags": {"A": entry()}}, "slug"),
    ],
)
def test_parse_registry_rejects(data, message):
    with pytest.raises(ValueError, match=message):
        parse_registry(data)
