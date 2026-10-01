"""``cr-service``: compare declared flags and permissions, and the flag registry, with WorkOS.

Every command only reads WorkOS.
Commands take the modules or ``module:Class`` references that declare a service's sets::

    cr-service flags check bookshelf_api.auth
    cr-service flags check --registry live/_envcommon/workos-flags.toml --targeting
    cr-service permissions check bookshelf_api.auth

A bare module means every set defined in it.
``WORKOS_API_KEY`` picks the WorkOS environment, so run each command once per environment.
"""

import argparse
import asyncio
import dataclasses
import importlib
import json
import os
import sys
import typing
from collections.abc import Sequence

import httpx

from cr_service.auth.workos_api import WorkOSClient
from cr_service.flags import FlagSet
from cr_service.permissions import PermissionSet
from cr_service.reconcile import (
    Finding,
    check_flag_targeting_remote,
    check_flags,
    check_permissions_remote,
    check_registry,
    fetch_flags,
    list_flags,
    requirements_of,
)
from cr_service.registry import RegisteredFlag, load_registry


class UsageError(Exception):
    """A reference, file or setting the command cannot use."""


def load_sets[T: (FlagSet, PermissionSet)](references: Sequence[str], base: type[T]) -> list[type[T]]:
    """Import every ``base`` subclass the references name, in order and without repeats."""
    if os.getcwd() not in sys.path:
        sys.path.insert(0, os.getcwd())
    found: list[type[T]] = []
    for reference in references:
        module_name, _, attribute = reference.partition(":")
        try:
            module = importlib.import_module(module_name)
        except ImportError as error:
            raise UsageError(f"Cannot import {module_name!r}: {error}") from error
        if attribute:
            value = getattr(module, attribute, None)
            if not (isinstance(value, type) and issubclass(value, base) and value is not base):
                raise UsageError(f"{reference!r} is not a {base.__name__} subclass")
            candidates = [value]
        else:
            candidates = [
                value
                for value in vars(module).values()
                if isinstance(value, type)
                and issubclass(value, base)
                and value is not base
                and value.__module__ == module.__name__
            ]
            if not candidates:
                raise UsageError(f"{module_name!r} defines no {base.__name__}")
        found.extend(candidate for candidate in candidates if candidate not in found)
    return found


def _registry(path: str | None) -> tuple[RegisteredFlag, ...]:
    if path is None:
        return ()
    try:
        return load_registry(path)
    except (OSError, ValueError) as error:
        raise UsageError(f"Cannot read the registry {path}: {error}") from error


def _client() -> WorkOSClient:
    api_key = os.environ.get("WORKOS_API_KEY")
    if not api_key:
        raise UsageError("Set WORKOS_API_KEY to the management API key of the environment to check")
    return WorkOSClient(api_key)


def _print_findings(findings: Sequence[Finding], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps([dataclasses.asdict(finding) for finding in findings], indent=2))
        return
    if not findings:
        print("No differences.")
        return
    for finding in sorted(findings, key=lambda finding: (finding.level != "error", finding.slug)):
        print(f"{finding.level.upper():7} {finding.slug}: {finding.message}")
        if finding.fix:
            print(f"        {finding.fix}")


def _exit_code(findings: Sequence[Finding], *, strict: bool) -> int:
    failing = {"error", "warning"} if strict else {"error"}
    return 1 if any(finding.level in failing for finding in findings) else 0


def _table(rows: Sequence[Sequence[str]]) -> str:
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    return "\n".join(
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths, strict=True)).rstrip() for row in rows
    )


async def _flags_list(args: argparse.Namespace) -> int:
    flag_sets = load_sets(args.sets, FlagSet)
    registry = _registry(args.registry)
    async with _client() as client:
        remote = await fetch_flags(client)
    rows = list_flags(remote, flag_sets, registry)
    if args.owner:
        rows = [row for row in rows if row.owner == args.owner or args.owner in row.tags]
    if args.json:
        print(json.dumps([dataclasses.asdict(row) for row in rows], indent=2))
        return 0
    if not rows:
        print("No flags.")
        return 0
    header = ("SLUG", "STATUS", "KIND", "OWNER", "ENABLED", "TAGS")
    cells = [
        (
            row.slug,
            row.status,
            row.kind or "-",
            row.owner or "-",
            "-" if row.enabled is None else ("on" if row.enabled else "off"),
            ", ".join(row.tags) or "-",
        )
        for row in rows
    ]
    print(_table([header, *cells]))
    return 0


async def _flags_check(args: argparse.Namespace) -> int:
    if not args.sets and not args.registry:
        raise UsageError("Name the modules declaring flag sets, or pass --registry")
    flag_sets = load_sets(args.sets, FlagSet)
    registry = _registry(args.registry)
    async with _client() as client:
        remote = await fetch_flags(client)
        findings = check_flags(flag_sets, remote)
        if registry:
            findings += check_registry(registry, remote)
        if args.targeting:
            findings += await check_flag_targeting_remote(client, requirements_of(flag_sets, registry))
    _print_findings(findings, as_json=args.json)
    return _exit_code(findings, strict=args.strict)


async def _permissions_list(args: argparse.Namespace) -> int:
    permission_sets = load_sets(args.sets, PermissionSet)
    declared = {slug for permission_set in permission_sets for slug in permission_set.permissions()}
    async with _client() as client:
        remote = {permission["slug"]: permission async for permission in client.list_permissions()}
    rows = []
    for slug in sorted(declared | set(remote)):
        current = remote.get(slug)
        if current is None:
            status = "missing"
        elif slug in declared:
            status = "ok"
        else:
            status = "system" if current.get("system") else "-"
        rows.append({"slug": slug, "status": status, "name": (current or {}).get("name") or ""})
    if args.json:
        print(json.dumps(rows, indent=2))
    elif rows:
        print(_table([("SLUG", "STATUS", "NAME"), *[(r["slug"], r["status"], r["name"]) for r in rows]]))
    else:
        print("No permissions.")
    return 0


async def _permissions_check(args: argparse.Namespace) -> int:
    permission_sets = load_sets(args.sets, PermissionSet)
    async with _client() as client:
        findings = await check_permissions_remote(client, *permission_sets)
    _print_findings(findings, as_json=args.json)
    return _exit_code(findings, strict=args.strict)


def build_parser() -> argparse.ArgumentParser:
    """Build the ``cr-service`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="cr-service",
        description="Compare declared flags and permissions, and the flag registry, with WorkOS. Read-only.",
    )
    commands = parser.add_subparsers(dest="group", required=True)

    def common(command: argparse.ArgumentParser, *, sets_required: bool) -> None:
        command.add_argument(
            "sets",
            nargs="+" if sets_required else "*",
            metavar="MODULE[:CLASS]",
            help="module declaring the sets, or one set in it",
        )
        command.add_argument("--json", action="store_true", help="print JSON")

    registry_help = "infrastructure flag registry (TOML) to compare WorkOS with"

    flags = commands.add_parser("flags", help="feature flags").add_subparsers(dest="command", required=True)
    flags_list = flags.add_parser("list", help="list WorkOS flags with their status")
    common(flags_list, sets_required=False)
    flags_list.add_argument("--registry", help=registry_help)
    flags_list.add_argument("--owner", help="only flags the registry gives this owner, or tagged with it")
    flags_list.set_defaults(handler=_flags_list)
    flags_check = flags.add_parser("check", help="check WorkOS holds the declared or registered flags")
    common(flags_check, sets_required=False)
    flags_check.add_argument("--registry", help=registry_help)
    flags_check.add_argument(
        "--targeting", action="store_true", help="also check organisations have what each flag requires"
    )
    flags_check.add_argument("--strict", action="store_true", help="fail on warnings too")
    flags_check.set_defaults(handler=_flags_check)

    permissions = commands.add_parser("permissions", help="RBAC permissions").add_subparsers(
        dest="command", required=True
    )
    permissions_list = permissions.add_parser("list", help="list WorkOS permissions with their status")
    common(permissions_list, sets_required=False)
    permissions_list.set_defaults(handler=_permissions_list)
    permissions_check = permissions.add_parser("check", help="check WorkOS holds the declared permissions")
    common(permissions_check, sets_required=True)
    permissions_check.add_argument("--strict", action="store_true", help="fail on warnings too")
    permissions_check.set_defaults(handler=_permissions_check)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line and return its exit code."""
    args = build_parser().parse_args(argv)
    try:
        return typing.cast(int, asyncio.run(args.handler(args)))
    except UsageError as error:
        print(f"cr-service: {error}", file=sys.stderr)
        return 2
    except httpx.HTTPStatusError as error:
        response = error.response
        print(
            f"cr-service: WorkOS answered {response.status_code} to {error.request.method} "
            f"{error.request.url.path}: {response.text}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
