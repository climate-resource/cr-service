"""Comparing declared flags and permissions with WorkOS.

The comparisons are pure functions over what the WorkOS API returns,
and the ``*_remote`` coroutines fetch that state first.
A service can await them at startup and log the findings,
and ``cr-service`` runs them from the command line.

A WorkOS API key belongs to one environment.
Flag definitions and tags are shared by the project's environments,
but whether a flag is on, its targeting and every permission are per environment,
so check each environment with its own key.
"""

import dataclasses
import typing
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence

from cr_service.auth.workos_api import JSONObject, WorkOSClient
from cr_service.flags import KIND_TAG_PREFIX, Flag, FlagSet
from cr_service.permissions import Permission, PermissionSet

Level = typing.Literal["error", "warning"]
Code = typing.Literal[
    "conflict", "missing", "tags", "details", "requires", "undeclared", "targeting", "system", "outdated"
]


@dataclasses.dataclass(frozen=True, slots=True)
class Finding:
    """One difference between the code and WorkOS.

    An ``error`` means the code relies on something WorkOS does not hold.
    A ``warning`` is drift worth tidying, such as a flag nothing declares any more.
    """

    level: Level
    code: Code
    """Stable identifier of the kind of difference, for scripts."""
    slug: str
    message: str
    fix: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class FlagRow:
    """One flag as ``cr-service flags list`` shows it."""

    slug: str
    owner: str | None
    """Owner of the set declaring the flag, or ``None`` if no given set declares it."""
    kind: str | None
    """Declared kind, or the ``kind:`` tag WorkOS holds for an undeclared flag."""
    enabled: bool | None
    """Whether the flag is on in the key's environment, ``None`` if WorkOS has no such flag."""
    tags: tuple[str, ...]
    status: str
    """``ok``, ``missing``, ``drift`` or ``undeclared``, or ``-`` for a flag no given set covers."""


@dataclasses.dataclass(frozen=True, slots=True)
class PermissionChange:
    """A permission ``cr-service permissions sync`` creates or updates."""

    action: typing.Literal["create", "update"]
    permission: Permission


def _declared_flags(
    flag_sets: Sequence[type[FlagSet]],
) -> tuple[dict[str, tuple[type[FlagSet], Flag]], list[Finding]]:
    declared: dict[str, tuple[type[FlagSet], Flag]] = {}
    findings: list[Finding] = []
    for flag_set in flag_sets:
        for flag in flag_set.flags():
            if flag.slug in declared and declared[flag.slug][0].owner != flag_set.owner:
                findings.append(
                    Finding(
                        "error",
                        "conflict",
                        flag.slug,
                        f"declared by both {declared[flag.slug][0].owner!r} and {flag_set.owner!r}, "
                        "a flag has one owner",
                    )
                )
                continue
            declared[flag.slug] = (flag_set, flag)
    return declared, findings


def _describe_flag(flag_set: type[FlagSet], flag: Flag) -> str:
    parts = [f"slug {flag.slug!r}", f"name {flag.name!r}"]
    if flag.description:
        parts.append(f"description {flag.description!r}")
    parts.append(f"tags {', '.join(sorted(flag_set.tags_for(flag)))}")
    return "; ".join(parts)


def check_flags(flag_sets: Sequence[type[FlagSet]], remote: Iterable[JSONObject]) -> list[Finding]:
    """Compare the declared flags with the flags WorkOS lists.

    WorkOS must hold every declared flag, tagged with its set's owner and exactly its kind.
    A flag tagged with a given owner but not declared by it is reported as a warning.
    """
    declared, findings = _declared_flags(flag_sets)
    by_slug = {flag["slug"]: flag for flag in remote}

    for slug, (flag_set, flag) in declared.items():
        current = by_slug.get(slug)
        if current is None:
            findings.append(
                Finding(
                    "error",
                    "missing",
                    slug,
                    "missing from WorkOS",
                    f"Create it in the WorkOS dashboard with {_describe_flag(flag_set, flag)}",
                )
            )
            continue
        tags = set(current.get("tags") or [])
        expected = flag_set.tags_for(flag)
        missing_tags = sorted(expected - tags)
        wrong_kinds = sorted(tag for tag in tags if tag.startswith(KIND_TAG_PREFIX) and tag not in expected)
        if missing_tags or wrong_kinds:
            changes = [f"add {', '.join(missing_tags)}"] if missing_tags else []
            if wrong_kinds:
                changes.append(f"remove {', '.join(wrong_kinds)}")
            findings.append(
                Finding(
                    "error",
                    "tags",
                    slug,
                    "tags differ from the declaration",
                    f"In the dashboard, {'; '.join(changes)}",
                )
            )
        if current.get("name") != flag.name or (current.get("description") or None) != flag.description:
            findings.append(
                Finding(
                    "warning",
                    "details",
                    slug,
                    "name or description differs from the declaration",
                    f"Set name {flag.name!r} and description {flag.description!r} in the dashboard, "
                    "or change the declaration",
                )
            )
        if (
            flag.requires is not None
            and flag.requires.slug not in declared
            and flag.requires.slug not in by_slug
        ):
            findings.append(
                Finding(
                    "error", "requires", slug, f"requires {flag.requires.slug!r}, which WorkOS does not hold"
                )
            )

    owners = {flag_set.owner for flag_set in flag_sets}
    for slug, current in by_slug.items():
        claimed = owners & set(current.get("tags") or [])
        for owner in sorted(claimed):
            if slug not in declared or declared[slug][0].owner != owner:
                findings.append(
                    Finding(
                        "warning",
                        "undeclared",
                        slug,
                        f"tagged {owner!r} but not declared by it",
                        "Declare it, delete the flag if nothing checks it, or remove the tag",
                    )
                )
    return findings


def check_flag_targeting(
    flag_sets: Sequence[type[FlagSet]],
    organization_flags: Mapping[str, Iterable[str]],
    organization_names: Mapping[str, str] | None = None,
) -> list[Finding]:
    """Find organisations that have a flag but not the flag it ``requires``.

    ``organization_flags`` maps an organisation id to the flags WorkOS serves it.
    """
    names = organization_names or {}
    declared, _ = _declared_flags(flag_sets)
    findings = []
    for organization_id, slugs in organization_flags.items():
        served = set(slugs)
        for slug, (_, flag) in declared.items():
            if flag.requires is not None and slug in served and flag.requires.slug not in served:
                label = names.get(organization_id, organization_id)
                findings.append(
                    Finding(
                        "warning",
                        "targeting",
                        slug,
                        f"organisation {label} ({organization_id}) has it without {flag.requires.slug!r}",
                        f"Target {organization_id} with {flag.requires.slug!r}, or remove it from {slug!r}",
                    )
                )
    return findings


def list_flags(flag_sets: Sequence[type[FlagSet]], remote_flags: Iterable[JSONObject]) -> list[FlagRow]:
    """Every flag WorkOS lists, followed by declared flags it does not, with each one's status."""
    declared, _ = _declared_flags(flag_sets)
    remote = list(remote_flags)
    findings = check_flags(flag_sets, remote)
    status: dict[str, str] = {}
    for finding in findings:
        if finding.code in {"missing", "undeclared"}:
            status[finding.slug] = finding.code
        else:
            status.setdefault(finding.slug, "drift")

    rows = []
    for current in sorted(remote, key=lambda flag: flag["slug"]):
        slug = current["slug"]
        tags = tuple(sorted(current.get("tags") or []))
        entry = declared.get(slug)
        remote_kind = next(
            (tag.removeprefix(KIND_TAG_PREFIX) for tag in tags if tag.startswith(KIND_TAG_PREFIX)), None
        )
        rows.append(
            FlagRow(
                slug=slug,
                owner=entry[0].owner if entry else None,
                kind=entry[1].kind.value if entry else remote_kind,
                enabled=bool(current.get("enabled")),
                tags=tags,
                status=status.get(slug, "ok" if entry else "-"),
            )
        )
    known = {row.slug for row in rows}
    for slug, (flag_set, flag) in sorted(declared.items()):
        if slug not in known:
            rows.append(FlagRow(slug, flag_set.owner, flag.kind.value, None, (), "missing"))
    return rows


def _declared_permissions(
    permission_sets: Sequence[type[PermissionSet]],
) -> tuple[dict[str, Permission], list[Finding]]:
    declared: dict[str, Permission] = {}
    findings: list[Finding] = []
    for permission_set in permission_sets:
        for permission in permission_set.permissions():
            previous = declared.get(permission.slug)
            if previous is not None and (previous.name, previous.description) != (
                permission.name,
                permission.description,
            ):
                findings.append(
                    Finding("error", "conflict", permission.slug, "declared twice with different names")
                )
                continue
            declared[permission.slug] = permission
    return declared, findings


def plan_permissions(
    permission_sets: Sequence[type[PermissionSet]], remote: Iterable[JSONObject]
) -> tuple[list[PermissionChange], list[Finding]]:
    """Work out which permissions to create or update, and what to report.

    Permissions in a declared namespace that nothing declares are reported, never deleted:
    deleting one unbinds it from every role that grants it.
    """
    declared, findings = _declared_permissions(permission_sets)
    by_slug = {permission["slug"]: permission for permission in remote}
    changes = []
    for slug, permission in declared.items():
        current = by_slug.get(slug)
        if current is None:
            changes.append(PermissionChange("create", permission))
        elif current.get("system"):
            findings.append(
                Finding("error", "system", slug, "is a WorkOS system permission and cannot be declared")
            )
        elif (current.get("name"), current.get("description") or None) != (
            permission.name,
            permission.description,
        ):
            changes.append(PermissionChange("update", permission))

    namespaces = {permission_set.namespace for permission_set in permission_sets}
    for slug, current in sorted(by_slug.items()):
        if slug in declared or current.get("system"):
            continue
        if slug.split(":", 1)[0] in namespaces:
            findings.append(
                Finding(
                    "warning",
                    "undeclared",
                    slug,
                    "is in a declared namespace but not declared",
                    "Declare it, or unbind it from every role and delete it",
                )
            )
    return changes, findings


def permission_findings(changes: Iterable[PermissionChange]) -> list[Finding]:
    """Report pending changes as errors, for a check that does not apply them."""
    return [
        Finding(
            "error",
            "missing" if change.action == "create" else "outdated",
            change.permission.slug,
            "missing from WorkOS" if change.action == "create" else "name or description differs from WorkOS",
            "Run cr-service permissions sync",
        )
        for change in changes
    ]


async def check_flags_remote(client: WorkOSClient, *flag_sets: type[FlagSet]) -> list[Finding]:
    """Fetch the flags from WorkOS and :func:`check_flags` them."""
    return check_flags(flag_sets, [flag async for flag in client.list_feature_flags()])


async def check_flag_targeting_remote(client: WorkOSClient, *flag_sets: type[FlagSet]) -> list[Finding]:
    """Fetch every organisation's flags and :func:`check_flag_targeting` them.

    This makes one request per organisation, so it suits a command-line check rather than startup.
    """
    if not any(flag.requires is not None for flag_set in flag_sets for flag in flag_set.flags()):
        return []
    served: dict[str, list[str]] = defaultdict(list)
    names: dict[str, str] = {}
    async for organization in client.list_organizations():
        organization_id = organization["id"]
        names[organization_id] = organization.get("name") or organization_id
        async for flag in client.list_organization_feature_flags(organization_id):
            served[organization_id].append(flag["slug"])
    return check_flag_targeting(flag_sets, served, names)


async def check_permissions_remote(
    client: WorkOSClient, *permission_sets: type[PermissionSet]
) -> list[Finding]:
    """Fetch the permissions from WorkOS and report what a sync would change."""
    changes, findings = plan_permissions(permission_sets, [p async for p in client.list_permissions()])
    return permission_findings(changes) + findings


async def sync_permissions(
    client: WorkOSClient, *permission_sets: type[PermissionSet], dry_run: bool = False
) -> tuple[list[PermissionChange], list[Finding]]:
    """Create and update the declared permissions, returning what changed and what else was found."""
    changes, findings = plan_permissions(permission_sets, [p async for p in client.list_permissions()])
    if not dry_run:
        for change in changes:
            permission = change.permission
            if change.action == "create":
                await client.create_permission(
                    permission.slug, name=permission.name, description=permission.description
                )
            else:
                await client.update_permission(
                    permission.slug, name=permission.name, description=permission.description
                )
    return changes, findings
