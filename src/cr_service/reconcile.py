"""Comparing what a service relies on, and the infrastructure registry, with WorkOS.

Everything here only reads WorkOS.
The comparisons are pure functions over what the WorkOS API returns,
and the ``*_remote`` coroutines fetch that state first.
A service awaits :func:`warn_on_drift` at startup,
and ``cr-service`` runs the same checks from the command line.

A WorkOS API key belongs to one environment.
Flag definitions and tags are shared by the project's environments,
but whether a flag is on, its targeting and every permission are per environment,
so check each environment with its own key.
"""

import dataclasses
import logging
import typing
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence

import httpx

from cr_service.auth.workos_api import JSONObject, WorkOSClient
from cr_service.flags import KIND_TAG_PREFIX, Flag, FlagSet
from cr_service.permissions import PermissionSet
from cr_service.registry import RegisteredFlag

logger = logging.getLogger(__name__)

Level = typing.Literal["error", "warning"]
Code = typing.Literal[
    "missing", "kind", "tags", "details", "requires", "conflict", "unregistered", "targeting"
]


@dataclasses.dataclass(frozen=True, slots=True)
class Finding:
    """One difference between WorkOS and what the code or registry expects.

    An ``error`` means something relies on what WorkOS does not hold.
    A ``warning`` is drift worth tidying, such as a flag the registry does not list.
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
    kind: str | None
    """Kind the registry or code expects, or the ``kind:`` tag WorkOS holds for anything else."""
    owner: str | None
    """Owner the registry gives the flag."""
    enabled: bool | None
    """Whether the flag is on in the key's environment, ``None`` if WorkOS has no such flag."""
    tags: tuple[str, ...]
    status: str
    """``ok``, ``missing``, ``drift`` or ``unregistered``, or ``-`` for a flag nothing expects."""


def _kind_tags(tags: Iterable[str]) -> list[str]:
    return sorted(tag for tag in tags if tag.startswith(KIND_TAG_PREFIX))


def _declared_flags(flag_sets: Sequence[type[FlagSet]]) -> tuple[dict[str, Flag], list[Finding]]:
    declared: dict[str, Flag] = {}
    findings: list[Finding] = []
    for flag_set in flag_sets:
        for flag in flag_set.flags():
            previous = declared.get(flag.slug)
            if previous is not None and previous.kind != flag.kind:
                findings.append(
                    Finding(
                        "error", "conflict", flag.slug, f"declared as both {previous.kind} and {flag.kind}"
                    )
                )
                continue
            declared[flag.slug] = flag
    return declared, findings


def check_flags(flag_sets: Sequence[type[FlagSet]], remote: Iterable[JSONObject]) -> list[Finding]:
    """Check WorkOS holds every flag the code checks, tagged with the kind the code expects."""
    declared, findings = _declared_flags(flag_sets)
    by_slug = {flag["slug"]: flag for flag in remote}
    for slug, flag in declared.items():
        current = by_slug.get(slug)
        if current is None:
            findings.append(
                Finding(
                    "error",
                    "missing",
                    slug,
                    "missing from WorkOS, so nobody has it",
                    "Add it to the infrastructure flag registry and create it in the WorkOS dashboard",
                )
            )
            continue
        kinds = _kind_tags(current.get("tags") or [])
        if kinds != [flag.kind.tag]:
            held = ", ".join(kinds) or "no kind tag"
            findings.append(
                Finding(
                    "error",
                    "kind",
                    slug,
                    f"the code expects {flag.kind.tag} but WorkOS has {held}",
                    "Check the infrastructure flag registry and the declaration agree, then fix the tag",
                )
            )
        if flag.requires is not None and flag.requires.slug not in by_slug:
            findings.append(
                Finding(
                    "error", "requires", slug, f"requires {flag.requires.slug!r}, which WorkOS does not hold"
                )
            )
    return findings


def check_permissions(
    permission_sets: Sequence[type[PermissionSet]], remote: Iterable[JSONObject]
) -> list[Finding]:
    """Check WorkOS holds every permission the code guards on."""
    held = {permission["slug"] for permission in remote}
    declared = dict.fromkeys(
        slug for permission_set in permission_sets for slug in permission_set.permissions()
    )
    return [
        Finding(
            "error",
            "missing",
            slug,
            "missing from WorkOS, so no role grants it",
            "Add it to the permissions in the infrastructure repository and apply",
        )
        for slug in declared
        if slug not in held
    ]


def _describe(flag: RegisteredFlag) -> str:
    parts = [f"slug {flag.slug!r}", f"name {flag.name!r}"]
    if flag.description:
        parts.append(f"description {flag.description!r}")
    parts.append(f"tags {', '.join(sorted(flag.tags))}")
    return "; ".join(parts)


def check_registry(registry: Iterable[RegisteredFlag], remote: Iterable[JSONObject]) -> list[Finding]:
    """Compare the infrastructure registry with WorkOS in both directions.

    Every registered flag must exist with its owner and kind tags.
    Other tags are left alone, except a second ``kind:`` tag.
    A WorkOS flag the registry does not list is reported as a warning.
    """
    registered = {flag.slug: flag for flag in registry}
    by_slug = {flag["slug"]: flag for flag in remote}
    findings = []
    for slug, flag in registered.items():
        current = by_slug.get(slug)
        if current is None:
            findings.append(
                Finding(
                    "error",
                    "missing",
                    slug,
                    "registered but missing from WorkOS",
                    f"Create it in the WorkOS dashboard with {_describe(flag)}",
                )
            )
            continue
        tags = set(current.get("tags") or [])
        add = sorted(flag.tags - tags)
        remove = [tag for tag in _kind_tags(tags) if tag not in flag.tags]
        if add or remove:
            changes = [f"add {', '.join(add)}"] if add else []
            if remove:
                changes.append(f"remove {', '.join(remove)}")
            findings.append(
                Finding(
                    "error",
                    "tags",
                    slug,
                    "tags differ from the registry",
                    f"In the dashboard, {'; '.join(changes)}",
                )
            )
        if current.get("name") != flag.name or (current.get("description") or None) != flag.description:
            findings.append(
                Finding(
                    "warning",
                    "details",
                    slug,
                    "name or description differs from the registry",
                    f"In the dashboard, set name {flag.name!r} and description {flag.description!r}",
                )
            )
    for slug in sorted(set(by_slug) - set(registered)):
        findings.append(
            Finding(
                "warning",
                "unregistered",
                slug,
                "in WorkOS but not in the registry",
                "Register it in the infrastructure repository, or delete it if nothing checks it",
            )
        )
    return findings


def check_flag_targeting(
    requirements: Mapping[str, Iterable[str]],
    organization_flags: Mapping[str, Iterable[str]],
    organization_names: Mapping[str, str] | None = None,
) -> list[Finding]:
    """Find organisations served a flag without a flag it requires.

    ``requirements`` maps a flag to the flags it requires,
    and ``organization_flags`` an organisation id to the flags WorkOS serves it.
    """
    names = organization_names or {}
    findings = []
    for organization_id, slugs in organization_flags.items():
        served = set(slugs)
        label = f"{names.get(organization_id, organization_id)} ({organization_id})"
        for slug, required in requirements.items():
            if slug not in served:
                continue
            for requirement in required:
                if requirement not in served:
                    findings.append(
                        Finding(
                            "warning",
                            "targeting",
                            slug,
                            f"organisation {label} has it without {requirement!r}",
                            f"Target {organization_id} with {requirement!r}, or remove it from {slug!r}",
                        )
                    )
    return findings


def requirements_of(
    flag_sets: Sequence[type[FlagSet]] = (), registry: Iterable[RegisteredFlag] = ()
) -> dict[str, tuple[str, ...]]:
    """Collect which flags each flag requires, from declarations and the registry."""
    requirements: dict[str, set[str]] = defaultdict(set)
    for flag_set in flag_sets:
        for flag in flag_set.flags():
            if flag.requires is not None:
                requirements[flag.slug].add(flag.requires.slug)
    for registered in registry:
        requirements[registered.slug].update(registered.requires)
    return {slug: tuple(sorted(required)) for slug, required in requirements.items() if required}


def list_flags(
    remote_flags: Iterable[JSONObject],
    flag_sets: Sequence[type[FlagSet]] = (),
    registry: Iterable[RegisteredFlag] = (),
) -> list[FlagRow]:
    """Every flag WorkOS lists, then any expected flag it does not, each with its status."""
    remote = list(remote_flags)
    registered = {flag.slug: flag for flag in registry}
    declared, _ = _declared_flags(flag_sets)
    findings = check_flags(flag_sets, remote)
    if registered:
        findings += check_registry(registered.values(), remote)
    status: dict[str, str] = {}
    for finding in findings:
        if finding.code in {"missing", "unregistered"}:
            status[finding.slug] = finding.code
        else:
            status.setdefault(finding.slug, "drift")

    def expected_kind(slug: str) -> str | None:
        if slug in registered:
            return registered[slug].kind.value
        if slug in declared:
            return declared[slug].kind.value
        return None

    rows = []
    for current in sorted(remote, key=lambda flag: flag["slug"]):
        slug = current["slug"]
        tags = tuple(sorted(current.get("tags") or []))
        held = next((tag.removeprefix(KIND_TAG_PREFIX) for tag in _kind_tags(tags)), None)
        expected = slug in registered or slug in declared
        rows.append(
            FlagRow(
                slug=slug,
                kind=expected_kind(slug) or held,
                owner=registered[slug].owner if slug in registered else None,
                enabled=bool(current.get("enabled")),
                tags=tags,
                status=status.get(slug, "ok" if expected else "-"),
            )
        )
    listed = {row.slug for row in rows}
    for slug in sorted((set(registered) | set(declared)) - listed):
        owner = registered[slug].owner if slug in registered else None
        rows.append(FlagRow(slug, expected_kind(slug), owner, None, (), "missing"))
    return rows


async def fetch_flags(client: WorkOSClient) -> list[JSONObject]:
    """List every WorkOS flag."""
    return [flag async for flag in client.list_feature_flags()]


async def check_flags_remote(client: WorkOSClient, *flag_sets: type[FlagSet]) -> list[Finding]:
    """Fetch the flags from WorkOS and :func:`check_flags` them."""
    return check_flags(flag_sets, await fetch_flags(client))


async def check_permissions_remote(
    client: WorkOSClient, *permission_sets: type[PermissionSet]
) -> list[Finding]:
    """Fetch the permissions from WorkOS and :func:`check_permissions` them."""
    return check_permissions(permission_sets, [permission async for permission in client.list_permissions()])


async def check_registry_remote(client: WorkOSClient, registry: Iterable[RegisteredFlag]) -> list[Finding]:
    """Fetch the flags from WorkOS and :func:`check_registry` them."""
    return check_registry(registry, await fetch_flags(client))


async def check_flag_targeting_remote(
    client: WorkOSClient, requirements: Mapping[str, Iterable[str]]
) -> list[Finding]:
    """Fetch every organisation's flags and :func:`check_flag_targeting` them.

    This makes one request per organisation, so it suits a command-line check rather than startup.
    """
    if not requirements:
        return []
    served: dict[str, list[str]] = defaultdict(list)
    names: dict[str, str] = {}
    async for organization in client.list_organizations():
        organization_id = organization["id"]
        names[organization_id] = organization.get("name") or organization_id
        async for flag in client.list_organization_feature_flags(organization_id):
            served[organization_id].append(flag["slug"])
    return check_flag_targeting(requirements, served, names)


async def warn_on_drift(
    client: WorkOSClient,
    *,
    flags: Sequence[type[FlagSet]] = (),
    permissions: Sequence[type[PermissionSet]] = (),
    log: logging.Logger = logger,
) -> list[Finding]:
    """Log a warning for each flag or permission the service relies on that WorkOS does not match.

    Meant for startup: it never raises, so an unreachable WorkOS only logs.
    """
    findings: list[Finding] = []
    try:
        if flags:
            findings += await check_flags_remote(client, *flags)
        if permissions:
            findings += await check_permissions_remote(client, *permissions)
    except httpx.HTTPError as error:
        log.warning("Could not compare flags and permissions with WorkOS", extra={"error": str(error)})
        return findings
    for finding in findings:
        log.warning(
            f"WorkOS {finding.slug}: {finding.message}",
            extra={"workos_slug": finding.slug, "workos_drift": finding.code, "workos_fix": finding.fix},
        )
    return findings
