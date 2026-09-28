"""Masking secrets before they reach the logs.

A field or query parameter is secret when its name looks like a credential,
or when it is one of the names added through ``LOG_REDACT_KEYS``.
Values are masked wherever they sit, including inside nested dicts and lists.
"""

import re
import urllib.parse
from collections.abc import Iterable, Mapping
from typing import Any

REDACTED = "[redacted]"

_SECRET_NAME = re.compile(
    r"token|secret|password|passwd|api_?key|authorization|cookie|signature|credential|private_?key",
    re.IGNORECASE,
)

# OAuth authorisation codes travel in the query string, where a bare "code" is almost always one.
_SECRET_QUERY_NAMES = frozenset({"code"})

_extra_names: frozenset[str] = frozenset()


def configure(extra_names: Iterable[str]) -> None:
    """Treat ``extra_names`` as secret as well, matched exactly and ignoring case."""
    global _extra_names  # noqa: PLW0603
    _extra_names = frozenset(name.strip().lower().replace("-", "_") for name in extra_names if name.strip())


def is_secret(name: str) -> bool:
    """Whether a field called ``name`` holds a secret."""
    return name.lower().replace("-", "_") in _extra_names or bool(_SECRET_NAME.search(name.replace("-", "_")))


def redact(value: Any) -> Any:
    """Return ``value`` with every secret field masked, at any depth."""
    if isinstance(value, dict):
        return {key: REDACTED if isinstance(key, str) and is_secret(key) else redact(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return type(value)(redact(item) for item in value)
    return value


def redact_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Return log fields with every secret masked, at any depth."""
    return {key: REDACTED if is_secret(key) else redact(value) for key, value in fields.items()}


def _is_secret_query(name: str) -> bool:
    return name.lower() in _SECRET_QUERY_NAMES or is_secret(name)


def redact_query(params: Iterable[tuple[str, str]]) -> dict[str, str]:
    """Return query parameters as a dict, masking the secret ones."""
    return {key: REDACTED if _is_secret_query(key) else value for key, value in params}


def redact_url(url: str | None) -> str | None:
    """Return ``url`` with the secret query parameters masked."""
    if not url or "?" not in url:
        return url
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.urlencode(
        [
            (key, REDACTED if _is_secret_query(key) else value)
            for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        ],
        safe="[]",
    )
    return parsed._replace(query=query).geturl()
