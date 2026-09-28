"""Masking secrets before they reach the logs.

A field or query parameter is secret when its name ends in a credential word,
such as ``access_token``, ``db_password`` or ``apiKey``,
or when it is one of the names added through ``LOG_REDACT_KEYS``.
Values are masked wherever they sit, including inside nested dicts and lists.
"""

import re
import urllib.parse
from collections.abc import Iterable, Mapping
from typing import Any

REDACTED = "[redacted]"

_SECRET_WORDS = frozenset(
    {
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "passphrase",
        "passwd",
        "password",
        "secret",
        "signature",
        "token",
    }
)
_SECRET_KEY_QUALIFIERS = frozenset({"access", "api", "private", "secret", "signing"})

# OAuth authorisation codes travel in the query string, where a bare "code" is almost always one.
_SECRET_QUERY_NAMES = frozenset({"code"})

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

_extra_names: frozenset[str] = frozenset()


def _normalise(name: str) -> str:
    return _CAMEL_BOUNDARY.sub("_", name.strip()).lower().replace("-", "_")


def configure(extra_names: Iterable[str]) -> None:
    """Treat ``extra_names`` as secret as well, matched exactly and ignoring case."""
    global _extra_names  # noqa: PLW0603
    _extra_names = frozenset(_normalise(name) for name in extra_names if name.strip())


def is_secret(name: str) -> bool:
    """Whether a field called ``name`` holds a secret."""
    normalised = _normalise(name)
    if normalised in _extra_names:
        return True
    words = normalised.split("_")
    if words[-1] in _SECRET_WORDS:
        return True
    return len(words) > 1 and words[-1] == "key" and words[-2] in _SECRET_KEY_QUALIFIERS


def _redact_mapping(fields: Mapping[Any, Any]) -> dict[Any, Any]:
    return {
        key: REDACTED if isinstance(key, str) and is_secret(key) else redact(value)
        for key, value in fields.items()
    }


def redact(value: Any) -> Any:
    """Return ``value`` with every secret field masked, at any depth."""
    if isinstance(value, Mapping):
        return _redact_mapping(value)
    if isinstance(value, list | tuple):
        return type(value)(redact(item) for item in value)
    return value


def redact_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    """Return log fields with every secret masked, at any depth."""
    return _redact_mapping(fields)


def _redact_pairs(params: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    return [
        (key, REDACTED if key.lower() in _SECRET_QUERY_NAMES or is_secret(key) else value)
        for key, value in params
    ]


def redact_query(params: Iterable[tuple[str, str]]) -> dict[str, str]:
    """Return query parameters as a dict, masking the secret ones."""
    return dict(_redact_pairs(params))


def redact_url(url: str | None) -> str | None:
    """Return ``url`` with the secret query parameters masked."""
    if not url or "?" not in url:
        return url
    parsed = urllib.parse.urlsplit(url)
    pairs = _redact_pairs(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    return parsed._replace(query=urllib.parse.urlencode(pairs, safe="[]")).geturl()
