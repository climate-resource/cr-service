"""Verification of WorkOS API keys."""

import datetime
import hashlib
import time
import typing
from collections.abc import Callable, Mapping

import httpx

from cr_service.auth.errors import AuthenticationError, AuthUnavailableError
from cr_service.auth.principal import Principal
from cr_service.auth.workos_api import WORKOS_API_BASE_URL, JSONObject, WorkOSClient

API_KEY_PREFIX = "sk_"


def _str(data: Mapping[str, typing.Any], name: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"WorkOS returned an API key without {name}")
    return value


def _optional_str(data: Mapping[str, typing.Any], name: str) -> str | None:
    value = data.get(name)
    return value if isinstance(value, str) and value.strip() else None


def _expired(expires_at: object, now: datetime.datetime) -> bool:
    if expires_at is None:
        return False
    if not isinstance(expires_at, str):
        raise TypeError("WorkOS returned a malformed expires_at")
    expiry = datetime.datetime.fromisoformat(expires_at)
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=datetime.UTC)
    return expiry <= now


def _str_set(value: object, name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"WorkOS returned malformed {name}")
    return frozenset(item.strip() for item in value if item.strip())


class ApiKeyVerifier:
    """Resolves WorkOS API keys through the WorkOS API, caching each accepted key for ``ttl`` seconds.

    A user's key acts as that user in the organisation it was created in.
    An organisation's key is a machine principal of that organisation, identified by the key id.
    Either carries the key's permissions and the organisation's feature flags, but no role.
    Refused keys are not cached, so a revoked key stops working once its entry expires.

    Parameters
    ----------
    workos_api_key
        Management API key the validations are made with.
    require_email
        Refuse a user's key when the user has no email.
    """

    def __init__(  # noqa: PLR0913
        self,
        workos_api_key: str,
        *,
        require_email: bool = False,
        ttl: float = 60.0,
        max_entries: int = 1024,
        base_url: str = WORKOS_API_BASE_URL,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._workos_api_key = workos_api_key
        self._require_email = require_email
        self._ttl = ttl
        self._max_entries = max_entries
        self._base_url = base_url
        self._timeout = timeout
        self._transport = transport
        self._clock = clock
        # Keyed by the SHA-256 of the key, so no key is held in memory.
        self._cache: dict[str, tuple[Principal, float]] = {}

    @staticmethod
    def recognises(token: str) -> bool:
        """Whether ``token`` looks like a WorkOS API key rather than a JWT."""
        return token.startswith(API_KEY_PREFIX)

    async def verify(self, token: str) -> Principal:
        """Return the caller behind ``token``, raising :class:`AuthenticationError` if the key is not live."""
        digest = hashlib.sha256(token.encode()).hexdigest()
        cached = self._cache.get(digest)
        if cached is not None and self._clock() - cached[1] < self._ttl:
            return cached[0]
        self._cache.pop(digest, None)

        try:
            async with WorkOSClient(
                self._workos_api_key,
                base_url=self._base_url,
                timeout=self._timeout,
                transport=self._transport,
            ) as client:
                api_key = await client.validate_api_key(token)
                if api_key is None:
                    raise AuthenticationError("API key is invalid, expired or revoked")
                principal = await self._principal(client, api_key)
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise AuthUnavailableError("Unable to validate the API key") from exc

        while len(self._cache) >= self._max_entries:
            del self._cache[next(iter(self._cache))]
        self._cache[digest] = (principal, self._clock())
        return principal

    async def _principal(self, client: WorkOSClient, api_key: JSONObject) -> Principal:
        key_id = _str(api_key, "id")
        if _expired(api_key.get("expires_at"), datetime.datetime.now(datetime.UTC)):
            raise AuthenticationError("API key has expired")
        owner = api_key.get("owner")
        if not isinstance(owner, dict):
            raise TypeError("WorkOS returned an API key without an owner")
        permissions = _str_set(api_key.get("permissions"), "permissions")

        owner_type = owner.get("type")
        if owner_type == "organization":
            organization_id = _str(owner, "id")
            return Principal(
                kind="machine",
                id=key_id,
                organization_id=organization_id,
                permissions=permissions,
                feature_flags=await self._feature_flags(client, organization_id),
                credential="api_key",
                token_id=key_id,
                claims=api_key,
            )
        if owner_type != "user":
            raise AuthenticationError("API key has an unsupported owner")

        user_id = _str(owner, "id")
        organization_id = _str(owner, "organization_id")
        user = await client.get_user(user_id)
        email = _optional_str(user, "email")
        if self._require_email and email is None:
            raise AuthenticationError("API key belongs to a user with no email")
        return Principal(
            kind="user",
            id=user_id,
            organization_id=organization_id,
            permissions=permissions,
            feature_flags=await self._feature_flags(client, organization_id),
            email=email,
            email_verified=user.get("email_verified") is True,
            first_name=_optional_str(user, "first_name"),
            last_name=_optional_str(user, "last_name"),
            credential="api_key",
            token_id=key_id,
            claims=api_key,
        )

    @staticmethod
    async def _feature_flags(client: WorkOSClient, organization_id: str) -> frozenset[str]:
        return frozenset(
            [
                slug
                async for flag in client.list_organization_feature_flags(organization_id)
                if (slug := _optional_str(flag, "slug"))
            ]
        )
