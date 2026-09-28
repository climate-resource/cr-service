"""Sources of the public keys that sign access tokens."""

import asyncio
import logging
import time
import typing
import weakref
from collections.abc import Callable

import httpx
import jwt

from cr_service.auth.errors import AuthenticationError, AuthUnavailableError

logger = logging.getLogger(__name__)

_UNKNOWN_KEY = "Access token was signed with an unknown key"


class KeySource(typing.Protocol):
    """Looks up a token's signing key by its ``kid``."""

    async def get_signing_key(self, kid: str) -> jwt.PyJWK:
        """Return the key, raising :class:`AuthenticationError` if it is unknown."""
        ...


class StaticKeySource:
    """A fixed key set, for tests."""

    def __init__(self, keys: jwt.PyJWKSet) -> None:
        self._keys = keys

    async def get_signing_key(self, kid: str) -> jwt.PyJWK:
        """Return the key, raising :class:`AuthenticationError` if it is unknown."""
        try:
            return self._keys[kid]
        except KeyError:
            raise AuthenticationError(_UNKNOWN_KEY) from None


class JWKSCache:
    """Fetches a JWKS over HTTP and caches it.

    The document is refetched once ``ttl`` has passed, and early when a token names an unknown ``kid``,
    at most once per ``refresh_cooldown`` so junk tokens cannot hammer WorkOS.
    If a refetch fails, the stale keys keep serving.
    """

    def __init__(  # noqa: PLR0913
        self,
        url: str,
        *,
        ttl: float = 3600.0,
        refresh_cooldown: float = 60.0,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.url = url
        self._ttl = ttl
        self._refresh_cooldown = refresh_cooldown
        self._timeout = timeout
        self._transport = transport
        self._clock = clock
        self._keys: jwt.PyJWKSet | None = None
        self._fetched_at = 0.0
        self._last_forced = float("-inf")
        # asyncio locks bind to one loop, and test clients run a loop each.
        self._locks: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
            weakref.WeakKeyDictionary()
        )

    def _lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        lock = self._locks.get(loop)
        if lock is None:
            lock = self._locks[loop] = asyncio.Lock()
        return lock

    def _fresh(self) -> bool:
        return self._keys is not None and self._clock() - self._fetched_at < self._ttl

    async def get_signing_key(self, kid: str) -> jwt.PyJWK:
        """Return the key, refetching the JWKS if it is stale or does not hold ``kid``."""
        keys = await self._get_keys(force=False)
        try:
            return keys[kid]
        except KeyError:
            if self._clock() - self._last_forced < self._refresh_cooldown:
                raise AuthenticationError(_UNKNOWN_KEY) from None
        keys = await self._get_keys(force=True)
        try:
            return keys[kid]
        except KeyError:
            raise AuthenticationError(_UNKNOWN_KEY) from None

    async def _get_keys(self, *, force: bool) -> jwt.PyJWKSet:
        if not force and self._fresh():
            assert self._keys is not None
            return self._keys
        async with self._lock():
            # Another request may have refreshed while this one waited.
            if not force and self._fresh():
                assert self._keys is not None
                return self._keys
            if force:
                self._last_forced = self._clock()
            try:
                keys = await self._fetch()
            except (httpx.HTTPError, ValueError, AttributeError, jwt.PyJWKSetError) as exc:
                if self._keys is not None:
                    logger.warning("JWKS refresh failed, serving stale keys", extra={"jwks_url": self.url})
                    return self._keys
                raise AuthUnavailableError("Unable to fetch the token signing keys") from exc
            self._keys = keys
            self._fetched_at = self._clock()
            return keys

    async def _fetch(self) -> jwt.PyJWKSet:
        async with httpx.AsyncClient(timeout=self._timeout, transport=self._transport) as client:
            response = await client.get(self.url)
            response.raise_for_status()
            return jwt.PyJWKSet.from_dict(response.json())
