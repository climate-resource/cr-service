"""A small async client for the WorkOS management API."""

import types
import typing
from collections.abc import AsyncIterator

import httpx

from cr_service.auth.errors import AuthConfigurationError
from cr_service.settings import ServiceSettings

WORKOS_API_BASE_URL = "https://api.workos.com"

JSONObject = dict[str, typing.Any]


class WorkOSClient:
    """Looks up users and organisations, authenticated with the management API key.

    Open it once per app, for example in the lifespan, and close it on shutdown.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = WORKOS_API_BASE_URL,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout,
            transport=transport,
            headers={"Authorization": f"Bearer {api_key}"},
        )

    @classmethod
    def from_settings(cls, settings: ServiceSettings, **kwargs: typing.Any) -> "WorkOSClient":
        """Build a client from ``WORKOS_API_KEY``."""
        if settings.workos_api_key is None:
            raise AuthConfigurationError("WORKOS_API_KEY must be set to call the WorkOS API")
        return cls(settings.workos_api_key.get_secret_value(), **kwargs)

    async def __aenter__(self) -> "WorkOSClient":
        """Return the client."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> None:
        """Close the connection pool."""
        await self.aclose()

    async def aclose(self) -> None:
        """Close the connection pool."""
        await self._client.aclose()

    async def _get(self, path: str, params: dict[str, str] | None = None) -> JSONObject:
        response = await self._client.get(path, params=params)
        response.raise_for_status()
        return typing.cast(JSONObject, response.json())

    async def get_user(self, user_id: str) -> JSONObject:
        """Fetch one user."""
        return await self._get(f"/user_management/users/{user_id}")

    async def get_organization(self, organization_id: str) -> JSONObject:
        """Fetch one organisation."""
        return await self._get(f"/organizations/{organization_id}")

    async def list_users(self, *, organization_id: str | None = None) -> AsyncIterator[JSONObject]:
        """Yield every user, or every member of one organisation, following the pagination cursor."""
        params = {"limit": "100"}
        if organization_id:
            params["organization_id"] = organization_id
        seen: set[str] = set()
        while True:
            page = await self._get("/user_management/users", params)
            for user in page.get("data", []):
                yield user
            after = (page.get("list_metadata") or {}).get("after")
            if not after or after in seen:
                return
            seen.add(after)
            params["after"] = after
