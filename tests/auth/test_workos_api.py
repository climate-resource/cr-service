import httpx
import pytest

from cr_service.auth import AuthConfigurationError
from cr_service.auth.workos_api import WorkOSClient
from tests.conftest import make_settings


def client_with(handler) -> WorkOSClient:
    return WorkOSClient("sk_test", transport=httpx.MockTransport(handler))


async def test_get_user_and_organization():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"id": request.url.path.rsplit("/", 1)[-1]})

    async with client_with(handler) as client:
        assert await client.get_user("user_1") == {"id": "user_1"}
        assert await client.get_organization("org_1") == {"id": "org_1"}
    assert [request.url.path for request in requests] == [
        "/user_management/users/user_1",
        "/organizations/org_1",
    ]
    assert requests[0].headers["authorization"] == "Bearer sk_test"


async def test_list_users_follows_cursor_and_stops_on_repeat():
    pages = {
        None: {"data": [{"id": "u1"}], "list_metadata": {"after": "c1"}},
        "c1": {"data": [{"id": "u2"}], "list_metadata": {"after": "c2"}},
        "c2": {"data": [{"id": "u3"}], "list_metadata": {"after": "c1"}},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["organization_id"] == "org_1"
        return httpx.Response(200, json=pages[request.url.params.get("after")])

    async with client_with(handler) as client:
        users = [user["id"] async for user in client.list_users(organization_id="org_1")]
    assert users == ["u1", "u2", "u3"]


async def test_errors_raise():
    async with client_with(lambda request: httpx.Response(404)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_user("missing")


async def test_from_settings():
    with pytest.raises(AuthConfigurationError, match="WORKOS_API_KEY"):
        WorkOSClient.from_settings(make_settings())
    client = WorkOSClient.from_settings(make_settings(workos_api_key="sk_test"))
    await client.aclose()
