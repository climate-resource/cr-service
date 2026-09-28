import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from cr_service.auth import AuthenticationError, AuthUnavailableError
from cr_service.auth.keys import JWKSCache

URL = "https://auth.example.com/jwks"


def _jwk(kid: str) -> dict:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return {**jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True), "kid": kid, "alg": "RS256"}


class FakeJWKS:
    def __init__(self, *kids: str) -> None:
        self.documents = {"keys": [_jwk(kid) for kid in kids]}
        self.calls = 0
        self.fail = False

    def rotate(self, *kids: str) -> None:
        self.documents = {"keys": [_jwk(kid) for kid in kids]}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        if self.fail:
            return httpx.Response(500)
        return httpx.Response(200, json=self.documents)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def jwks():
    return FakeJWKS("key-1")


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def cache(jwks, clock):
    return JWKSCache(
        URL, transport=httpx.MockTransport(jwks.handler), clock=clock, ttl=100, refresh_cooldown=10
    )


async def test_fetches_once_while_fresh(cache, jwks):
    await cache.get_signing_key("key-1")
    await cache.get_signing_key("key-1")
    assert jwks.calls == 1


async def test_refetches_after_ttl(cache, jwks, clock):
    await cache.get_signing_key("key-1")
    clock.now += 101
    await cache.get_signing_key("key-1")
    assert jwks.calls == 2


async def test_unknown_kid_refreshes_once_per_cooldown(cache, jwks, clock):
    await cache.get_signing_key("key-1")
    jwks.rotate("key-2")
    assert await cache.get_signing_key("key-2")
    assert jwks.calls == 2

    # Inside the cooldown of the refresh that found key-2.
    with pytest.raises(AuthenticationError, match="unknown key"):
        await cache.get_signing_key("key-3")
    assert jwks.calls == 2

    clock.now += 11
    with pytest.raises(AuthenticationError):
        await cache.get_signing_key("key-3")
    with pytest.raises(AuthenticationError):
        await cache.get_signing_key("key-3")
    assert jwks.calls == 3


async def test_serves_stale_keys_when_refresh_fails(cache, jwks, clock):
    await cache.get_signing_key("key-1")
    jwks.fail = True
    clock.now += 101
    assert await cache.get_signing_key("key-1")


async def test_unavailable_without_any_keys(cache, jwks):
    jwks.fail = True
    with pytest.raises(AuthUnavailableError):
        await cache.get_signing_key("key-1")


@pytest.mark.parametrize("document", [[], {"keys": "nope"}, {}, {"keys": [{"kid": "x", "kty": "nope"}]}])
async def test_unusable_documents(document):
    cache = JWKSCache(URL, transport=httpx.MockTransport(lambda request: httpx.Response(200, json=document)))
    with pytest.raises(AuthUnavailableError):
        await cache.get_signing_key("x")
