"""Minting real, signed WorkOS-shaped tokens in tests.

Tests exercise the same verifier as production, with a local key in place of the WorkOS JWKS::

    tokens = TokenFactory.for_settings(settings)
    tokens.install(app, settings)
    client.get("/v1/things", headers=tokens.headers(permissions=["things:read"]))
"""

import dataclasses
import time
import typing
import uuid
from collections.abc import Iterable

import fastapi
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from cr_service.auth.authenticator import Authenticator, build_authenticator
from cr_service.auth.dependencies import AuthConfig, install_auth
from cr_service.auth.keys import StaticKeySource
from cr_service.settings import ServiceSettings
from cr_service.workos import STAGING, WorkOSEnvironment


class TokenFactory:
    """Signs user and machine tokens that the verifier accepts once :meth:`install` has run."""

    def __init__(
        self,
        environment: WorkOSEnvironment = STAGING,
        *,
        client_id: str = "client_test",
        kid: str = "test-key",
    ) -> None:
        self.environment = environment
        self.client_id = client_id
        self.kid = kid
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self._private_key.public_key(), as_dict=True)
        self.keys = StaticKeySource(jwt.PyJWKSet([{**public_jwk, "kid": kid, "alg": "RS256", "use": "sig"}]))

    @classmethod
    def for_settings(cls, settings: ServiceSettings, **kwargs: typing.Any) -> "TokenFactory":
        """Match the settings' WorkOS environment and application."""
        return cls(settings.workos, client_id=settings.workos_client_id or "client_test", **kwargs)

    def authenticator(self, settings: ServiceSettings) -> Authenticator:
        """Build the authenticator for ``settings``, trusting this factory's key."""
        return build_authenticator(settings, keys=self.keys)

    def install(self, app: fastapi.FastAPI, settings: ServiceSettings) -> None:
        """Make an app built by :func:`cr_service.setup` trust this factory's key, keeping its hooks."""
        installed = getattr(app.state, "cr_service_auth", None)
        config = installed.config if installed else AuthConfig()
        install_auth(app, settings, dataclasses.replace(config, authenticator=self.authenticator(settings)))

    def sign(self, claims: dict[str, typing.Any], *, kid: str | None = None) -> str:
        """Sign arbitrary claims, for tests of malformed tokens."""
        return jwt.encode(claims, self._private_key, algorithm="RS256", headers={"kid": kid or self.kid})

    def user_token(  # noqa: PLR0913
        self,
        *,
        user_id: str = "user_test",
        organization_id: str | None = "org_test",
        permissions: Iterable[str] = (),
        feature_flags: Iterable[str] = (),
        role: str = "member",
        email: str = "test@example.com",
        client_id: str | None = None,
        expires_in: int = 300,
        **claims: typing.Any,
    ) -> str:
        """Sign a user access token shaped like the Climate Resource WorkOS JWT template."""
        now = int(time.time())
        payload: dict[str, typing.Any] = {
            "iss": self.environment.user_token_issuer,
            "sub": user_id,
            "sid": f"session_{uuid.uuid4().hex}",
            "jti": uuid.uuid4().hex,
            "client_id": client_id or self.client_id,
            "iat": now,
            "exp": now + expires_in,
            "org_id": organization_id,
            "role": role,
            "roles": [role],
            "permissions": list(permissions),
            "feature_flags": list(feature_flags),
            "email": email,
            "email_verified": "true",
            "first_name": "Test",
            "last_name": "User",
        }
        payload.update(claims)
        return self.sign({key: value for key, value in payload.items() if value is not None})

    def machine_token(
        self,
        *,
        client_id: str = "client_machine_test",
        organization_id: str | None = "org_test",
        expires_in: int = 300,
        **claims: typing.Any,
    ) -> str:
        """Sign a client-credentials access token."""
        now = int(time.time())
        payload: dict[str, typing.Any] = {
            "iss": self.environment.machine_token_issuer,
            "aud": self.environment.machine_token_audience,
            "sub": client_id,
            "jti": uuid.uuid4().hex,
            "iat": now,
            "exp": now + expires_in,
            "org_id": organization_id,
        }
        payload.update(claims)
        return self.sign({key: value for key, value in payload.items() if value is not None})

    def headers(self, token: str | None = None, **user_claims: typing.Any) -> dict[str, str]:
        """Return an ``Authorization`` header for ``token``, or for a user token made from ``user_claims``."""
        return {"Authorization": f"Bearer {token or self.user_token(**user_claims)}"}
