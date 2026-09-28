"""Verification of WorkOS access tokens."""

import dataclasses
import typing
from collections.abc import Mapping

import jwt

from cr_service.auth.errors import AuthenticationError
from cr_service.auth.keys import KeySource
from cr_service.auth.principal import Principal

_REQUIRED_CLAIMS = ["exp", "iat", "sub"]


@dataclasses.dataclass(frozen=True, slots=True)
class TrustProfile:
    """One kind of token the verifier accepts, identified by its issuer."""

    kind: typing.Literal["user", "machine"]
    issuer: str
    keys: KeySource
    audience: str | None


def _str_claim(claims: Mapping[str, typing.Any], name: str) -> str | None:
    value = claims.get(name)
    return value if isinstance(value, str) and value.strip() else None


def _str_set_claim(claims: Mapping[str, typing.Any], name: str) -> frozenset[str]:
    value = claims.get(name)
    if value is None:
        return frozenset()
    if not isinstance(value, list | tuple) or not all(isinstance(item, str) for item in value):
        raise AuthenticationError(f"Access token has a malformed {name} claim")
    return frozenset(item.strip() for item in value if item.strip())


def _bool_claim(claims: Mapping[str, typing.Any], name: str) -> bool:
    # The WorkOS JWT template renders booleans as strings.
    value = claims.get(name)
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() == "true"


class TokenVerifier:
    """Verifies RS256 access tokens against a set of trust profiles.

    The unverified ``iss`` picks the profile, and the signature, issuer, audience and expiry
    are then checked against that profile alone, so no claim is trusted before verification.

    Parameters
    ----------
    profiles
        Accepted token kinds. At most one per issuer.
    accepted_client_ids
        Applications whose user tokens are accepted, when the token names one.
    machine_clients
        Machine client ids allowed in, each mapped to the permissions it is granted.
        Permissions come from here, never from the token.
    machine_organizations
        Machine client ids mapped to the organisations they may act for.
        A listed client's tokens must carry one of them as ``org_id``.
    require_email
        Refuse user tokens without an ``email`` claim.
    """

    def __init__(
        self,
        profiles: typing.Iterable[TrustProfile],
        *,
        accepted_client_ids: typing.Iterable[str],
        machine_clients: Mapping[str, typing.Iterable[str]] | None = None,
        machine_organizations: Mapping[str, typing.Iterable[str]] | None = None,
        require_email: bool = False,
    ) -> None:
        self._profiles = {profile.issuer: profile for profile in profiles}
        self._accepted_client_ids = frozenset(accepted_client_ids)
        self._machine_clients = {
            client_id: frozenset(permissions) for client_id, permissions in (machine_clients or {}).items()
        }
        self._machine_organizations = {
            client_id: frozenset(organizations)
            for client_id, organizations in (machine_organizations or {}).items()
        }
        self._require_email = require_email

    async def verify(self, token: str) -> Principal:
        """Verify ``token`` and return the caller, raising :class:`AuthenticationError` if it is not valid."""
        try:
            unverified = jwt.api_jwt.decode_complete(token, options={"verify_signature": False})
        except jwt.PyJWTError:
            raise AuthenticationError("Access token is not a valid JWT") from None
        header = unverified["header"]
        if header.get("alg") != "RS256":
            raise AuthenticationError("Access token must be signed with RS256")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AuthenticationError("Access token has no key id")
        profile = self._profiles.get(unverified["payload"].get("iss"))
        if profile is None:
            raise AuthenticationError("Access token was issued by an untrusted issuer")

        key = await profile.keys.get_signing_key(kid)
        try:
            claims: dict[str, typing.Any] = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=profile.issuer,
                audience=profile.audience,
                options={"require": _REQUIRED_CLAIMS, "verify_aud": profile.audience is not None},
            )
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Access token has expired") from None
        except jwt.PyJWTError as exc:
            raise AuthenticationError(f"Access token is invalid: {exc}") from None

        subject = _str_claim(claims, "sub")
        if subject is None:
            raise AuthenticationError("Access token has no subject")
        if profile.kind == "machine":
            return self._machine_principal(subject, claims)
        return self._user_principal(subject, claims)

    def _machine_principal(self, subject: str, claims: dict[str, typing.Any]) -> Principal:
        permissions = self._machine_clients.get(subject)
        if permissions is None:
            raise AuthenticationError("Machine client is not allowed")
        organization_id = _str_claim(claims, "org_id")
        organizations = self._machine_organizations.get(subject)
        if organizations is not None and organization_id not in organizations:
            raise AuthenticationError("Machine client is not allowed to act for this organisation")
        return Principal(
            kind="machine",
            id=subject,
            client_id=subject,
            organization_id=organization_id,
            permissions=permissions,
            token_id=_str_claim(claims, "jti"),
            claims=claims,
        )

    def _user_principal(self, subject: str, claims: dict[str, typing.Any]) -> Principal:
        client_id = _str_claim(claims, "client_id")
        if client_id is not None and client_id not in self._accepted_client_ids:
            raise AuthenticationError("Access token was issued for a different application")
        email = _str_claim(claims, "email")
        if self._require_email and email is None:
            raise AuthenticationError("Access token has no email")
        roles = _str_set_claim(claims, "roles")
        return Principal(
            kind="user",
            id=subject,
            organization_id=_str_claim(claims, "org_id"),
            permissions=_str_set_claim(claims, "permissions"),
            feature_flags=_str_set_claim(claims, "feature_flags"),
            role=_str_claim(claims, "role"),
            roles=tuple(sorted(roles)),
            email=email,
            email_verified=_bool_claim(claims, "email_verified"),
            first_name=_str_claim(claims, "first_name"),
            last_name=_str_claim(claims, "last_name"),
            organization_name=_str_claim(claims, "org_name"),
            client_id=client_id,
            session_id=_str_claim(claims, "sid"),
            token_id=_str_claim(claims, "jti"),
            claims=claims,
        )
