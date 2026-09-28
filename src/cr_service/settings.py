"""Settings read by :func:`cr_service.setup`.

A service subclasses :class:`ServiceSettings` and adds its own fields.
Field names map straight to environment variables, so ``sentry_dsn`` reads ``SENTRY_DSN``.
Only ``WORKOS_API_KEY`` is secret, everything else belongs in the deploy config.
"""

import json
import typing

import pydantic
import pydantic_settings

from cr_service.workos import (
    WORKOS_ENVIRONMENTS,
    WorkOSEnvironment,
    WorkOSEnvironmentName,
    workos_environment_for,
)

Environment = typing.Literal["local", "staging", "preview", "production"]
CommaSeparated = typing.Annotated[tuple[str, ...], pydantic_settings.NoDecode]


class ServiceSettings(pydantic_settings.BaseSettings):
    """Environment, logging, Sentry and auth settings."""

    environment: Environment = "local"
    """Where the service runs. Picks the WorkOS environment and drives the fail-closed checks."""

    log_level: str = "INFO"
    log_format: typing.Literal["json", "text"] = "json"

    sentry_dsn: str | None = None
    """Sentry is not initialised when unset."""

    sentry_traces_sample_rate: float = pydantic.Field(default=0.0, ge=0.0, le=1.0)

    auth_provider: typing.Literal["workos", "local", "fake"] = "workos"
    """``local`` lets every request through as a fixed identity.

    ``fake`` returns that identity only for ``AUTH_FAKE_TOKEN``. Both are refused outside ``local``.
    """

    auth_enforce: bool = True
    """``false`` is shadow mode: failures are logged but let through as anonymous.

    Refused in production unless ``AUTH_ALLOW_PRODUCTION_SHADOW`` is set.
    """

    auth_allow_production_shadow: bool = False
    """Allows ``AUTH_ENFORCE=false`` in production, for a service still rolling auth out."""

    auth_local_user_id: str = "user_local"
    auth_local_email: str = "local@example.com"
    auth_local_organization_id: str | None = None
    auth_local_permissions: CommaSeparated = ()
    auth_local_feature_flags: CommaSeparated = ()
    auth_local_roles: CommaSeparated = ()
    auth_fake_token: str = "fake-access-token"  # noqa: S105

    workos_environment: WorkOSEnvironmentName | None = None
    """Override the WorkOS environment picked from ``ENVIRONMENT``, for example to test against production."""

    workos_client_id: str | None = None
    """This service's WorkOS application id."""

    workos_additional_client_ids: CommaSeparated = ()
    """Other applications whose user tokens are accepted, such as a CLI registered separately."""

    workos_accept_bookshelf_tokens: bool = False
    """Accept user tokens from the ``bookshelf`` CLI, so ``bookshelf auth token`` works as a bearer token."""

    workos_api_key: pydantic.SecretStr | None = None
    """Management API key, only needed to call the WorkOS API."""

    workos_required_feature_flag: str | None = None
    """Feature flag a user's organisation must have, such as ``app:bookshelf``."""

    workos_allowed_organization_ids: CommaSeparated = ()
    """Organisations allowed in. Empty allows any."""

    workos_machine_clients: dict[str, tuple[str, ...]] = pydantic.Field(default_factory=dict)
    """Machine client ids allowed in, as JSON mapping each to the permissions it is granted."""

    model_config = pydantic_settings.SettingsConfigDict(env_file=".env", extra="ignore", frozen=True)

    @pydantic.field_validator(
        "auth_local_permissions",
        "auth_local_feature_flags",
        "auth_local_roles",
        "workos_additional_client_ids",
        "workos_allowed_organization_ids",
        mode="before",
    )
    @classmethod
    def _split_lists(cls, value: typing.Any) -> typing.Any:
        """Accept a JSON array or a comma-separated string."""
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("["):
                return tuple(json.loads(stripped))
            return tuple(item.strip() for item in stripped.split(",") if item.strip())
        return value

    @pydantic.model_validator(mode="after")
    def _fail_closed(self) -> typing.Self:
        if self.auth_provider in {"local", "fake"} and self.environment != "local":
            raise ValueError(
                f"AUTH_PROVIDER={self.auth_provider} is only allowed when ENVIRONMENT=local, "
                f"not {self.environment}"
            )
        if self.environment == "production":
            if not self.auth_enforce and not self.auth_allow_production_shadow:
                raise ValueError("AUTH_ENFORCE=false needs AUTH_ALLOW_PRODUCTION_SHADOW=true in production")
            if self.workos.name != "production":
                raise ValueError("Production must verify tokens from the production WorkOS environment")
        return self

    def __hash__(self) -> int:
        """Identity hash, so an instance can key a cache."""
        return id(self)

    @property
    def workos(self) -> WorkOSEnvironment:
        """The WorkOS environment tokens are verified against."""
        if self.workos_environment is not None:
            return WORKOS_ENVIRONMENTS[self.workos_environment]
        return workos_environment_for(self.environment)

    @property
    def accepted_client_ids(self) -> frozenset[str]:
        """Applications whose user tokens are accepted."""
        ids = set(self.workos_additional_client_ids)
        if self.workos_client_id:
            ids.add(self.workos_client_id)
        if self.workos_accept_bookshelf_tokens:
            ids.add(self.workos.bookshelf_client_id)
        return frozenset(ids)

    def public_auth_config(self) -> dict[str, str | None]:
        """Return what a browser needs to sign in, safe to serve from an unauthenticated endpoint."""
        return {
            "provider": self.auth_provider,
            "workos_environment": self.workos.name,
            "client_id": self.workos_client_id,
            "api_hostname": self.workos.api_hostname,
            "authkit_domain": self.workos.authkit_domain,
        }
