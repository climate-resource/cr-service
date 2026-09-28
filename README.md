# cr-service

WorkOS authentication, logging and observability for Climate Resource FastAPI services.

Services generated from [copier-python-service](https://github.com/climate-resource/copier-python-service)
each carried their own copy of the logging, Sentry, tracing, metrics and profiling modules,
and each service that needed WorkOS wrote its own token verifier.
This package holds one version of all of it, so a fix lands everywhere with a dependency bump.

What it provides:

- WorkOS access-token verification, with the production and staging issuers and JWKS URLs built in.
- FastAPI dependencies for the caller, required permissions and feature flags.
- Machine-to-machine (client credentials) tokens, allowed per client id.
- A request-scoped log context that the caller's ids are added to.
- The wide-event access log, correlation headers, Sentry, OpenTelemetry, Prometheus, Pyroscope and health probes.
- A token factory that signs real tokens, so tests go through the production verifier.

## Quick start

```python
import fastapi
from fastapi.middleware.cors import CORSMiddleware

import cr_service
from cr_service.auth import CurrentPrincipal, require_permission

from my_service import __version__

SERVICE = cr_service.ServiceInfo(name="my-service", version=__version__)

# Capture startup logs before uvicorn applies its own config.
cr_service.configure_logging(SERVICE)


class Settings(cr_service.ServiceSettings):
    cors_allow_origins: tuple[str, ...] = ()


def build_app() -> fastapi.FastAPI:
    settings = Settings()
    app = fastapi.FastAPI(title="My Service", version=__version__)
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_allow_origins, allow_headers=["*"])
    cr_service.setup(app, service=SERVICE, settings=settings)

    @app.get("/v1/me")
    def me(principal: CurrentPrincipal) -> dict[str, str]:
        return {"id": principal.id}

    @app.post("/v1/things", dependencies=[fastapi.Depends(require_permission("things:write"))])
    def create_thing() -> None: ...

    return app
```

`setup` installs, in order:

- logging and Sentry, from the settings,
- the Pyroscope profiler, when `PYROSCOPE_SERVER_ADDRESS` is set,
- the wide-event, route-tag and forwarded-prefix middleware,
- `/livez` and `/readyz`, running any `readiness_checks` passed in,
- `/metrics`,
- OpenTelemetry, when `OTEL_EXPORTER_OTLP_ENDPOINT` is set,
- auth, unless `auth=None` is passed.

Add the service's own middleware, such as CORS, before calling `setup`,
so the wide event and the trace wrap it.

## Configuration

Settings come from the environment, or from `.env`.
Field names map straight to variable names.

| Variable | Default | Notes |
|---|---|---|
| `ENVIRONMENT` | `local` | `local`, `staging`, `preview` or `production`. |
| `LOG_LEVEL` | `INFO` | |
| `LOG_FORMAT` | `json` | `text` for local development. |
| `SENTRY_DSN` | unset | Sentry is off when unset. |
| `SENTRY_TRACES_SAMPLE_RATE` | `0.0` | |
| `SENTRY_RELEASE` | `<service>@<version>` | The deploy sets it to the revision. |
| `AUTH_PROVIDER` | `workos` | `local` lets every request in as a fixed identity. `fake` does so only for `AUTH_FAKE_TOKEN`. Both need `ENVIRONMENT=local`. |
| `AUTH_ENFORCE` | `true` | `false` is shadow mode: refusals are logged, not enforced. |
| `AUTH_ALLOW_PRODUCTION_SHADOW` | `false` | Allows `AUTH_ENFORCE=false` in production, which is otherwise refused. |
| `AUTH_LOCAL_PERMISSIONS` | empty | Permissions of the local identity, comma separated. |
| `AUTH_LOCAL_ROLES` | empty | Roles of the local identity, comma separated. |
| `AUTH_FAKE_TOKEN` | `fake-access-token` | The one bearer token `AUTH_PROVIDER=fake` accepts. |
| `WORKOS_CLIENT_ID` | unset | This service's WorkOS application id. Required with `AUTH_PROVIDER=workos`. |
| `WORKOS_ADDITIONAL_CLIENT_IDS` | empty | Other applications whose user tokens are accepted, such as a CLI. |
| `WORKOS_ACCEPT_BOOKSHELF_TOKENS` | `false` | Also accept user tokens from the `bookshelf` CLI's application. |
| `WORKOS_REQUIRED_FEATURE_FLAG` | unset | Feature flag the user's organisation must have, such as `app:bookshelf`. |
| `WORKOS_ALLOWED_ORGANIZATION_IDS` | empty | Organisations allowed in. Empty allows any. |
| `WORKOS_MACHINE_CLIENTS` | `{}` | JSON mapping machine client ids to the permissions each is granted. |
| `WORKOS_ENVIRONMENT` | from `ENVIRONMENT` | `production` or `staging`, to override the mapping below. |
| `WORKOS_API_KEY` | unset | Secret. Only needed for `WorkOSClient`. |

Every variable except `WORKOS_API_KEY` is public,
so it belongs in the deploy config rather than in chamber.

### WorkOS environments

`ENVIRONMENT=production` verifies tokens from the production WorkOS environment.
Every other environment, `local` included, uses staging.
The values are in `cr_service/workos.py`:

| | Production | Staging |
|---|---|---|
| User-token issuer | `https://auth-api.climateresource.com.au/user_management/client_01KABZE0SFNZXEYZ337HSVBZ36` | `https://auth-api.climateresource.com.au/user_management/client_01KABZE0E62YS9H7BMV6YZGMD1` |
| User-token JWKS | `https://auth-api.climateresource.com.au/sso/jwks/client_01KABZE0SFNZXEYZ337HSVBZ36` | `https://auth-api.climateresource.com.au/sso/jwks/client_01KABZE0E62YS9H7BMV6YZGMD1` |
| Machine-token issuer | `https://auth.climateresource.com.au` | `https://balanced-universe-28-staging.authkit.app` |
| Bookshelf CLI application | `client_01KY695M48CT84XBQ53EDTG8PE` | `client_01M2EV5XYS01J8283Q89M9BHQM` |

Each environment signs every application's tokens with one key,
so the JWKS is the same whichever application a token was minted for.
The issuer names the environment's default application, not the service's own.
`settings.public_auth_config()` returns what a browser needs to sign in, for a `/config` endpoint.

## Authentication

`CurrentPrincipal` answers 401 without a valid token.
`OptionalPrincipal` is `None` without a token, and still answers 401 for an invalid one.
`require_permission(...)` and `require_feature_flag(...)` answer 403.
Guard on permissions, never on role names.

A verified token becomes a `Principal`:

- `kind` is `user`, `machine`, `local` (from the `local` or `fake` provider),
  or `anonymous` for a caller let through by shadow mode.
- `id` is the WorkOS user id, or the machine client id.
- `organization_id`, `permissions`, `feature_flags`, `role` and `roles` come from the token.
- `email`, `first_name`, `last_name` and `organization_name` come from the Climate Resource JWT template.
- `claims` holds every verified claim.

User tokens must be RS256, signed by the environment key, carry the environment issuer, and not be expired.
When a token names the application it was minted for, that must be `WORKOS_CLIENT_ID`
or one of `WORKOS_ADDITIONAL_CLIENT_IDS`,
or the bookshelf CLI's application when `WORKOS_ACCEPT_BOOKSHELF_TOKENS=true`.
Machine tokens are only accepted from client ids listed in `WORKOS_MACHINE_CLIENTS`,
and their permissions come from that list, never from the token.

### Bookshelf tokens

With `WORKOS_ACCEPT_BOOKSHELF_TOKENS=true`, anyone signed in with the `bookshelf` CLI can call the service:

```sh
curl -H "Authorization: Bearer $(bookshelf auth token)" https://my-service.example/v1/me
```

The CLI refreshes the token when it is due.
This covers `bookshelf auth login` only.
Its `bsat_` agent tokens are opaque to WorkOS, so they are still refused.

The JWKS is cached for an hour.
An unknown key id triggers one early refetch, at most once a minute.
When a refetch fails the stale keys keep serving,
and with no keys at all the request gets a 503 rather than a 401.

### Extending auth

`setup` takes an `AuthConfig`, whose fields are all optional:

- `on_success` and `on_failure` are callbacks run after each attempt, for example to write an audit log.
- `authenticator` replaces the one built from the settings,
  so a service with its own token types, such as Bookshelf's agent tokens,
  can wrap `build_authenticator(settings)`.
- `resource_metadata_url` adds an RFC 9728 `resource_metadata` hint to 401 responses.

```python
from cr_service import AuthConfig


def audit_success(request, principal):
    audit_log.info("authn_login_success", extra={"user_id": principal.id})


cr_service.setup(app, service=SERVICE, settings=settings, auth=AuthConfig(on_success=[audit_success]))
```

The callbacks run after the built-in ones.
Those bind `user_id`, `organization_id`, `auth_kind` and `auth_client_id` to the log context,
set the Sentry user id and `organization_id` tag, stamp `enduser.id` on the span,
and log an `auth_failed` record with the reason for each refusal.
Emails and names are never attached.

Each attempt also binds `auth_outcome`, which is `pass`, `fail`, `shadow_fail`, or `skipped` for `AUTH_PROVIDER=local`.
Responses carry it as the `x-auth-status` header, with `shadow_fail` reported as `fail`.
A route that never checks auth, or an optional one called without a token, gets no header.

## Logging

`cr_service.bind(**fields)` adds fields to the current request's log context.
Every record logged while the request runs carries them,
and so does the `http_request` wide event emitted when it finishes.
The middleware opens a fresh context per request, holding its `request_id`.
Outside a request, `with cr_service.log_scope(job_id=...):` opens one.

The JSON line holds `ts`, `level`, `logger` and `message`,
then `service`, `version`, `commit`, `env` and `instance_id`,
then the request context, then the record's `extra`.
A 422's validation errors land on the wide event as `validation_errors`.

`configure_logging(SERVICE)` at import reads `LOG_LEVEL`, `LOG_FORMAT` and `ENVIRONMENT` through `ServiceSettings`.
It only replaces its own root handler, so handlers added by anything else stay.
A service with its own logging stack can skip `configure_logging` and keep what it has.
The context is still available:
structlog users add `cr_service.logging_config.merge_request_context` to their processors,
and anything else can read `cr_service.get_context()`.

## Other helpers

- `cr_service.auth.workos_api.WorkOSClient` fetches users and organisations with `WORKOS_API_KEY`,
  and pages through an organisation's members.
- `cr_service.tracing.instrument_sqlalchemy(engine)` adds a span per statement.
  It needs `opentelemetry-instrumentation-sqlalchemy` installed.
- `cr_service.tracing.set_span_attributes(...)` and `current_trace_context()` work without the tracing extra.

## Testing a service

```python
import pytest
from fastapi.testclient import TestClient

from cr_service.auth.testing import TokenFactory


@pytest.fixture
def tokens(settings):
    return TokenFactory.for_settings(settings)


@pytest.fixture
def client(settings, tokens):
    app = build_app()
    tokens.install(app, settings)
    return TestClient(app)


def test_create_thing(client, tokens):
    response = client.post("/v1/things", headers=tokens.headers(permissions=["things:write"]))
    assert response.status_code == 200
```

`tokens.install` swaps in a verifier that trusts the factory's key, keeping the app's `AuthConfig` callbacks.
`tokens.user_token(...)` and `tokens.machine_token(...)` sign tokens shaped like the real ones,
and `tokens.sign(claims)` signs anything, for malformed-token tests.

## Migrating a templated service

1. Add `cr-service[tracing,profiling]` to the dependencies.
2. Delete `logging_config.py`, `middleware.py`, `sentry.py`, `tracing.py`, `metrics.py`, `profiling.py`
   and `routes/health.py`.
3. Make `Settings` subclass `cr_service.ServiceSettings` and drop the fields it now provides.
4. Replace the body of `build_app` with the quick-start shape above.
5. Replace any hand-written WorkOS verifier with the dependencies, and move its variables to the names above.
6. Regenerate `docs/openapi.json`, which gains the `WorkOS` bearer security scheme.

## Development

```sh
make virtual-environment
make test
make checks
```

Each pull request adds a changelog fragment, see `changelog/README.md`.
Releases go through the `Bump version` workflow, and tags publish to PyPI.
