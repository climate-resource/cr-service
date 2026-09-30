# Changelog

Versions follow [Semantic Versioning](https://semver.org/) (`<major>.<minor>.<patch>`).

Backward incompatible (breaking) changes will only be introduced in major versions
with advance notice in the **Deprecations** section of releases.

<!--
You should *NOT* be adding new changelog entries to this file,
this file is managed by towncrier.
See `changelog/README.md`.

You *may* edit previous changelogs to fix problems like typo corrections or such.
To add a new changelog entry, please see
`changelog/README.md`
and https://pip.pypa.io/en/latest/development/contributing/#news-entries,
noting that we use the `changelog` directory instead of news,
markdown instead of restructured text and use slightly different categories
from the examples given in that link.
-->

<!-- towncrier release notes start -->

## cr-service v0.5.0 (2026-09-30)

### Breaking Changes

- Enforces authorisation in shadow mode.
  With `AUTH_ENFORCE=false` only authentication failures let the caller through as anonymous.
  A missing permission or feature flag, a disallowed organisation or a failed request check now answers 403.
  Refuses trust profiles that share an issuer with `AuthConfigurationError`. ([#11](https://github.com/climate-resource/cr-service/pull/11))

### Features

- Exports `install_auth`, which installs auth without the rest of `setup`.
  Adds `AuthConfig.authenticator_dependency`, a FastAPI dependency that builds the authenticator for each request and can wrap `base_authenticator`.
  Adds `AuthConfig.has_permission`, which decides what `require_permission` accepts.
  Adds `AuthConfig.request_checks`, which can refuse any authenticated request and run again whenever the cached caller is reused.
  Adds the `agent` principal kind and `Principal.delegated_user_id`.
  Adds the `none` credential, which records an attempt as `skipped` even when a service wraps `LocalAuthenticator`.
  Sets `request.state.auth_outcome`.
  Allows `AuthConfig.resource_metadata_url` to be a callable that builds the URL from the request. ([#11](https://github.com/climate-resource/cr-service/pull/11))


## cr-service v0.4.0 (2026-09-30)

### Features

- Accepts WorkOS API keys owned by a user or an organisation as bearer tokens, behind `WORKOS_ACCEPT_API_KEYS`. ([#10](https://github.com/climate-resource/cr-service/pull/10))


## cr-service v0.3.1 (2026-09-28)

### Bug Fixes

- Names the OpenAPI security scheme `HTTPBearer` with the description "Access token", so the schema no longer names the identity provider. ([#9](https://github.com/climate-resource/cr-service/pull/9))


## cr-service v0.3.0 (2026-09-28)

### Features

- Adds `WORKOS_ACCEPT_BOOKSHELF_TOKENS`, which accepts user tokens from the `bookshelf` CLI,
  so `$(bookshelf auth token)` works as a bearer token.
  Adds `AUTH_PROVIDER=fake`, which returns the local identity only for `AUTH_FAKE_TOKEN`.
  Adds `AUTH_LOCAL_ROLES`, the roles of the local identity.
  Adds `AUTH_ALLOW_PRODUCTION_SHADOW`, which allows `AUTH_ENFORCE=false` in production. ([#5](https://github.com/climate-resource/cr-service/pull/5))
- Adds the `x-auth-status` response header, which is `pass`, `fail` or `skipped`. ([#6](https://github.com/climate-resource/cr-service/pull/6))
- Adds `WORKOS_MACHINE_CLIENT_ORGANIZATIONS`, which binds machine clients to the organisations they may act for.
  Refuses machine tokens without an `org_id`.
  Adds `WORKOS_REQUIRE_EMAIL`, which refuses user tokens without an email.
  Adds `try_authenticate`, which returns the caller or `None` without refusing the request.
  Redacts token-like query parameters on the wide event. ([#7](https://github.com/climate-resource/cr-service/pull/7))
- Masks log fields whose names look like credentials, plus names listed in `LOG_REDACT_KEYS`.
  Adds `redact_paths` to `setup`, which logs those routes without their query or referer.
  Logs the wide event at `error` for any 5xx response, not only when the route raised. ([#8](https://github.com/climate-resource/cr-service/pull/8))


## cr-service v0.2.0 (2026-09-28)

### Trivial/Internal Changes

- [#4](https://github.com/climate-resource/cr-service/pull/4)


## cr-service v0.1.0 (2026-09-28)

### Features

- Adds WorkOS access-token verification with FastAPI dependencies, baked-in production and staging WorkOS settings, request-scoped log context, the wide-event middleware, Sentry, tracing, metrics, profiling and health probes. ([#1](https://github.com/climate-resource/cr-service/pull/1))
