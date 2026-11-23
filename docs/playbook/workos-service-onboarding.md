---
type: Operations
title: WorkOS service contract
description: How a client-facing Python service verifies WorkOS tokens through cr-service, the settings it reads, the local-only auth guards, and shadow rollout.
tags: [identity, workos, security]
timestamp: 2026-11-23
---

# WorkOS service contract

This is the backend half of adopting WorkOS: how a service verifies tokens and what cr-service needs from it.
Every Python service verifies tokens through cr-service rather than writing its own verifier.
The [README](https://github.com/climate-resource/cr-service#configuration) lists every variable,
so this page does not repeat them.

- [WorkOS core configuration](https://playbook.climate-resource.workers.dev/infrastructure/production/workos-core-config/)
  owns the tenant: environments, domains, the JWT template, roles, and where each setting lives.
- [Authorisation and entitlements](https://playbook.climate-resource.workers.dev/engineering/preferences/authorisation/)
  owns the policy these settings enforce.

## The shape of it

The browser signs in with AuthKit,
and sends the WorkOS access token (a JWT) as `Authorization: Bearer <token>`.
cr-service verifies it locally against the environment's JWKS
and reads identity, organisation, permissions and feature flags from the verified claims.

- A user token must be RS256, carry the environment issuer, a key id, `sub`, `iat` and `exp`,
  and not be expired.
- When the token names the application it was minted for,
  that must be `WORKOS_CLIENT_ID`, one of `WORKOS_ADDITIONAL_CLIENT_IDS`,
  or the `bookshelf` CLI's application when `WORKOS_ACCEPT_BOOKSHELF_TOKENS=true`.
- The JWKS is cached for an hour, with one early refetch for an unknown key id.
  A failed refetch keeps the stale keys serving, and no keys at all answers 503 rather than 401.

No WorkOS API call sits on the request path for a token.
The exception is `WORKOS_ACCEPT_API_KEYS=true`:
each API key is validated with the WorkOS API and cached for a minute.

## Settings

The service's settings class subclasses `cr_service.ServiceSettings`, which reads cr-service's variable names.
`ENVIRONMENT=production` selects the production WorkOS environment, and every other value, `local` included,
selects staging.
That choice brings the API hostname, issuers and JWKS URLs with it,
so no service sets them.
Production refuses to start against the staging WorkOS environment, even with `WORKOS_ENVIRONMENT` set.

The values a service sets itself:

- `WORKOS_CLIENT_ID`, the service's own application id, required with `AUTH_PROVIDER=workos`.
- `WORKOS_REQUIRED_FEATURE_FLAG`, the entitlement flag the caller's organisation must have.
- `WORKOS_ALLOWED_ORGANIZATION_IDS` and `WORKOS_MACHINE_CLIENTS`, when the service needs them.
- `WORKOS_API_KEY`, the only secret, needed only for `WorkOSClient` and `WORKOS_ACCEPT_API_KEYS`.

A missing flag or a disallowed organisation answers 403.
[Where each value lives](https://playbook.climate-resource.workers.dev/infrastructure/production/workos-core-config/#where-each-value-lives)
is owned by core configuration.

## Local-only auth guards

`AUTH_PROVIDER=local` lets every request in as a fixed identity.
`AUTH_PROVIDER=fake` does the same only for the `AUTH_FAKE_TOKEN` bearer token.
Both are accepted only when `ENVIRONMENT=local`.
The settings validator raises otherwise,
so a misconfigured deploy fails at startup rather than running unauthenticated.

## Shadow rollout

`AUTH_ENFORCE=false` runs auth in shadow mode.
A caller whose credentials are missing, invalid or cannot be checked continues as the `anonymous` principal.
Authorisation is still enforced,
so a missing permission or feature flag and a disallowed organisation answer 403.

Each attempt logs `auth_outcome` (`pass`, `fail`, `shadow_fail` or `skipped`)
and returns it in the `x-auth-status` response header, where `shadow_fail` reads as `fail`.
So the header shows which requests enforcement would refuse, and the logs tell those apart from real refusals.

Production refuses `AUTH_ENFORCE=false` unless `AUTH_ALLOW_PRODUCTION_SHADOW=true`.
A service rolls auth out in shadow mode, watches the failures, then sets `AUTH_ENFORCE=true` to answer 401.

## Backend checklist

Work through staging first, then production.
The dashboard side (application, flags, redirect URIs) is
[WorkOS app onboarding](https://playbook.climate-resource.workers.dev/infrastructure/production/workos-app-onboarding/).

- [ ] Use cr-service 0.5.2 or later.
      Earlier releases let authorisation failures through in shadow mode,
      and organisation API keys past the required flag.
- [ ] Read settings through a subclass of `cr_service.ServiceSettings`.
- [ ] Set `ENVIRONMENT` correctly for the deployment, and leave `WORKOS_ENVIRONMENT` unset.
- [ ] Set `WORKOS_CLIENT_ID` for that WorkOS environment, and check it with the `curl` command in
      [core configuration](https://playbook.climate-resource.workers.dev/infrastructure/production/workos-core-config/#where-each-value-lives).
- [ ] Set `WORKOS_REQUIRED_FEATURE_FLAG` to the product's entitlement flag.
- [ ] Leave `AUTH_PROVIDER` at its default, `workos`.
- [ ] Roll out with `AUTH_ENFORCE=false`, watch `x-auth-status` and the `shadow_fail` logs, then enforce.
- [ ] Confirm an organisation without the flag gets 403,
      and a member of an entitled organisation gets exactly the permissions the product expects.
