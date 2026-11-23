# cr-service

Documentation for the contract cr-service gives the services that use it.

These pages live here rather than in the
[playbook](https://github.com/climate-resource/playbook) because they describe what cr-service does,
so they go stale the moment its code changes.
Keeping them beside the code means a change and its documentation land in the same diff.

The playbook imports this directory at build time,
so the pages are readable at
[playbook.climate-resource.workers.dev](https://playbook.climate-resource.workers.dev/)
alongside the conventions and decisions that stay there.
The [README](https://github.com/climate-resource/cr-service#readme) remains the reference
for every setting and API.

| Page                                                    | Description                                                                                                                                         |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| [WorkOS service contract](workos-service-onboarding.md) | How a client-facing Python service verifies WorkOS tokens through cr-service, the settings it reads, the local-only auth guards, and shadow rollout. |
