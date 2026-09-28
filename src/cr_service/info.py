"""Identity of the service using this package."""

import dataclasses


@dataclasses.dataclass(frozen=True, slots=True)
class ServiceInfo:
    """Name and version stamped on logs, Sentry releases, traces and profiles.

    Parameters
    ----------
    name
        Distribution name of the service, for example ``ndc-doc-pipeline``.
    version
        Version of the service, usually its ``__version__``.
    """

    name: str
    version: str
