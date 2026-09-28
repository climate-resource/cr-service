"""Sentry SDK initialisation for error monitoring."""

import logging
import os
from typing import Any

import sentry_sdk

from cr_service.info import ServiceInfo
from cr_service.settings import ServiceSettings

logger = logging.getLogger(__name__)


def init_sentry(settings: ServiceSettings, service: ServiceInfo, **options: Any) -> bool:
    """Initialise Sentry when ``SENTRY_DSN`` is set, returning whether it was.

    ``options`` are passed to ``sentry_sdk.init``, for hooks such as ``before_send``.
    PII stays off, so the only user detail Sentry sees is the id the auth hooks attach.
    """
    if not settings.sentry_dsn:
        return False

    release = os.environ.get("SENTRY_RELEASE") or f"{service.name}@{service.version}"
    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        environment=settings.environment,
        release=release,
        traces_sample_rate=settings.sentry_traces_sample_rate,
        send_default_pii=False,
        **options,
    )
    logger.info(
        "Sentry initialised",
        extra={"sentry_release": release, "traces_sample_rate": settings.sentry_traces_sample_rate},
    )
    return True
