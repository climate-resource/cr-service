"""Prometheus metrics via prometheus-fastapi-instrumentator."""

import fastapi
from prometheus_fastapi_instrumentator import Instrumentator

LATENCY_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0, 30.0)


def instrument_app(app: fastapi.FastAPI) -> None:
    """Instrument the app and expose it at ``/metrics``.

    Registers the default request-count and latency histograms
    (``http_requests_total``, ``http_request_duration_seconds``).
    Any counter or histogram made with ``prometheus_client`` shows up there too.
    """
    Instrumentator(
        excluded_handlers=["/metrics", "/livez", "/readyz"],
        should_group_status_codes=False,
    ).instrument(app, latency_lowr_buckets=LATENCY_BUCKETS).expose(app, include_in_schema=False)
