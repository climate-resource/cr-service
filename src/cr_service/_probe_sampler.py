"""Sampler that keeps probe and scrape hits out of traces. Needs the ``tracing`` extra."""

from collections.abc import Sequence

from opentelemetry.context import Context
from opentelemetry.sdk.trace.sampling import ALWAYS_OFF, ALWAYS_ON, Sampler, SamplingResult
from opentelemetry.trace import Link, SpanKind, TraceState
from opentelemetry.util.types import Attributes

from cr_service.health import PROBE_PATHS


class SkipProbes(Sampler):
    """Drop spans whose ``url.path`` is a probe, sampling everything else."""

    def should_sample(  # noqa: PLR0913, PLR0917
        self,
        parent_context: Context | None,
        trace_id: int,
        name: str,
        kind: SpanKind | None = None,
        attributes: Attributes = None,
        links: Sequence[Link] | None = None,
        trace_state: TraceState | None = None,
    ) -> SamplingResult:
        """Delegate to ``ALWAYS_OFF`` for a probe path and ``ALWAYS_ON`` otherwise."""
        path: object = attributes.get("url.path") if attributes else None
        # Suffix match, so a probe still matches behind a gateway prefix.
        sampler = ALWAYS_OFF if isinstance(path, str) and path.endswith(PROBE_PATHS) else ALWAYS_ON
        return sampler.should_sample(parent_context, trace_id, name, kind, attributes, links, trace_state)

    def get_description(self) -> str:
        """Name the sampler in SDK debug output."""
        return "SkipProbes"
