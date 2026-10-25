"""Interfaces for application log adapters.

This follows the shared adapter interface in ``project_guidelines.txt``:
application and database adapters translate their raw records into the
universal event envelope without changing the collector engine.
"""

from __future__ import annotations

from typing import Any, Protocol

from ..core.engine import Event


class AppAdapter(Protocol):
    """Minimal contract for an application log adapter."""

    name: str

    def supports(self, raw: Any) -> bool:
        """Return True when this adapter can handle the raw record."""
        ...

    def extract_timestamp(self, raw: Any):
        """Extract a timestamp from the raw record."""
        ...

    def to_envelope(self, raw: Any, ts) -> Event:
        """Convert one raw record into a contract-valid event."""
        ...

    def provides(self) -> set[str]:
        """Return optional features supplied by this source."""
        ...
