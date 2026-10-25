"""Platform specific log sources for the LAD collector."""

from __future__ import annotations

import sys
from typing import Any, Callable, Iterator, Optional

from .core.runtime import StreamMerger, UnavailableSource


def get_stream_factories(
    redactor: Any,
    *,
    hostname: Optional[str] = None,
) -> list[tuple[str, Callable[[], Iterator[Any]]]]:
    """Return the enabled ``(name, factory)`` sources for the current OS."""
    platform = sys.platform

    if platform.startswith("linux"):
        from .linux.collector import iter_linux_sources

        return iter_linux_sources(redactor, hostname=hostname)

    if platform.startswith("win") or platform in ("cygwin", "msys"):
        from .windows.collector import iter_windows_sources

        return iter_windows_sources(redactor, hostname=hostname)

    raise NotImplementedError(
        f"Unsupported operating system: '{platform}'. "
        "Supported platforms are Linux and Windows."
    )


__all__ = [
    "StreamMerger",
    "UnavailableSource",
    "get_stream_factories",
]
