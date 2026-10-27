"""Fan-in of multiple blocking log streams into one iterator.

Each source runs in its own daemon thread.  A crash in one source (for
example: no permission for the Windows Security channel) never stops the
others, and the failing source is retried with capped exponential backoff.
Sources that raise :class:`UnavailableSource` are considered permanently
unavailable and are not retried.
"""

from __future__ import annotations

import logging
import os
import queue
import threading
from typing import Any, Callable, Iterable, Iterator


class UnavailableSource(Exception):
    """Raised when a source cannot ever work on this host (no permission, ...)."""


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on", "y")


class StreamMerger:
    """Run ``(name, factory)`` sources concurrently and yield their events."""

    def __init__(
        self,
        sources: Iterable[tuple[str, Callable[[], Iterator[Any]]]],
        *,
        max_queue: int = 10000,
        stop_timeout: float = 5.0,
    ):
        self._sources = list(sources)
        self._queue: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=max_queue)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._started = False
        self._stop_timeout = stop_timeout

    @property
    def source_names(self) -> list[str]:
        return [name for name, _ in self._sources]

    def start(self) -> "StreamMerger":
        if self._started:
            return self
        self._started = True
        for name, factory in self._sources:
            thread = threading.Thread(
                target=self._run_source,
                args=(name, factory),
                name=f"lad-source-{name}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)
        return self

    def _put(self, name: str, event: Any) -> bool:
        while not self._stop.is_set():
            try:
                self._queue.put((name, event), timeout=1.0)
                return True
            except queue.Full:
                # Backpressure: the consumer is slower than the sources.
                continue
        return False

    def _run_source(self, name: str, factory: Callable[[], Iterator[Any]]) -> None:
        backoff = 5.0
        debug = _env_bool("LAD_DEBUG_STREAMS", False)

        while not self._stop.is_set():
            try:
                for event in factory():
                    if self._stop.is_set():
                        break
                    if not self._put(name, event):
                        break

                if self._stop.is_set():
                    break

                logging.warning(
                    "[%s] stream ended unexpectedly; restarting in %.0fs", name, backoff
                )
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 60.0)
            except UnavailableSource as exc:
                logging.error("[%s] source unavailable: %s", name, exc)
                break
            except Exception as exc:  # noqa: BLE001 - one bad source must not kill all
                logging.error("[%s] stream failed: %s", name, exc, exc_info=debug)
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 60.0)

        logging.debug("[%s] stream thread stopped", name)

    def __iter__(self) -> Iterator[Any]:
        if not self._started:
            self.start()

        while True:
            try:
                _name, event = self._queue.get(timeout=0.5)
                yield event
            except queue.Empty:
                if self._stop.is_set():
                    break
                if not any(thread.is_alive() for thread in self._threads):
                    break

    def close(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=self._stop_timeout)

    def __enter__(self) -> "StreamMerger":
        return self.start()

    def __exit__(self, *_exc_info: Any) -> None:
        self.close()
