"""Shared configuration helpers for collector sources."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable


def env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean environment flag."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on", "y")


def env_list(name: str) -> tuple[str, ...]:
    """Read a comma- or semicolon-separated environment list."""
    value = os.getenv(name, "")
    return tuple(
        part.strip() for part in value.replace(";", ",").split(",") if part.strip()
    )


@dataclass(frozen=True)
class FileSourceSpec:
    """A file/glob based log source.

    ``prefer_file`` means: when journald is available, still read this file
    (used for database logs, which are richer on disk).
    """

    name: str
    category: str
    default_type: str
    patterns: tuple[str, ...]
    prefer_file: bool = False
    description: str = ""


def expand_patterns(patterns: Iterable[str]) -> tuple[str, ...]:
    """Expand env vars and ``~`` in configured globs."""
    expanded = []
    for pattern in patterns:
        expanded.append(os.path.expanduser(os.path.expandvars(pattern)))
    return tuple(expanded)
