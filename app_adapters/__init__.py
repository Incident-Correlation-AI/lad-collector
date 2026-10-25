"""Application and file-based adapters."""

from .base import AppAdapter
from .file_tail import FileTailStream

__all__ = ["AppAdapter", "FileTailStream"]
