"""Standalone launcher for running the collector from inside this directory.

Use this when ``collectors/`` itself is the repository root::

    python3 run.py

From the parent directory, ``python3 -m collectors`` is also supported.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_local_package():
    package_dir = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location(
        "collectors",
        package_dir / "__init__.py",
        submodule_search_locations=[str(package_dir)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load collector package from {package_dir}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["collectors"] = module
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    if __package__ in (None, ""):
        _load_local_package()
    from collectors.main import main

    raise SystemExit(main())
