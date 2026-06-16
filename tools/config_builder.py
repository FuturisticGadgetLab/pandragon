#!/usr/bin/env python3
"""
Pandragon Beacon Config Builder (CLI shim)

Installed as 'pandragon-config-builder' when the package is installed.
For development, run directly from the repo root:
    python tools/config_builder.py Beacon/config/default.json
"""

import sys
import os

# Allow running from repo root without installing the package
_pkg_dir = os.path.join(os.path.dirname(__file__), "src")
if os.path.isdir(_pkg_dir) and _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

from pandragon_config_builder.builder import main

if __name__ == "__main__":
    main()
