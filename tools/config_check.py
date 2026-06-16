#!/usr/bin/env python3
"""
Pandragon Config Linter / Validator (CLI shim)

Installed as 'pandragon-config-check' when the package is installed.
For development, run directly from the repo root:
    python tools/config_check.py --check-all
"""

import sys
import os

# Allow running from repo root without installing the package
_pkg_dir = os.path.join(os.path.dirname(__file__), "src")
if os.path.isdir(_pkg_dir) and _pkg_dir not in sys.path:
    sys.path.insert(0, _pkg_dir)

from pandragon_config_builder.checker import main

if __name__ == "__main__":
    import hashlib
    main()
