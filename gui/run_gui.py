#!/usr/bin/env python3
"""
Launch the Pandragon GUI Operator Console.

Usage:
    python3 run_gui.py
    python3 run_gui.py --no-ssl-verify

Run from the project root (/sec/root/pandragon) or anywhere.
"""

import sys
import os

# Ensure the project root is on sys.path so `gui.*` imports work
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from gui.main import main

if __name__ == '__main__':
    main()
