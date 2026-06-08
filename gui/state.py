"""
GUI state persistence - loads/saves gui/.state.json

Stores last-used theme, connection details, and other UI preferences
inside the gui/ directory (no ~/.config dependency).
"""

import json
import os

_STATE_FILE = os.path.join(os.path.dirname(__file__), ".state.json")

_DEFAULT = {
    "last_theme": "neon",
    "last_url": "wss://127.0.0.1:6767/ws",
    "last_username": "operator",
    "last_token": "",
}


def _get_path() -> str:
    return _STATE_FILE


def load() -> dict:
    """Load saved state, returning defaults for missing keys."""
    state = dict(_DEFAULT)
    try:
        with open(_STATE_FILE, "r") as f:
            saved = json.load(f)
        if isinstance(saved, dict):
            state.update(saved)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return state


def save(updates: dict):
    """Merge updates into existing state and write atomically."""
    current = load()
    current.update(updates)
    tmp = _STATE_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(current, f, indent=2)
        os.replace(tmp, _STATE_FILE)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
