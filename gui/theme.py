"""
Pandragon Theme Manager

Loads and applies .qss stylesheets from the gui/themes/ directory.
Provides runtime theme switching via signal and a combo-box helper.
"""

import os
from typing import Optional

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication, QComboBox

from gui.state import load as load_state, save as save_state


class ThemeManager(QObject):
    """Loads .qss files from gui/themes/ and applies them app-wide."""

    theme_changed = pyqtSignal(str)

    def __init__(self, app: QApplication, parent=None):
        super().__init__(parent)
        self._app = app
        self._themes_dir = os.path.join(os.path.dirname(__file__), "themes")
        self._current: str = "neon"
        self._theme_cache: dict[str, str] = {}

        # Pre-load all available themes
        self._discover_themes()

        # Restore last-used theme
        saved = load_state()
        last = saved.get("last_theme", "neon")
        if last not in self._theme_cache:
            last = "neon"
        self._current = last
        self.apply(self._current)

    # ── Public API ─────────────────────────────────────────────────

    @property
    def current(self) -> str:
        return self._current

    def names(self) -> list[str]:
        """Return sorted list of available theme names."""
        return sorted(self._theme_cache.keys())

    def apply(self, name: str) -> bool:
        """Apply a theme by name. Returns True on success."""
        qss = self._theme_cache.get(name)
        if qss is None:
            # Try loading from disk
            path = os.path.join(self._themes_dir, f"{name}.qss")
            if not os.path.isfile(path):
                return False
            try:
                with open(path, "r", encoding="utf-8") as f:
                    qss = f.read()
                self._theme_cache[name] = qss
            except OSError:
                return False

        self._app.setStyleSheet(qss)
        self._current = name
        save_state({"last_theme": name})
        self.theme_changed.emit(name)
        return True

    # ── Theme switcher widget ──────────────────────────────────────

    def make_switcher(self) -> QComboBox:
        """Create a QComboBox populated with available themes."""
        cb = QComboBox()
        for name in self.names():
            cb.addItem(name.capitalize(), name)
        cb.setCurrentText(self._current.capitalize())
        cb.currentIndexChanged.connect(
            lambda idx: self.apply(cb.itemData(idx))
        )
        return cb

    # ── Internal ───────────────────────────────────────────────────

    def _discover_themes(self):
        if not os.path.isdir(self._themes_dir):
            return
        for fname in os.listdir(self._themes_dir):
            if fname.endswith(".qss"):
                name = fname[:-4]
                path = os.path.join(self._themes_dir, fname)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        self._theme_cache[name] = f.read()
                except OSError:
                    pass
