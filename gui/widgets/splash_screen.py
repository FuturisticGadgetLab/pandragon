"""
Splash Screen / Progress Display

Embeddable widget that displays initialization stages with status icons.
Can be used standalone or embedded in a larger panel.
"""

from typing import Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont


_STAGE_LABELS = {
    "ok":    "[ OK ]",
    "fail":  "[FAIL]",
    "info":  "[INFO]",
    "busy":  "[ .. ]",
    "skip":  "[SKIP]",
}


class _StageLine(QWidget):
    """Single line in the progress list."""

    def __init__(self, text: str, icon_key: str = "busy", parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._icon = QLabel(_STAGE_LABELS.get(icon_key, _STAGE_LABELS["busy"]))
        self._icon.setObjectName(f"stageIcon_{icon_key}")
        layout.addWidget(self._icon)

        self._label = QLabel(text)
        layout.addWidget(self._label)

        layout.addStretch()

    def set_icon(self, icon_key: str):
        self._icon.setText(_STAGE_LABELS.get(icon_key, _STAGE_LABELS["busy"]))
        self._icon.setObjectName(f"stageIcon_{icon_key}")
        # force style re-apply
        self._icon.style().unpolish(self._icon)
        self._icon.style().polish(self._icon)


class SplashScreen(QWidget):
    """
    Embeddable progress display with stage-by-stage status updates.

    Usage:
        splash = SplashScreen(parent)
        idx = splash.add_stage("Connecting...", "busy")
        splash.update_stage(idx, "ok", "Connected")
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._stage_widgets: list[_StageLine] = []
        self.setStyleSheet("background: transparent;")

        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(0, 0, 0, 0)
        self._stage_layout = layout

    def add_stage(self, text: str, icon_key: str = "busy") -> int:
        """Append a stage line. Returns index for later update."""
        line = _StageLine(text, icon_key)
        self._stage_layout.addWidget(line)
        self._stage_widgets.append(line)
        return len(self._stage_widgets) - 1

    def update_stage(self, index: int, icon_key: str, text: Optional[str] = None):
        """Update an existing stage's icon and/or text."""
        if 0 <= index < len(self._stage_widgets):
            self._stage_widgets[index].set_icon(icon_key)
            if text is not None:
                self._stage_widgets[index]._label.setText(text)

    def clear_stages(self):
        """Remove all stages."""
        for w in self._stage_widgets:
            self._stage_layout.removeWidget(w)
            w.deleteLater()
        self._stage_widgets.clear()
