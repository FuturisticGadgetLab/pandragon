"""
Options Widget

Brutalist flat panel with disconnect, quit, and theme switching.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QComboBox,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

_MONO = QFont("Consolas", 10)
_MONO_BOLD = QFont("Consolas", 10, QFont.Weight.Bold)
_MONO.setStyleHint(QFont.StyleHint.Monospace)
_MONO_BOLD.setStyleHint(QFont.StyleHint.Monospace)

_BTN_STYLE = (
    "QPushButton {"
    "  background-color: #2a2a2a;"
    "  border: 1px solid #555;"
    "  color: #e0e0e0;"
    "  padding: 8px 16px;"
    "  min-width: 180px;"
    "}"
    "QPushButton:hover { border: 1px solid #888; }"
)
_DISCONNECT_STYLE = (
    "QPushButton#disconnectBtn {"
    "  background-color: #2a1a1a;"
    "  border: 1px solid #4a2a2a;"
    "  color: #f88;"
    "  padding: 8px 16px;"
    "  min-width: 180px;"
    "}"
    "QPushButton#disconnectBtn:hover { border: 1px solid #8a4a4a; }"
)
_LABEL_STYLE = "color: #888;"


class OptionsWidget(QWidget):
    """Options panel with disconnect, quit, and theme control."""

    def __init__(self, disconnect_callback, theme_mgr, parent=None):
        super().__init__(parent)
        self._disconnect_cb = disconnect_callback

        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        inner = QVBoxLayout()
        inner.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        inner.setSpacing(8)

        w = 300

        title = QLabel("OPTIONS")
        title.setFont(_MONO_BOLD)
        title.setStyleSheet("color: #e0e0e0;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFixedWidth(w)
        inner.addWidget(title, alignment=Qt.AlignmentFlag.AlignHCenter)

        inner.addSpacing(12)

        disconnect_btn = QPushButton("Disconnect")
        disconnect_btn.setObjectName("disconnectBtn")
        disconnect_btn.setFont(_MONO_BOLD)
        disconnect_btn.setStyleSheet(_DISCONNECT_STYLE)
        disconnect_btn.setFixedWidth(w)
        disconnect_btn.clicked.connect(self._disconnect_cb)
        inner.addWidget(disconnect_btn, alignment=Qt.AlignmentFlag.AlignHCenter)

        inner.addSpacing(6)

        quit_btn = QPushButton("Quit")
        quit_btn.setFont(_MONO)
        quit_btn.setStyleSheet(_BTN_STYLE)
        quit_btn.setFixedWidth(w)
        quit_btn.clicked.connect(self._quit_app)
        inner.addWidget(quit_btn, alignment=Qt.AlignmentFlag.AlignHCenter)

        inner.addSpacing(20)

        theme_lbl = QLabel("Theme")
        theme_lbl.setFont(_MONO)
        theme_lbl.setStyleSheet(_LABEL_STYLE)
        theme_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        theme_lbl.setFixedWidth(w)
        inner.addWidget(theme_lbl, alignment=Qt.AlignmentFlag.AlignHCenter)

        combo = theme_mgr.make_switcher()
        combo.setFont(_MONO)
        combo.setFixedWidth(w)
        inner.addWidget(combo, alignment=Qt.AlignmentFlag.AlignHCenter)

        outer.addLayout(inner)

    def _quit_app(self):
        from PyQt6.QtWidgets import QApplication
        QApplication.quit()
