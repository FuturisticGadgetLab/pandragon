"""
Notification Overlay

Toast-style notifications that slide in from the top-right corner
and auto-dismiss after a configurable timeout. Non-blocking replacement
for QMessageBox informational/warning messages.
"""

import time
from typing import Optional
from collections import deque

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QApplication,
    QSizePolicy,
)
from PyQt6.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve, QParallelAnimationGroup,
    QPoint, QRect, pyqtSignal,
)
from PyQt6.QtGui import QFont, QColor, QPainter


_STYLES = {
    "info":    {"bg": "#16213e", "border": "#2a82da", "icon": "\u2139\uFE0F"},
    "success": {"bg": "#0a2a0a", "border": "#00cc00", "icon": "\u2705"},
    "warning": {"bg": "#2a2a00", "border": "#ffaa00", "icon": "\u26A0\uFE0F"},
    "error":   {"bg": "#2a0000", "border": "#ff4444", "icon": "\u274C"},
}


class _Notification(QWidget):
    """A single notification toast."""

    DISMISSED = pyqtSignal(object)

    def __init__(self, message: str, style: str = "info",
                 timeout_ms: int = 4000, parent=None):
        super().__init__(parent)
        self._timeout_ms = timeout_ms
        self._dismissed = False
        self._slide_anim: Optional[QPropertyAnimation] = None

        self.setFixedWidth(360)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Minimum)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)

        s = _STYLES.get(style, _STYLES["info"])

        # Base stylesheet for this notification
        self._base_css = (
            f"background-color: {s['bg']}; border: 1px solid {s['border']}; "
            f"border-radius: 4px; padding: 8px;"
        )

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)

        # Icon
        icon = QLabel(s["icon"])
        icon.setFont(QFont("Segoe UI Emoji", 12))
        icon.setFixedWidth(20)
        layout.addWidget(icon)

        # Message
        msg = QLabel(message)
        msg.setWordWrap(True)
        msg.setStyleSheet("color: #e0e0e0; font-size: 9pt; background: transparent;")
        msg.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)
        layout.addWidget(msg, 1)

        # Close button
        close_btn = QPushButton("\u00D7")
        close_btn.setFixedSize(18, 18)
        close_btn.setStyleSheet(
            "QPushButton { background: transparent; border: none; color: #888; font-size: 14px; }"
            "QPushButton:hover { color: white; }"
        )
        close_btn.clicked.connect(self._on_dismiss)
        layout.addWidget(close_btn)

    def paintEvent(self, a0):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = self._base_css
        # Parse bg color from _base_css (simplified)
        painter.setBrush(QColor(22, 33, 62))
        painter.setPen(QColor(42, 130, 218))
        painter.drawRoundedRect(self.rect().adjusted(1, 1, -1, -1), 4, 4)

    def show_with_slide(self):
        # Start offscreen to the right
        parent_w = self.parent().width() if self.parent() else 800
        self.move(parent_w, self.pos().y())
        self.show()

        # Slide in
        target_x = parent_w - self.width() - 12
        self._slide_anim = QPropertyAnimation(self, b"pos")
        self._slide_anim.setDuration(250)
        self._slide_anim.setStartValue(QPoint(parent_w, self.pos().y()))
        self._slide_anim.setEndValue(QPoint(target_x, self.pos().y()))
        self._slide_anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._slide_anim.start()

        # Auto-dismiss timer
        if self._timeout_ms > 0:
            QTimer.singleShot(self._timeout_ms, self._on_dismiss)

    def slide_out(self, callback=None):
        if self._dismissed:
            return
        self._dismissed = True

        parent_w = self.parent().width() if self.parent() else 800
        self._slide_anim = QPropertyAnimation(self, b"pos")
        self._slide_anim.setDuration(200)
        self._slide_anim.setStartValue(self.pos())
        self._slide_anim.setEndValue(QPoint(parent_w + 50, self.pos().y()))
        self._slide_anim.setEasingCurve(QEasingCurve.Type.InCubic)
        if callback:
            self._slide_anim.finished.connect(callback)
        self._slide_anim.finished.connect(self.deleteLater)
        self._slide_anim.start()

    def _on_dismiss(self):
        if self._dismissed:
            return
        self._dismissed = True
        self.slide_out(callback=lambda: self.DISMISSED.emit(self))


class NotificationOverlay(QWidget):
    """
    Floating notification overlay for the main window.

    Usage:
        overlay = NotificationOverlay(main_window)
        overlay.info("Beacon checked in")
        overlay.error("Connection lost", timeout=0)  # persists until dismissed
    """

    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, False)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)

        # Position in top-right corner of parent
        self._notifications: list[_Notification] = []

        # We re-layout whenever the parent is resized
        parent.installEventFilter(self)

    # ── Public API ─────────────────────────────────────────────────

    def info(self, message: str, timeout_ms: int = 4000):
        self._add(message, "info", timeout_ms)

    def success(self, message: str, timeout_ms: int = 3000):
        self._add(message, "success", timeout_ms)

    def warning(self, message: str, timeout_ms: int = 5000):
        self._add(message, "warning", timeout_ms)

    def error(self, message: str, timeout_ms: int = 0):
        """Errors persist until dismissed by default (timeout=0)."""
        self._add(message, "error", timeout_ms)

    # ── Internal ──────────────────────────────────────────────────

    def _add(self, message: str, style: str, timeout_ms: int):
        n = _Notification(message, style, timeout_ms, self)
        n.setVisible(False)
        self._notifications.append(n)

        # Position below existing notifications
        y_offset = 12 + sum(
            w.sizeHint().height() + 6 for w in self._notifications[:-1]
        )
        n.move(self._calc_x(n), y_offset)

        n.show_with_slide()

        # Auto-remove from list on dismiss
        n.DISMISSED.connect(lambda: self._remove(n))

        self._reposition_all()

    def _remove(self, n: _Notification):
        if n in self._notifications:
            self._notifications.remove(n)
        self._reposition_all()

    def _reposition_all(self):
        y = 12
        for n in list(self._notifications):
            if n.isVisible() and not n._dismissed:
                target_y = y
                if n.pos().y() != target_y:
                    anim = QPropertyAnimation(n, b"pos")
                    anim.setDuration(200)
                    anim.setStartValue(n.pos())
                    anim.setEndValue(QPoint(self._calc_x(n), target_y))
                    anim.setEasingCurve(QEasingCurve.Type.OutCubic)
                    anim.start()
                y += n.sizeHint().height() + 6

    def _calc_x(self, n: _Notification) -> int:
        pw = self.parent().width() if self.parent() else 800
        return pw - n.width() - 12

    def eventFilter(self, obj, event):
        if obj == self.parent() and event.type() == event.Type.Resize:
            self.setGeometry(0, 0, self.parent().width(), self.parent().height())
            self._reposition_all()
        return super().eventFilter(obj, event)
