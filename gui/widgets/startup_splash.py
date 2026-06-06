from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QMouseEvent


class StartSplash(QWidget):
    """Full-window splash with the Hermes quote, shown briefly on start."""

    finished = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("background-color: #000000;")

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(12)

        label = QLabel(
            '\u201cThe bird of Hermes is my Name,\n'
            'eat my Wings to make me tame\u201d'
        )
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        f = QFont("Georgia", 14)
        f.setStyleHint(QFont.StyleHint.Serif)
        label.setFont(f)
        label.setStyleSheet(
            "color: #c8b8a0; background: transparent; font-style: italic;"
        )
        layout.addWidget(label)

        sub = QLabel("Pandragon")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sf = QFont("Georgia", 10)
        sf.setStyleHint(QFont.StyleHint.Serif)
        sub.setFont(sf)
        sub.setStyleSheet("color: #605040; background: transparent;")
        layout.addWidget(sub)

        credit = QLabel("a serexp / FGL production")
        credit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        cf = QFont("Georgia", 7)
        cf.setStyleHint(QFont.StyleHint.Serif)
        credit.setFont(cf)
        credit.setStyleSheet("color: #403020; background: transparent;")
        layout.addWidget(credit)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.finished.emit)
        self._timer.start(3500)

    def mousePressEvent(self, event: QMouseEvent):
        self._timer.stop()
        self.finished.emit()
