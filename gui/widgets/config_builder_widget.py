"""
Config Builder Widget

Full-featured visual editor for Pandragon beacon configurations.
Provides tabbed sections for all config properties and a Build
button that invokes the config builder toolchain.
"""

import json
import os
import sys
import tempfile
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
    QLabel, QLineEdit, QSpinBox, QComboBox, QCheckBox,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QTabWidget, QScrollArea, QTextEdit, QSplitter,
    QDialog, QDialogButtonBox, QMessageBox, QFileDialog,
    QDateEdit, QProgressBar, QListWidget, QListWidgetItem, QStyledItemDelegate,
    QStyle, QInputDialog
)
from PyQt6.QtCore import Qt, QDate, QThread, pyqtSignal, QObject, QRectF, QSize
from PyQt6.QtGui import (
    QFont, QPainter, QColor, QPen, QPainterPath, QPalette,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG = {
    "c2_channels": [
        {
            "type": "HTTPS",
            "host": "127.0.0.1",
            "port": 6767,
            "path": "/api/checkin",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "http_method": "POST",
            "max_consecutive_failures": 5,
            "backoff_sleep_ms": 10000,
        }
    ],
    "sleep_ms": 5000,
    "jitter_pct": 20,
    "use_indirect_syscalls": False,
    "indirect_syscall_pivot": "",
    "lazy_checkin": False,
    "lazy_checkin_max": 2,
    "lazy_unhook": False,
    "pad": False,
    "pad_max": 1024,
    "sleep_obfuscation": "none",
    "sleep_wipe_pe_headers": False,
    "sleep_stack_spoof": False,
    "num_spoof_frames": 6,
    "stack_spoof_chain": [
        {"module": "ntdll.dll", "function": "RtlUserThreadStart"},
        {"module": "kernel32.dll", "function": "BaseThreadInitThunk"},
    ],
    "kill_date": "",
    "options": {
        "sandbox_evasion": False,
        "debug_mode": False,
        "bypass_etw": False,
        "validate_ssl": False,
    },
    "malleable_config": {
        "wrapper": {"prefix": "", "suffix": ""},
        "http_headers": [],
        "payload_location": {"type": "body", "body_content_type": "text/plain"},
    },
    "work_hours": {
        "enabled": False,
        "start_hour": 9,
        "start_minute": 0,
        "end_hour": 17,
        "end_minute": 0,
        "insomnia": False,
    },
    "spawnto": {
        "x64": "C:\\Windows\\System32\\rundll32.exe",
        "x86": "C:\\Windows\\SysWOW64\\rundll32.exe",
    },
}


def _project_root() -> str:
    """Return absolute path to the pandragon project root."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _default_json_path() -> str:
    return os.path.join(_project_root(), "Beacon", "config", "default.json")


# ---------------------------------------------------------------------------
# C2 Channel Edit Dialog
# ---------------------------------------------------------------------------

class _C2ChannelDialog(QDialog):
    """Dialog for adding or editing a C2 channel."""

    def __init__(self, channel: Optional[dict] = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("C2 Channel")
        self.setMinimumWidth(450)
        self._channel = channel or {}

        layout = QFormLayout(self)

        self._type = QComboBox()
        self._type.addItems(["HTTP", "HTTPS", "TCP", "PIPE"])
        self._type.setCurrentText(self._channel.get("type", "HTTPS"))
        layout.addRow("Type", self._type)

        self._host = QLineEdit(self._channel.get("host", ""))
        self._host.setPlaceholderText("127.0.0.1")
        layout.addRow("Host", self._host)

        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(self._channel.get("port", 6767))
        layout.addRow("Port", self._port)

        self._path = QLineEdit(self._channel.get("path", ""))
        self._path.setPlaceholderText("/api/checkin")
        layout.addRow("Path", self._path)

        self._ua = QLineEdit(self._channel.get("user_agent", ""))
        self._ua.setPlaceholderText("Mozilla/5.0 ...")
        layout.addRow("User-Agent", self._ua)

        self._method = QComboBox()
        self._method.addItems(["GET", "POST"])
        self._method.setCurrentText(self._channel.get("http_method", "POST"))
        layout.addRow("HTTP Method", self._method)

        self._max_fail = QSpinBox()
        self._max_fail.setRange(1, 100)
        self._max_fail.setValue(self._channel.get("max_consecutive_failures", 5))
        layout.addRow("Max Failures", self._max_fail)

        self._backoff = QSpinBox()
        self._backoff.setRange(1000, 300000)
        self._backoff.setSingleStep(1000)
        self._backoff.setValue(self._channel.get("backoff_sleep_ms", 10000))
        layout.addRow("Backoff (ms)", self._backoff)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_channel(self) -> dict:
        return {
            "type": self._type.currentText(),
            "host": self._host.text().strip(),
            "port": self._port.value(),
            "path": self._path.text().strip(),
            "user_agent": self._ua.text().strip(),
            "http_method": self._method.currentText(),
            "max_consecutive_failures": self._max_fail.value(),
            "backoff_sleep_ms": self._backoff.value(),
        }


# ---------------------------------------------------------------------------
# Config Builder Widget
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Build Worker (runs in background thread)
# ---------------------------------------------------------------------------

class _BuildWorker(QObject):
    """Performs the build pipeline in a background thread."""

    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self._config = config
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            channels = self._config.get("c2_channels", [])
            if not channels:
                self.error.emit("At least one C2 channel is required.")
                return

            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, prefix="pandragon_cfg_"
            )
            try:
                json.dump(self._config, tmp, indent=2)
                tmp.close()

                sys.path.insert(0, _project_root())
                from tools.config_builder import (
                    validate_config,
                    build_config_blob,
                    generate_cpp_header,
                    sync_beacon_to_server,
                )

                if self._cancelled:
                    return

                errors = validate_config(self._config)
                if errors:
                    msg = (
                        "Validation errors:\n  " + "\n  ".join(errors)
                        if isinstance(errors, list)
                        else f"Validation error: {errors}"
                    )
                    self.error.emit(msg)
                    return

                self.progress.emit("Building config blob...")
                blob, nonce, config_key = build_config_blob(self._config)
                self.progress.emit(
                    f"Blob size: {len(blob)} bytes | Config key: {config_key.hex()}"
                )

                if self._cancelled:
                    return

                bin_dir = os.path.join(_project_root(), "Beacon", "config")
                os.makedirs(bin_dir, exist_ok=True)
                bin_path = os.path.join(bin_dir, "default.bin")
                with open(bin_path, "wb") as f:
                    f.write(blob)
                self.progress.emit(f"Wrote: {bin_path}")

                include_dir = os.path.join(bin_dir, "include")
                os.makedirs(include_dir, exist_ok=True)
                header_path = os.path.join(include_dir, "generated_config.h")
                generate_cpp_header(blob, header_path, nonce, config_key, channels)
                self.progress.emit(f"Wrote: {header_path}")

                crypto_key = self._config.get("crypto_key", "")
                beacon_id = self._config.get("beacon_id", "")
                sync_beacon_to_server(beacon_id, crypto_key, self._config)
                self.progress.emit("Synced to server/known_beacons.json")

                self.progress.emit("\nBuild complete!")
            finally:
                try:
                    os.unlink(tmp.name)
                except Exception:
                    pass
        except Exception as e:
            import traceback
            self.error.emit(f"{e}\n{traceback.format_exc()}")
        finally:
            self.finished.emit()


# ---------------------------------------------------------------------------
# Stack spoof chain: card-based stack view with drag-drop
# ---------------------------------------------------------------------------

class _ChainStackDelegate(QStyledItemDelegate):
    """Paints each chain entry as a connected stack-frame card."""

    USER_HEIGHT = 50
    ANCHOR_HEIGHT = 38

    _small_font = None
    _small_font_locked = None
    _small_font_offset = None

    def paint(self, painter, option, index):
        data = index.data(Qt.ItemDataRole.UserRole)
        if not isinstance(data, dict):
            return

        pal = option.palette
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        is_selected = option.state & QStyle.StateFlag.State_Selected
        is_top = data.get("type") == "anchor_top"
        is_bottom = data.get("type") == "anchor_bottom"
        is_locked = is_top or is_bottom

        rect = option.rect.adjusted(4, 1, -4, -1)

        # ── Continuous vertical connector (spans full item rect) ──
        line_x = rect.x() + 2
        conn_color = pal.color(QPalette.ColorRole.Mid).darker(120)
        painter.setPen(QPen(conn_color, 1))
        painter.drawLine(
            int(line_x), option.rect.top(),
            int(line_x), option.rect.bottom(),
        )

        # ── Card background ──
        if is_locked:
            bg = pal.color(QPalette.ColorRole.AlternateBase)
        elif is_selected:
            hl = pal.color(QPalette.ColorRole.Highlight)
            bg = QColor(hl.red(), hl.green(), hl.blue(), 60)
        else:
            bg = pal.color(QPalette.ColorRole.Base)
        path = QPainterPath()
        path.addRoundedRect(QRectF(rect), 4, 4)
        painter.fillPath(path, bg)

        # ── Card border ──
        if is_selected and not is_locked:
            painter.setPen(
                QPen(pal.color(QPalette.ColorRole.Highlight), 1.2)
            )
        else:
            painter.setPen(QPen(conn_color, 1))
        painter.drawRoundedRect(QRectF(rect), 4, 4)

        # ── Accent bar (on top of connector) ──
        accent = QRectF(line_x, rect.y() + 4, 3, rect.height() - 8)
        if is_locked:
            accent_color = pal.color(QPalette.ColorRole.Mid)
        else:
            accent_color = pal.color(QPalette.ColorRole.Highlight)
        painter.fillRect(accent, accent_color)

        # ── Text ──
        text_x = rect.x() + 12
        text_w = rect.width() - 22

        if is_locked:
            font = option.font
            font.setItalic(True)
            painter.setFont(font)
            painter.setPen(pal.color(QPalette.ColorRole.PlaceholderText))
            label = "pandragon.exe" if is_top else "ntdll.dll!NtContinue"
            tr = QRectF(text_x, rect.y(), text_w, rect.height())
            painter.drawText(
                tr,
                Qt.AlignmentFlag.AlignLeft
                | Qt.AlignmentFlag.AlignVCenter,
                label,
            )

            if self._small_font_locked is None:
                self._small_font_locked = QFont(option.font)
                self._small_font_locked.setPointSize(int(self._small_font_locked.pointSize() * 0.8))
            painter.setFont(self._small_font_locked)
            painter.setPen(pal.color(QPalette.ColorRole.Mid))
            side_label = "<-- RSP" if is_top else "<-- RBP"
            sr = QRectF(text_x - 6, rect.y(), text_w + 12, rect.height())
            painter.drawText(
                sr,
                Qt.AlignmentFlag.AlignRight
                | Qt.AlignmentFlag.AlignVCenter,
                side_label,
            )
        else:
            mod = data.get("module", "")
            fn = data.get("function", "")
            offset_val = data.get("offset", 0)
            off_str = hex(offset_val) if offset_val else "scan"

            lw = text_w - 60

            font = option.font
            font.setBold(True)
            painter.setFont(font)
            painter.setPen(pal.color(QPalette.ColorRole.WindowText))
            mr = QRectF(text_x, rect.y() + 5, lw, 18)
            elided = painter.fontMetrics().elidedText(
                mod, Qt.TextElideMode.ElideRight, int(lw),
            )
            painter.drawText(
                mr,
                Qt.AlignmentFlag.AlignLeft
                | Qt.AlignmentFlag.AlignBottom,
                elided,
            )

            font.setBold(False)
            painter.setFont(font)
            painter.setPen(pal.color(QPalette.ColorRole.WindowText))
            fr = QRectF(text_x, rect.y() + 23, lw, 18)
            elided = painter.fontMetrics().elidedText(
                fn, Qt.TextElideMode.ElideRight, int(lw),
            )
            painter.drawText(
                fr,
                Qt.AlignmentFlag.AlignLeft
                | Qt.AlignmentFlag.AlignTop,
                elided,
            )

            if self._small_font_offset is None:
                self._small_font_offset = QFont(option.font)
                self._small_font_offset.setPointSize(int(self._small_font_offset.pointSize() * 0.85))
                self._small_font_offset.setBold(False)
            painter.setFont(self._small_font_offset)
            painter.setPen(pal.color(QPalette.ColorRole.PlaceholderText))
            or_ = QRectF(text_x, rect.y() + 5, text_w, 36)
            painter.drawText(
                or_,
                Qt.AlignmentFlag.AlignRight
                | Qt.AlignmentFlag.AlignVCenter,
                off_str,
            )

        painter.restore()

    def sizeHint(self, option, index):
        data = index.data(Qt.ItemDataRole.UserRole)
        locked = isinstance(data, dict) and data.get("type") in (
            "anchor_top", "anchor_bottom",
        )
        h = self.ANCHOR_HEIGHT if locked else self.USER_HEIGHT
        return QSize(200, h + 2)


class _ChainStackWidget(QListWidget):
    """QListWidget with internal drag-drop and locked anchor items."""

    chainDropped = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setDragDropMode(QListWidget.DragDropMode.InternalMove)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDropIndicatorShown(True)
        self.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self.setSpacing(1)
        self.setFrameShape(QListWidget.Shape.NoFrame)
        self.viewport().setAutoFillBackground(False)

    def dropEvent(self, a0):
        pos = a0.position().toPoint()
        item = self.itemAt(pos)
        drop_pos = self.dropIndicatorPosition()
        row = self.row(item) if item else -1
        count = self.count()

        if row < 0:
            a0.ignore()
            return
        if drop_pos in (
            self.DropIndicatorPosition.AboveItem,
            self.DropIndicatorPosition.OnItem,
        ) and row <= 0:
            a0.ignore()
            return
        if drop_pos in (
            self.DropIndicatorPosition.OnItem,
            self.DropIndicatorPosition.BelowItem,
        ) and row >= count - 1:
            a0.ignore()
            return

        super().dropEvent(a0)
        self.chainDropped.emit()


class ConfigBuilderWidget(QWidget):
    """Visual editor for beacon config with build capability."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._config_path: Optional[str] = None
        self._config: dict = {}
        self._build_output: str = ""
        self._worker: Optional[_BuildWorker] = None
        self._thread: Optional[QThread] = None
        self._api: Optional[object] = None

        self._build_config()

    def set_api(self, api):
        self._api = api
        if api and hasattr(api, '_url') and api._url:
            from urllib.parse import urlparse
            parsed = urlparse(api._url)
            host = parsed.hostname or ""
            if host and host not in ("127.0.0.1", "localhost", "0.0.0.0"):
                self._auto_fill_c2_host(host)

    def _auto_fill_c2_host(self, host: str):
        if self._config.get("c2_channels"):
            for ch in self._config["c2_channels"]:
                if ch.get("host") in ("127.0.0.1", "localhost", ""):
                    ch["host"] = host
            self._refresh_channels_table()
            self._status_label.setText(f"C2 host auto-filled: {host}")

    def _build_config(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Toolbar: load / save / reset
        toolbar = QHBoxLayout()
        self._load_btn = QPushButton("Load JSON")
        self._load_btn.clicked.connect(self._load_config)
        toolbar.addWidget(self._load_btn)

        self._save_btn = QPushButton("Save JSON")
        self._save_btn.clicked.connect(self._save_config)
        toolbar.addWidget(self._save_btn)

        self._reset_btn = QPushButton("Reset Defaults")
        self._reset_btn.clicked.connect(self._reset_config)
        toolbar.addWidget(self._reset_btn)

        toolbar.addStretch()
        self._status_label = QLabel("")
        self._status_label.setObjectName("statusLabel")
        toolbar.addWidget(self._status_label)
        layout.addLayout(toolbar)

        # Main tabs
        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_channels_tab(), "C2 Channels")
        self._tabs.addTab(self._build_timing_tab(), "Timing && Obfuscation")
        self._tabs.addTab(self._build_chain_tab(), "Stack Spoof Chain")
        self._tabs.addTab(self._build_malleable_tab(), "Malleable C2")
        self._tabs.addTab(self._build_workhours_tab(), "Work Hours && Spawn-to")
        self._tabs.addTab(self._build_postbuild_tab(), "Post-Build")
        self._tabs.addTab(self._build_preview_tab(), "Request Preview")
        self._tabs.addTab(self._build_build_tab(), "Build")
        layout.addWidget(self._tabs)

    # ── Tab 1: C2 Channels ──────────────────────────────────────────

    def _build_channels_tab(self) -> QWidget:
        tab = QWidget()
        tab.setObjectName("configTab")
        layout = QVBoxLayout(tab)

        self._channels_table = QTableWidget(0, 5)
        self._channels_table.setHorizontalHeaderLabels(
            ["Type", "Host", "Port", "Path", "Method"]
        )
        self._channels_table.horizontalHeader().setStretchLastSection(True)
        self._channels_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        layout.addWidget(self._channels_table)

        btn_row = QHBoxLayout()
        self._ch_add = QPushButton("Add")
        self._ch_add.clicked.connect(self._channel_add)
        btn_row.addWidget(self._ch_add)

        self._ch_edit = QPushButton("Edit")
        self._ch_edit.clicked.connect(self._channel_edit)
        btn_row.addWidget(self._ch_edit)

        self._ch_remove = QPushButton("Remove")
        self._ch_remove.clicked.connect(self._channel_remove)
        btn_row.addWidget(self._ch_remove)

        btn_row.addStretch()
        layout.addLayout(btn_row)
        return tab

    def _channel_add(self):
        dialog = _C2ChannelDialog(parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            ch = dialog.get_channel()
            if "c2_channels" not in self._config:
                self._config["c2_channels"] = []
            self._config["c2_channels"].append(ch)
            self._refresh_channels_table()

    def _channel_edit(self):
        row = self._channels_table.currentRow()
        if row < 0:
            return
        channels = self._config.get("c2_channels", [])
        if row >= len(channels):
            return
        dialog = _C2ChannelDialog(channels[row], parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            channels[row] = dialog.get_channel()
            self._refresh_channels_table()

    def _channel_remove(self):
        row = self._channels_table.currentRow()
        if row < 0:
            return
        channels = self._config.get("c2_channels", [])
        if 0 <= row < len(channels):
            del channels[row]
            self._refresh_channels_table()

    def _refresh_channels_table(self):
        channels = self._config.get("c2_channels", [])
        self._channels_table.setRowCount(len(channels))
        for i, ch in enumerate(channels):
            self._channels_table.setItem(i, 0, QTableWidgetItem(ch.get("type", "")))
            self._channels_table.setItem(i, 1, QTableWidgetItem(ch.get("host", "")))
            self._channels_table.setItem(
                i, 2, QTableWidgetItem(str(ch.get("port", "")))
            )
            self._channels_table.setItem(i, 3, QTableWidgetItem(ch.get("path", "")))
            self._channels_table.setItem(
                i, 4, QTableWidgetItem(ch.get("http_method", ""))
            )
        # Keep preview channel dropdown in sync
        self._populate_preview_channels()

    # ── Tab 2: Timing & Obfuscation ─────────────────────────────────

    def _build_timing_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        container = QWidget()
        container.setObjectName("configTab")
        layout = QVBoxLayout(container)

        # Timing
        timing_group = QGroupBox("Timing")
        timing_form = QFormLayout(timing_group)

        self._sleep_ms = QSpinBox()
        self._sleep_ms.setRange(100, 3600000)
        self._sleep_ms.setSingleStep(100)
        self._sleep_ms.setValue(5000)
        timing_form.addRow("Sleep (ms)", self._sleep_ms)

        self._jitter_pct = QSpinBox()
        self._jitter_pct.setRange(0, 100)
        self._jitter_pct.setSuffix("%")
        self._jitter_pct.setValue(20)
        timing_form.addRow("Jitter", self._jitter_pct)

        self._pad = QCheckBox("Enable PKCS#7 padding")
        timing_form.addRow(self._pad)

        self._pad_max = QSpinBox()
        self._pad_max.setRange(0, 65535)
        self._pad_max.setValue(1024)
        timing_form.addRow("Pad Max (bytes)", self._pad_max)

        self._kill_date = QDateEdit()
        self._kill_date.setCalendarPopup(True)
        self._kill_date.setDate(QDate.currentDate().addYears(1))
        self._kill_date.setSpecialValueText("None")
        timing_form.addRow("Kill Date", self._kill_date)

        layout.addWidget(timing_group)

        # Obfuscation
        obf_group = QGroupBox("Sleep Obfuscation")
        obf_form = QFormLayout(obf_group)

        self._sleep_obf = QComboBox()
        self._sleep_obf.addItems(["none", "ekko", "foliage"])
        self._sleep_obf.currentTextChanged.connect(self._update_conditional_visibility)
        obf_form.addRow("Method", self._sleep_obf)

        self._wipe_pe = QCheckBox("Wipe PE headers during sleep")
        obf_form.addRow(self._wipe_pe)

        # Stack spoofing row (shown only when method != "none")
        self._stack_spoof_row = QWidget()
        stack_spoof_layout = QHBoxLayout(self._stack_spoof_row)
        stack_spoof_layout.setContentsMargins(0, 0, 0, 0)
        self._stack_spoof = QCheckBox("Enable stack spoofing")
        stack_spoof_layout.addWidget(self._stack_spoof)
        stack_spoof_layout.addStretch()
        self._stack_spoof_row.setVisible(False)
        obf_form.addRow(self._stack_spoof_row)

        # Num Spoof Frames row (shown only when stack spoofing enabled)
        self._num_frames_row = QWidget()
        num_frames_layout = QHBoxLayout(self._num_frames_row)
        num_frames_layout.setContentsMargins(0, 0, 0, 0)
        self._num_frames = QSpinBox()
        self._num_frames.setRange(0, 65535)
        self._num_frames.setValue(6)
        self._num_frames.setToolTip("0 = use default of 6")
        num_frames_layout.addWidget(QLabel("Num Spoof Frames"))
        num_frames_layout.addWidget(self._num_frames)
        num_frames_layout.addStretch()
        self._num_frames_row.setVisible(False)
        obf_form.addRow(self._num_frames_row)

        self._stack_spoof.toggled.connect(self._update_conditional_visibility)

        layout.addWidget(obf_group)

        # Syscall
        sys_group = QGroupBox("Indirect Syscalls")
        sys_form = QFormLayout(sys_group)

        self._indirect_sys = QCheckBox("Use indirect syscalls")
        self._indirect_sys.toggled.connect(self._update_conditional_visibility)
        sys_form.addRow(self._indirect_sys)

        # Pivot API row (shown only when indirect syscalls enabled)
        self._pivot_row = QWidget()
        pivot_layout = QHBoxLayout(self._pivot_row)
        pivot_layout.setContentsMargins(0, 0, 0, 0)
        self._pivot = QLineEdit()
        self._pivot.setPlaceholderText("ZwSetDefaultLocale")
        pivot_layout.addWidget(QLabel("Pivot API"))
        pivot_layout.addWidget(self._pivot)
        pivot_layout.addStretch()
        self._pivot_row.setVisible(False)
        sys_form.addRow(self._pivot_row)

        self._lazy_checkin = QCheckBox("Lazy check-in")
        self._lazy_checkin.toggled.connect(self._update_conditional_visibility)
        sys_form.addRow(self._lazy_checkin)

        # Lazy Check-in Max row (shown only when lazy check-in enabled)
        self._lazy_checkin_max_row = QWidget()
        lazy_max_layout = QHBoxLayout(self._lazy_checkin_max_row)
        lazy_max_layout.setContentsMargins(0, 0, 0, 0)
        self._lazy_checkin_max = QSpinBox()
        self._lazy_checkin_max.setRange(1, 255)
        self._lazy_checkin_max.setValue(2)
        lazy_max_layout.addWidget(QLabel("Lazy Check-in Max"))
        lazy_max_layout.addWidget(self._lazy_checkin_max)
        lazy_max_layout.addStretch()
        self._lazy_checkin_max_row.setVisible(False)
        sys_form.addRow(self._lazy_checkin_max_row)

        self._lazy_unhook = QCheckBox("Lazy unhook (transparent)")
        sys_form.addRow(self._lazy_unhook)

        layout.addWidget(sys_group)

        # Options
        opt_group = QGroupBox("Options")
        opt_form = QFormLayout(opt_group)

        self._opt_sandbox = QCheckBox("Sandbox evasion")
        opt_form.addRow(self._opt_sandbox)

        self._opt_debug = QCheckBox("Debug mode")
        opt_form.addRow(self._opt_debug)

        self._opt_bypass_etw = QCheckBox("Bypass ETW")
        opt_form.addRow(self._opt_bypass_etw)

        self._opt_validate_ssl = QCheckBox("Validate SSL")
        opt_form.addRow(self._opt_validate_ssl)

        layout.addWidget(opt_group)

        layout.addStretch()
        scroll.setWidget(container)
        # Initial conditional visibility
        self._update_conditional_visibility()
        return scroll

    def _update_conditional_visibility(self):
        """Show/hide conditional fields based on current widget state."""
        # Stack spoofing fields: visible when sleep obf method != "none"
        obf_method = self._sleep_obf.currentText()
        self._stack_spoof_row.setVisible(obf_method != "none")
        self._num_frames_row.setVisible(obf_method != "none" and self._stack_spoof.isChecked())

        # Pivot API: visible when indirect syscalls enabled
        self._pivot_row.setVisible(self._indirect_sys.isChecked())

        # Lazy Check-in Max: visible when lazy check-in enabled
        self._lazy_checkin_max_row.setVisible(self._lazy_checkin.isChecked())

    # ── Tab 3: Stack Spoof Chain ────────────────────────────────────

    def _build_chain_tab(self) -> QWidget:
        tab = QWidget()
        tab.setObjectName("configTab")
        layout = QVBoxLayout(tab)

        self._chain_stack = _ChainStackWidget()
        self._chain_stack.setItemDelegate(_ChainStackDelegate(self._chain_stack))
        self._chain_stack.chainDropped.connect(self._sync_chain_from_stack)
        self._chain_stack.itemDoubleClicked.connect(self._chain_edit_entry)
        layout.addWidget(self._chain_stack)

        btn_row = QHBoxLayout()
        self._chain_add = QPushButton("Add")
        self._chain_add.clicked.connect(self._chain_add_entry)
        btn_row.addWidget(self._chain_add)

        self._chain_edit = QPushButton("Edit")
        self._chain_edit.clicked.connect(lambda: self._chain_edit_entry())
        btn_row.addWidget(self._chain_edit)

        self._chain_remove = QPushButton("Remove")
        self._chain_remove.clicked.connect(self._chain_remove_entry)
        btn_row.addWidget(self._chain_remove)

        self._chain_up = QPushButton("Up")
        self._chain_up.clicked.connect(self._chain_move_up)
        btn_row.addWidget(self._chain_up)

        self._chain_down = QPushButton("Down")
        self._chain_down.clicked.connect(self._chain_move_down)
        btn_row.addWidget(self._chain_down)

        btn_row.addStretch()
        layout.addLayout(btn_row)

        note = QLabel(
            "Top and bottom entries are locked anchors.\n"
            "Drag-and-drop or use Up/Down to reorder middle entries."
        )
        note.setObjectName("mutedLabel")
        note.setWordWrap(True)
        layout.addWidget(note)

        return tab

    def _chain_entry_dialog(self, title, module="", function="", offset_text=""):
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        form = QFormLayout(dialog)

        module_edit = QLineEdit(module)
        module_edit.setPlaceholderText("ntdll.dll")
        form.addRow("Module DLL:", module_edit)

        func_edit = QLineEdit(function)
        func_edit.setPlaceholderText("RtlUserThreadStart")
        form.addRow("Function:", func_edit)

        offset_edit = QLineEdit(offset_text)
        offset_edit.setPlaceholderText("0 (auto-scan)")
        offset_edit.setToolTip(
            "Decimal or hex (e.g. 0x1000). 0 = auto-scan at build time."
        )
        form.addRow("Offset:", offset_edit)

        note = QLabel(
            "Empty chain will auto-populate with ntdll!RtlUserThreadStart + "
            "kernel32!BaseThreadInitThunk at build time."
        )
        note.setObjectName("mutedLabel")
        note.setWordWrap(True)
        form.addRow(note)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)

        if not dialog.exec():
            return None
        return (
            module_edit.text().strip(),
            func_edit.text().strip(),
            offset_edit.text().strip(),
        )

    def _chain_add_entry(self):
        result = self._chain_entry_dialog("Add Chain Entry")
        if result is None:
            return
        module, function, offset_text = result
        if not module or not function:
            return

        if "stack_spoof_chain" not in self._config:
            self._config["stack_spoof_chain"] = []
        entry = {"module": module, "function": function}
        if offset_text:
            try:
                offset = int(offset_text, 0)
            except ValueError:
                return
            if offset:
                entry["offset"] = offset
        self._config["stack_spoof_chain"].append(entry)
        self._refresh_chain_stack()

    def _chain_edit_entry(self, item=None):
        if item is not None:
            list_row = self._chain_stack.row(item)
        else:
            list_row = self._chain_stack.currentRow()
        chain = self._config.get("stack_spoof_chain", [])
        ci = list_row - 1
        if not (0 <= ci < len(chain)):
            return

        entry = chain[ci]
        offset = entry.get("offset", 0)
        offset_text = hex(offset) if offset else ""
        result = self._chain_entry_dialog(
            "Edit Chain Entry",
            entry.get("module", ""),
            entry.get("function", ""),
            offset_text,
        )
        if result is None:
            return

        module, function, offset_text = result
        if not module or not function:
            return

        entry["module"] = module
        entry["function"] = function
        if offset_text:
            try:
                offset = int(offset_text, 0)
            except ValueError:
                return
            if offset:
                entry["offset"] = offset
            else:
                entry.pop("offset", None)
        else:
            entry.pop("offset", None)
        self._refresh_chain_stack()

    def _chain_remove_entry(self):
        list_row = self._chain_stack.currentRow()
        chain = self._config.get("stack_spoof_chain", [])
        ci = list_row - 1
        if 0 <= ci < len(chain):
            del chain[ci]
            self._refresh_chain_stack()

    def _chain_move_up(self):
        list_row = self._chain_stack.currentRow()
        chain = self._config.get("stack_spoof_chain", [])
        ci = list_row - 1
        if ci > 0 and ci < len(chain):
            chain[ci - 1], chain[ci] = chain[ci], chain[ci - 1]
            self._refresh_chain_stack()
            self._chain_stack.setCurrentRow(list_row - 1)

    def _chain_move_down(self):
        list_row = self._chain_stack.currentRow()
        chain = self._config.get("stack_spoof_chain", [])
        ci = list_row - 1
        if 0 <= ci < len(chain) - 1:
            chain[ci], chain[ci + 1] = chain[ci + 1], chain[ci]
            self._refresh_chain_stack()
            self._chain_stack.setCurrentRow(list_row + 1)

    def _sync_chain_from_stack(self):
        chain = []
        for row in range(1, self._chain_stack.count() - 1):
            item = self._chain_stack.item(row)
            data = item.data(Qt.ItemDataRole.UserRole) if item else None
            if isinstance(data, dict) and data.get("type") == "user":
                entry = {
                    "module": data.get("module", ""),
                    "function": data.get("function", ""),
                }
                offset = data.get("offset", 0)
                if offset:
                    entry["offset"] = offset
                chain.append(entry)
        self._config["stack_spoof_chain"] = chain
        self._refresh_chain_stack()

    def _refresh_chain_stack(self):
        self._chain_stack.clear()

        top_item = QListWidgetItem()
        top_item.setData(Qt.ItemDataRole.UserRole, {"type": "anchor_top"})
        top_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
        self._chain_stack.addItem(top_item)

        for entry in self._config.get("stack_spoof_chain", []):
            data = {
                "type": "user",
                "module": entry.get("module", ""),
                "function": entry.get("function", ""),
                "offset": entry.get("offset", 0),
            }
            user_item = QListWidgetItem()
            user_item.setData(Qt.ItemDataRole.UserRole, data)
            user_item.setFlags(
                Qt.ItemFlag.ItemIsEnabled
                | Qt.ItemFlag.ItemIsSelectable
                | Qt.ItemFlag.ItemIsDragEnabled
            )
            self._chain_stack.addItem(user_item)

        bottom_item = QListWidgetItem()
        bottom_item.setData(Qt.ItemDataRole.UserRole, {"type": "anchor_bottom"})
        bottom_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
        self._chain_stack.addItem(bottom_item)

    # ── Tab 4: Malleable C2 ─────────────────────────────────────────

    def _build_malleable_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        container = QWidget()
        container.setObjectName("configTab")
        layout = QVBoxLayout(container)

        # Channel selector for per-channel malleable config
        ch_sel_row = QHBoxLayout()
        ch_sel_row.addWidget(QLabel("Edit malleable config for:"))
        self._malleable_channel = QComboBox()
        self._malleable_channel.currentIndexChanged.connect(self._on_malleable_channel_changed)
        ch_sel_row.addWidget(self._malleable_channel)
        ch_sel_row.addStretch()
        layout.addLayout(ch_sel_row)

        # Wrapper
        wrap_group = QGroupBox("Wrapper (prefix/suffix)")
        wrap_form = QFormLayout(wrap_group)

        self._wrap_prefix = QLineEdit()
        self._wrap_prefix.setPlaceholderText("REQ_${RAND_B64:4}_")
        self._wrap_prefix.setMaxLength(65535)
        wrap_form.addRow("Prefix", self._wrap_prefix)

        self._wrap_suffix = QLineEdit()
        self._wrap_suffix.setPlaceholderText("_${JUNK:8}")
        self._wrap_suffix.setMaxLength(65535)
        wrap_form.addRow("Suffix", self._wrap_suffix)

        layout.addWidget(wrap_group)

        # HTTP Headers
        hdr_group = QGroupBox("Custom HTTP Headers")
        hdr_layout = QVBoxLayout(hdr_group)

        self._headers_table = QTableWidget(0, 2)
        self._headers_table.setHorizontalHeaderLabels(["Name", "Value"])
        self._headers_table.horizontalHeader().setStretchLastSection(True)
        hdr_layout.addWidget(self._headers_table)

        hdr_btn_row = QHBoxLayout()
        self._hdr_add = QPushButton("Add Header")
        self._hdr_add.clicked.connect(self._header_add)
        hdr_btn_row.addWidget(self._hdr_add)

        self._hdr_remove = QPushButton("Remove")
        self._hdr_remove.clicked.connect(self._header_remove)
        hdr_btn_row.addWidget(self._hdr_remove)

        hdr_btn_row.addStretch()
        hdr_layout.addLayout(hdr_btn_row)
        layout.addWidget(hdr_group)

        # Payload Location
        pl_group = QGroupBox("Payload Location")
        pl_form = QFormLayout(pl_group)

        self._pl_type = QComboBox()
        self._pl_type.addItems(["query_param", "path", "body"])
        pl_form.addRow("Type", self._pl_type)

        self._pl_param = QLineEdit()
        self._pl_param.setPlaceholderText("q")
        pl_form.addRow("Query Param Name", self._pl_param)

        self._pl_path_prefix = QLineEdit()
        self._pl_path_prefix.setPlaceholderText("/api/")
        pl_form.addRow("Path Prefix", self._pl_path_prefix)

        self._pl_path_suffix = QLineEdit()
        self._pl_path_suffix.setPlaceholderText(".png")
        pl_form.addRow("Path Suffix", self._pl_path_suffix)

        self._pl_body_ct = QComboBox()
        self._pl_body_ct.addItems(["text/plain", "application/octet-stream"])
        pl_form.addRow("Body Content-Type", self._pl_body_ct)

        layout.addWidget(pl_group)
        layout.addStretch()
        scroll.setWidget(container)

        # Initial population
        self._populate_malleable_channels()
        return scroll

    def _populate_malleable_channels(self):
        """Populate the channel dropdown for malleable config editing."""
        self._malleable_channel.blockSignals(True)
        self._malleable_channel.clear()
        channels = self._config.get("c2_channels", [])
        for i, ch in enumerate(channels):
            ch_type = ch.get("type", "HTTP")
            host = ch.get("host", "")
            port = ch.get("port", 0)
            label = f"{i+1}. {ch_type}  {host}:{port}"
            self._malleable_channel.addItem(label, ("channel", i))
        # Global entry last
        self._malleable_channel.addItem("Global (fallback)", ("global", None))
        self._malleable_channel.blockSignals(False)

    def _get_malleable_target(self) -> tuple[dict, str]:
        """
        Get the malleable config dict being edited based on current dropdown selection.
        Returns (malleable_config_dict, target_type) where target_type is "channel:N" or "global".
        """
        data = self._malleable_channel.currentData()
        if not data:
            return self._config.setdefault("malleable_config", {}), "global"
        target_type, idx = data
        if target_type == "channel":
            channel = self._config.setdefault("c2_channels", [{}])[idx]
            return channel.setdefault("malleable_config", {}), f"channel:{idx}"
        return self._config.setdefault("malleable_config", {}), "global"

    def _on_malleable_channel_changed(self):
        """Refresh all malleable tab fields when channel selection changes."""
        self._refresh_malleable_fields()

    def _refresh_malleable_fields(self):
        """Refresh all malleable tab fields from the currently selected target."""
        mc, target = self._get_malleable_target()
        wrapper = mc.get("wrapper", {})
        self._wrap_prefix.setText(wrapper.get("prefix", ""))
        self._wrap_suffix.setText(wrapper.get("suffix", ""))
        # Headers
        self._refresh_headers_table()
        # Payload location
        pl = mc.get("payload_location", {})
        self._pl_type.setCurrentText(pl.get("type", "body"))
        self._pl_param.setText(pl.get("param_name", "q"))
        self._pl_path_prefix.setText(pl.get("path_prefix", ""))
        self._pl_path_suffix.setText(pl.get("path_suffix", ""))
        self._pl_body_ct.setCurrentText(pl.get("body_content_type", "text/plain"))

    def _header_add(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add HTTP Header")
        form = QFormLayout(dialog)

        name_edit = QLineEdit()
        name_edit.setPlaceholderText("X-My-Header")
        form.addRow("Name:", name_edit)

        value_edit = QLineEdit()
        value_edit.setPlaceholderText("some-value")
        form.addRow("Value:", value_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)

        if not dialog.exec():
            return

        name = name_edit.text().strip()
        value = value_edit.text().strip()
        if not name:
            return

        mc, _ = self._get_malleable_target()
        headers = mc.setdefault("http_headers", [])
        headers.append({"name": name, "value": value})
        self._refresh_headers_table()

    def _header_remove(self):
        row = self._headers_table.currentRow()
        mc, _ = self._get_malleable_target()
        headers = mc.get("http_headers", [])
        if 0 <= row < len(headers):
            del headers[row]
            self._refresh_headers_table()

    def _refresh_headers_table(self):
        mc, _ = self._get_malleable_target()
        headers = mc.get("http_headers", [])
        self._headers_table.setRowCount(len(headers))
        for i, h in enumerate(headers):
            self._headers_table.setItem(i, 0, QTableWidgetItem(h.get("name", "")))
            self._headers_table.setItem(i, 1, QTableWidgetItem(h.get("value", "")))

    # ── Tab 5: Work Hours & Spawn-to ────────────────────────────────

    def _build_workhours_tab(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        container = QWidget()
        container.setObjectName("configTab")
        layout = QVBoxLayout(container)

        # Work hours
        wh_group = QGroupBox("Work Hours (UTC)")
        wh_form = QFormLayout(wh_group)

        self._wh_enabled = QCheckBox("Enable work hours enforcement")
        wh_form.addRow(self._wh_enabled)

        self._wh_start_h = QSpinBox()
        self._wh_start_h.setRange(0, 23)
        self._wh_start_h.setValue(9)
        wh_form.addRow("Start Hour", self._wh_start_h)

        self._wh_start_m = QSpinBox()
        self._wh_start_m.setRange(0, 59)
        self._wh_start_m.setValue(0)
        wh_form.addRow("Start Minute", self._wh_start_m)

        self._wh_end_h = QSpinBox()
        self._wh_end_h.setRange(0, 23)
        self._wh_end_h.setValue(17)
        wh_form.addRow("End Hour", self._wh_end_h)

        self._wh_end_m = QSpinBox()
        self._wh_end_m.setRange(0, 59)
        self._wh_end_m.setValue(0)
        wh_form.addRow("End Minute", self._wh_end_m)

        self._wh_insomnia = QCheckBox("Insomnia (skip check-in, don't sleep)")
        wh_form.addRow(self._wh_insomnia)

        layout.addWidget(wh_group)

        # Spawn-to
        st_group = QGroupBox("Spawn-to Process")
        st_form = QFormLayout(st_group)

        self._st_x64 = QLineEdit()
        self._st_x64.setPlaceholderText("C:\\Windows\\System32\\rundll32.exe")
        st_form.addRow("x64 Path", self._st_x64)

        self._st_x86 = QLineEdit()
        self._st_x86.setPlaceholderText("C:\\Windows\\SysWOW64\\rundll32.exe")
        st_form.addRow("x86 Path", self._st_x86)

        layout.addWidget(st_group)
        layout.addStretch()
        scroll.setWidget(container)
        return scroll

    # ── Tab: Post-Build ───────────────────────────────────────────────

    def _build_postbuild_tab(self) -> QWidget:
        tab = QWidget()
        tab.setObjectName("configTab")
        layout = QVBoxLayout(tab)

        # Post-Build Append (unencrypted, IOC markers)
        post_group = QGroupBox("Post-Build Append - Unencrypted IOC markers")
        post_form = QFormLayout(post_group)

        self._post_append_list = QListWidget()
        self._post_append_list.setMaximumHeight(120)
        post_form.addRow("Strings:", self._post_append_list)

        post_btn_row = QHBoxLayout()
        self._post_add = QPushButton("Add")
        self._post_add.clicked.connect(self._post_append_add)
        post_btn_row.addWidget(self._post_add)

        self._post_remove = QPushButton("Remove")
        self._post_remove.clicked.connect(self._post_append_remove)
        post_btn_row.addWidget(self._post_remove)

        post_btn_row.addStretch()
        post_form.addRow(post_btn_row)

        post_info = QLabel("Appended to binary post-build as [MAGIC:4][LEN:4][DATA:N]. Not encrypted. Visible in strings output.")
        post_info.setWordWrap(True)
        post_info.setStyleSheet("color: #888; font-size: 10px;")
        post_form.addRow(post_info)

        layout.addWidget(post_group)

        # In-Memory Append (encrypted in config blob, decrypted at runtime)
        inmem_group = QGroupBox("In-Memory Append - Encrypted config strings")
        inmem_form = QFormLayout(inmem_group)

        self._inmem_append_list = QListWidget()
        self._inmem_append_list.setMaximumHeight(120)
        inmem_form.addRow("Strings:", self._inmem_append_list)

        inmem_btn_row = QHBoxLayout()
        self._inmem_add = QPushButton("Add")
        self._inmem_add.clicked.connect(self._inmem_append_add)
        inmem_btn_row.addWidget(self._inmem_add)

        self._inmem_remove = QPushButton("Remove")
        self._inmem_remove.clicked.connect(self._inmem_append_remove)
        inmem_btn_row.addWidget(self._inmem_remove)

        inmem_btn_row.addStretch()
        inmem_form.addRow(inmem_btn_row)

        inmem_info = QLabel("Encrypted in config blob, decrypted at beacon startup. Not visible in binary strings.")
        inmem_info.setWordWrap(True)
        inmem_info.setStyleSheet("color: #888; font-size: 10px;")
        inmem_form.addRow(inmem_info)

        layout.addWidget(inmem_group)

        layout.addStretch()
        return tab

    def _post_append_add(self):
        text, ok = QInputDialog.getText(self, "Add Post-Build String", "String:")
        if ok and text:
            self._post_append_list.addItem(text)
            self._sync_post_append_list()

    def _post_append_remove(self):
        row = self._post_append_list.currentRow()
        if row >= 0:
            self._post_append_list.takeItem(row)
            self._sync_post_append_list()

    def _inmem_append_add(self):
        text, ok = QInputDialog.getText(self, "Add In-Memory String", "String:")
        if ok and text:
            self._inmem_append_list.addItem(text)
            self._sync_inmem_append_list()

    def _inmem_append_remove(self):
        row = self._inmem_append_list.currentRow()
        if row >= 0:
            self._inmem_append_list.takeItem(row)
            self._sync_inmem_append_list()

    def _sync_post_append_list(self):
        self._config["post_build"] = {"append": [self._post_append_list.item(i).text() for i in range(self._post_append_list.count())]}

    def _sync_inmem_append_list(self):
        self._config["in_memory_append"] = {"append": [self._inmem_append_list.item(i).text() for i in range(self._inmem_append_list.count())]}

    # ── Tab: Request Preview ─────────────────────────────────────────────

    def _build_preview_tab(self) -> QWidget:
        tab = QWidget()
        tab.setObjectName("configTab")
        layout = QVBoxLayout(tab)

        # Controls
        ctrl_row = QHBoxLayout()
        self._preview_refresh = QPushButton("Refresh Preview")
        self._preview_refresh.clicked.connect(self._refresh_preview)
        ctrl_row.addWidget(self._preview_refresh)

        # Channel selector (handles multiple C2 channels)
        self._preview_channel = QComboBox()
        self._preview_channel.currentIndexChanged.connect(self._refresh_preview)
        ctrl_row.addWidget(QLabel("Channel:"))
        ctrl_row.addWidget(self._preview_channel)

        self._preview_profile = QComboBox()
        self._preview_profile.addItems(["Check-in (GET)", "Check-in (POST)", "Task Result (POST)", "File Upload (POST)"])
        self._preview_profile.currentTextChanged.connect(self._refresh_preview)
        ctrl_row.addWidget(QLabel("Profile:"))
        ctrl_row.addWidget(self._preview_profile)
        ctrl_row.addStretch()
        layout.addLayout(ctrl_row)

        # Mal Mode indicator (read-only label showing effective mode)
        self._preview_mode_label = QLabel("Mode: -")
        self._preview_mode_label.setStyleSheet("color: #9cdcfe; font-family: Consolas; font-size: 9pt;")
        ctrl_row.addWidget(self._preview_mode_label)

        # Request display
        from PyQt6.QtWidgets import QTextEdit
        self._preview_text = QTextEdit()
        self._preview_text.setReadOnly(True)
        self._preview_text.setFont(QFont("Consolas", 9))
        self._preview_text.setStyleSheet("background-color: #1a1a1a; color: #e0e0e0; border: 1px solid #333;")
        layout.addWidget(self._preview_text)

        # Initial render (populate channel dropdown first)
        self._populate_preview_channels()
        self._refresh_preview()
        return tab

    def _populate_preview_channels(self):
        """Populate the channel dropdown with all configured C2 channels."""
        self._preview_channel.blockSignals(True)
        self._preview_channel.clear()
        channels = self._config.get("c2_channels", [])
        for i, ch in enumerate(channels):
            ch_type = ch.get("type", "HTTP")
            host = ch.get("host", "")
            port = ch.get("port", 0)
            label = f"{i+1}. {ch_type}  {host}:{port}"
            self._preview_channel.addItem(label, i)
        self._preview_channel.blockSignals(False)

    def _get_effective_malleable(self, channel: dict) -> tuple[dict, str]:
        """
        Determine the effective malleable config for a channel based on malleable_mode logic.
        Returns (malleable_config_dict, mode_string).
        """
        c = self._config
        ch_type = channel.get("type", "HTTP")

        # TCP (3) and PIPE (4) channels have no malleable config
        if ch_type in ("TCP", "PIPE"):
            return {}, "NONE (TCP/PIPE)"

        # Check for per-channel malleable_config
        ch_malleable = channel.get("malleable_config")
        if ch_malleable:
            return ch_malleable, "INLINE (per-channel)"

        # Fall back to global malleable_config
        global_malleable = c.get("malleable_config", {})
        if global_malleable:
            return global_malleable, "GLOBAL"

        return {}, "NONE"

    def _refresh_preview(self):
        """Generate and display a preview HTTP request based on current config."""
        import random
        import base64
        import time

        c = self._config
        channels = c.get("c2_channels", [{}])

        # Get selected channel index
        ch_idx = self._preview_channel.currentData()
        if ch_idx is None or ch_idx >= len(channels):
            ch_idx = 0
        ch = channels[ch_idx]

        # Determine effective malleable config and mode
        mc, mode_str = self._get_effective_malleable(ch)
        self._preview_mode_label.setText(f"Mode: {mode_str}")

        wrapper = mc.get("wrapper", {})

        # Sample beacon data
        beacon_id = "a1b2c3d4"
        session_id = random.randint(1, 0xFFFFFFFF)
        timestamp = int(time.time())
        rand_b64_4 = base64.b64encode(random.randbytes(3)).decode()[:4]
        rand_b64_8 = base64.b64encode(random.randbytes(6)).decode()[:8]
        junk_8 = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", k=8))

        # Macro expansions
        macros = {
            "${BEACON_ID}": beacon_id,
            "${SESSION_ID}": f"{session_id:08x}",
            "${TIMESTAMP}": str(timestamp),
            "${RAND_B64:4}": rand_b64_4,
            "${RAND_B64:8}": rand_b64_8,
            "${JUNK:8}": junk_8,
            "${JUNK:16}": junk_8 + junk_8,
        }

        def expand(text: str) -> str:
            for k, v in macros.items():
                text = text.replace(k, v)
            return text

        # Build request components
        profile = self._preview_profile.currentText()
        method = ch.get("http_method", "POST")
        host = ch.get("host", "127.0.0.1")
        port = ch.get("port", 6767)
        path = ch.get("path", "/api/checkin")
        ua = ch.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

        # Apply wrapper
        prefix = expand(wrapper.get("prefix", ""))
        suffix = expand(wrapper.get("suffix", ""))

        # Payload location
        pl = mc.get("payload_location", {})
        pl_type = pl.get("type", "body")
        pl_param = pl.get("param_name", "q")
        pl_path_prefix = pl.get("path_prefix", "")
        pl_path_suffix = pl.get("path_suffix", "")
        pl_body_ct = pl.get("body_content_type", "text/plain")

        # Sample encrypted payload (base64)
        sample_payload = base64.b64encode(b"\x00" * 64).decode()

        # Expand path
        req_path = expand(pl_path_prefix + path + pl_path_suffix)

        headers = {
            "User-Agent": expand(ua),
            "Host": f"{host}:{port}",
        }

        # Custom headers (macro-expanded like the beacon does)
        for hdr in mc.get("http_headers", []):
            headers[expand(hdr.get("name", ""))] = expand(hdr.get("value", ""))

        # Build request
        if pl_type == "query_param":
            sep = "&" if "?" in req_path else "?"
            req_path += f"{sep}{pl_param}={sample_payload}"
            body = ""
            ct = ""
        elif pl_type == "path":
            # Payload in path suffix already handled
            body = ""
            ct = ""
        else:  # body
            body = prefix + sample_payload + suffix
            ct = pl_body_ct

        # HTTP request lines
        lines = []
        lines.append(f"{method} {req_path} HTTP/1.1")
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        if ct:
            lines.append(f"Content-Type: {ct}")
        if body:
            lines.append(f"Content-Length: {len(body)}")
        lines.append("")
        if body:
            lines.append(body)

        request_text = "\r\n".join(lines)

        # Display with color hints (using HTML)
        html = f"""
        <pre style="font-family: Consolas, monospace; font-size: 10pt; color: #e0e0e0;">
        <span style="color: #4ec9b0;">{method} {req_path} HTTP/1.1</span>
        """
        for k, v in headers.items():
            html += f'\n<span style="color: #9cdcfe;">{k}</span>: <span style="color: #ce9178;">{v}</span>'
        if ct:
            html += f'\n<span style="color: #9cdcfe;">Content-Type</span>: <span style="color: #ce9178;">{ct}</span>'
        if body:
            html += f'\n<span style="color: #9cdcfe;">Content-Length</span>: <span style="color: #ce9178;">{len(body)}</span>'
        html += "\n"
        if body:
            html += f'\n<span style="color: #dcdcaa;">{body[:200]}{"..." if len(body) > 200 else ""}</span>'

        self._preview_text.setHtml(html)

    # ── Tab 6: Build ────────────────────────────────────────────────

    def _build_build_tab(self) -> QWidget:
        tab = QWidget()
        tab.setObjectName("configTab")
        layout = QVBoxLayout(tab)

        # Build button + progress bar
        controls = QHBoxLayout()
        self._build_btn = QPushButton("Build Beacon")
        self._build_btn.setObjectName("BuildBtn")
        self._build_btn.clicked.connect(self._run_build)
        controls.addWidget(self._build_btn)

        self._build_progress = QProgressBar()
        self._build_progress.setRange(0, 0)  # indeterminate
        self._build_progress.setVisible(False)
        self._build_progress.setMaximumWidth(200)
        controls.addWidget(self._build_progress)

        self._upload_btn = QPushButton("Upload Config to Server")
        self._upload_btn.setObjectName("UploadBtn")
        self._upload_btn.clicked.connect(self._upload_to_server)
        self._upload_btn.setEnabled(False)
        controls.addWidget(self._upload_btn)

        controls.addStretch()
        layout.addLayout(controls)

        # Build output
        self._build_output_text = QTextEdit()
        self._build_output_text.setReadOnly(True)
        self._build_output_text.setFont(QFont("Consolas", 9))
        layout.addWidget(self._build_output_text)

        return tab

    def _upload_to_server(self):
        """Upload the current beacon config to the connected teamserver."""
        if not self._api or not self._api.is_connected():
            self._append_build("ERROR: Not connected to a teamserver")
            return

        self._sync_form_to_config()
        config = self._config

        beacon_id = config.get("beacon_id", "")
        crypto_key = config.get("crypto_key", "")
        if not beacon_id or not crypto_key:
            self._append_build("ERROR: Build the config first (generates beacon_id / crypto_key)")
            return

        channels = config.get("c2_channels", [])
        if not channels:
            self._append_build("ERROR: No C2 channels configured")
            return

        allowed_routes = []
        for ch in channels:
            if ch.get("malleable_config"):
                mc = ch["malleable_config"]
            elif config.get("malleable_config"):
                mc = config["malleable_config"]
            else:
                mc = None

            ch_type = ch.get("type", "HTTP")
            is_tcp = ch_type in ("TCP", "PIPE")
            if is_tcp and mc:
                wrapper = mc.get("wrapper")
                effective_mc = {"wrapper": wrapper} if wrapper else None
            else:
                effective_mc = mc

            allowed_routes.append({
                "transport_type": ch_type,
                "path": ch.get("path", ""),
                "port": ch.get("port", 0),
                "host": ch.get("host", ""),
                "user_agent": ch.get("user_agent", ""),
                "http_method": ch.get("http_method", "GET"),
                "malleable_config": effective_mc,
            })

        self._append_build(f"Uploading beacon {beacon_id[:16]} to server ({len(allowed_routes)} route(s))...")
        QApplication.processEvents()

        try:
            result = self._api.register_beacon(beacon_id, crypto_key, allowed_routes)
            if result.get("success"):
                self._append_build(f"OK: Beacon registered on server ({result.get('message', '')})")
                self._status_label.setText("Config uploaded to server")
            else:
                self._append_build(f"ERROR: {result.get('error', 'Unknown error')}")
        except Exception as e:
            self._append_build(f"ERROR: Upload failed: {e}")

    def _run_build(self):
        """Collect form values and run build in a background thread."""
        self._sync_form_to_config()

        channels = self._config.get("c2_channels", [])
        if not channels:
            QMessageBox.warning(self, "Build Error", "At least one C2 channel is required.")
            return

        self._build_output = ""
        self._build_output_text.clear()

        self._build_btn.setEnabled(False)
        self._upload_btn.setEnabled(False)
        self._build_progress.setVisible(True)

        self._worker = _BuildWorker(self._config, self)
        self._thread = QThread(self)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_build_progress)
        self._worker.error.connect(self._on_build_error)
        self._worker.finished.connect(self._on_build_finished)
        self._thread.start()

    def _on_build_progress(self, text: str):
        self._append_build(text)

    def _on_build_error(self, text: str):
        self._append_build(f"ERROR: {text}")

    def _on_build_finished(self):
        self._thread.quit()
        self._thread.wait()
        self._build_btn.setEnabled(True)
        self._build_progress.setVisible(False)
        self._upload_btn.setEnabled(self._api is not None and self._api.is_connected())

    def _append_build(self, text: str):
        self._build_output += text + "\n"
        self._build_output_text.append(text)
        cursor = self._build_output_text.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self._build_output_text.setTextCursor(cursor)

    # ── Config I/O ──────────────────────────────────────────────────

    def _sync_form_to_config(self):
        """Pull current widget values into self._config dict."""
        c = self._config

        c["sleep_ms"] = self._sleep_ms.value()
        c["jitter_pct"] = self._jitter_pct.value()
        c["pad"] = self._pad.isChecked()
        c["pad_max"] = self._pad_max.value()

        kd = self._kill_date.date()
        if kd.isValid() and kd != QDate.currentDate().addYears(1):
            dt = datetime(kd.year(), kd.month(), kd.day(), tzinfo=timezone.utc)
            c["kill_date"] = dt.strftime("%Y-%m-%d")
        else:
            c["kill_date"] = ""

        c["sleep_obfuscation"] = self._sleep_obf.currentText()
        c["sleep_wipe_pe_headers"] = self._wipe_pe.isChecked()
        c["sleep_stack_spoof"] = self._stack_spoof.isChecked()
        c["num_spoof_frames"] = self._num_frames.value()

        c["use_indirect_syscalls"] = self._indirect_sys.isChecked()
        c["indirect_syscall_pivot"] = self._pivot.text().strip()
        c["lazy_checkin"] = self._lazy_checkin.isChecked()
        c["lazy_checkin_max"] = self._lazy_checkin_max.value()
        c["lazy_unhook"] = self._lazy_unhook.isChecked()

        c.setdefault("options", {})
        c["options"]["sandbox_evasion"] = self._opt_sandbox.isChecked()
        c["options"]["debug_mode"] = self._opt_debug.isChecked()
        c["options"]["bypass_etw"] = self._opt_bypass_etw.isChecked()
        c["options"]["validate_ssl"] = self._opt_validate_ssl.isChecked()

        c.setdefault("malleable_config", {})
        # Sync malleable tab fields to the currently selected target (channel or global)
        mc, _ = self._get_malleable_target()
        mc.setdefault("wrapper", {})
        mc["wrapper"]["prefix"] = self._wrap_prefix.text().strip()
        mc["wrapper"]["suffix"] = self._wrap_suffix.text().strip()
        mc.setdefault("payload_location", {})
        mc["payload_location"]["type"] = self._pl_type.currentText()
        mc["payload_location"]["param_name"] = self._pl_param.text().strip()
        mc["payload_location"]["path_prefix"] = self._pl_path_prefix.text().strip()
        mc["payload_location"]["path_suffix"] = self._pl_path_suffix.text().strip()
        mc["payload_location"]["body_content_type"] = self._pl_body_ct.currentText()

        c.setdefault("work_hours", {})
        c["work_hours"]["enabled"] = self._wh_enabled.isChecked()
        c["work_hours"]["start_hour"] = self._wh_start_h.value()
        c["work_hours"]["start_minute"] = self._wh_start_m.value()
        c["work_hours"]["end_hour"] = self._wh_end_h.value()
        c["work_hours"]["end_minute"] = self._wh_end_m.value()
        c["work_hours"]["insomnia"] = self._wh_insomnia.isChecked()

        c.setdefault("spawnto", {})
        c["spawnto"]["x64"] = self._st_x64.text().strip()
        c["spawnto"]["x86"] = self._st_x86.text().strip()

        c["post_build"] = {"append": [self._post_append_list.item(i).text() for i in range(self._post_append_list.count())]}
        c["in_memory_append"] = {"append": [self._inmem_append_list.item(i).text() for i in range(self._inmem_append_list.count())]}

    def _sync_config_to_form(self):
        """Populate widget values from self._config dict."""
        c = self._config

        self._sleep_ms.setValue(c.get("sleep_ms", 5000))
        self._jitter_pct.setValue(c.get("jitter_pct", 20))
        self._pad.setChecked(c.get("pad", False))
        self._pad_max.setValue(c.get("pad_max", 1024))

        kd_str = c.get("kill_date", "")
        if kd_str:
            try:
                dt = datetime.strptime(kd_str, "%Y-%m-%d")
                self._kill_date.setDate(QDate(dt.year, dt.month, dt.day))
            except ValueError:
                self._kill_date.setDate(QDate.currentDate().addYears(1))
        else:
            self._kill_date.setDate(QDate.currentDate().addYears(1))

        self._sleep_obf.setCurrentText(c.get("sleep_obfuscation", "none"))
        self._wipe_pe.setChecked(c.get("sleep_wipe_pe_headers", False))
        self._stack_spoof.setChecked(c.get("sleep_stack_spoof", False))
        self._num_frames.setValue(c.get("num_spoof_frames", 6))

        self._indirect_sys.setChecked(c.get("use_indirect_syscalls", False))
        self._pivot.setText(c.get("indirect_syscall_pivot", ""))
        self._lazy_checkin.setChecked(c.get("lazy_checkin", False))
        self._lazy_checkin_max.setValue(c.get("lazy_checkin_max", 2))
        self._lazy_unhook.setChecked(c.get("lazy_unhook", False))

        opts = c.get("options", {})
        self._opt_sandbox.setChecked(opts.get("sandbox_evasion", False))
        self._opt_debug.setChecked(opts.get("debug_mode", False))
        self._opt_bypass_etw.setChecked(opts.get("bypass_etw", False))
        self._opt_validate_ssl.setChecked(opts.get("validate_ssl", False))

        # Populate malleable tab from currently selected target
        self._populate_malleable_channels()
        self._refresh_malleable_fields()

        # Update conditional visibility after loading config values
        self._update_conditional_visibility()

        wh = c.get("work_hours", {})
        self._wh_enabled.setChecked(wh.get("enabled", False))
        self._wh_start_h.setValue(wh.get("start_hour", 9))
        self._wh_start_m.setValue(wh.get("start_minute", 0))
        self._wh_end_h.setValue(wh.get("end_hour", 17))
        self._wh_end_m.setValue(wh.get("end_minute", 0))
        self._wh_insomnia.setChecked(wh.get("insomnia", False))

        st = c.get("spawnto", {})
        self._st_x64.setText(st.get("x64", ""))
        self._st_x86.setText(st.get("x86", ""))

        # Post-Build Append
        self._post_append_list.clear()
        post_build = c.get("post_build", {})
        for s in post_build.get("append", []):
            self._post_append_list.addItem(s)

        # In-Memory Append
        self._inmem_append_list.clear()
        inmem = c.get("in_memory_append", {})
        for s in inmem.get("append", []):
            self._inmem_append_list.addItem(s)

        self._refresh_channels_table()
        self._refresh_chain_stack()
        self._refresh_headers_table()

    def _load_config(self):
        """Load config from a JSON file."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Config", _default_json_path(),
            "JSON Files (*.json);;All Files (*)",
        )
        if not path:
            return
        try:
            with open(path, "r") as f:
                data = json.load(f)
            self._config = data
            self._config_path = path
            self._sync_config_to_form()
            self._status_label.setText(f"Loaded: {os.path.basename(path)}")
            self._tabs.setCurrentIndex(0)
        except Exception as e:
            QMessageBox.critical(self, "Load Error", str(e))

    def _save_config(self):
        """Save current config to a JSON file."""
        if not self._config_path:
            path, _ = QFileDialog.getSaveFileName(
                self, "Save Config", _default_json_path(),
                "JSON Files (*.json);;All Files (*)",
            )
            if not path:
                return
            self._config_path = path
        self._sync_form_to_config()
        try:
            with open(self._config_path, "w") as f:
                json.dump(self._config, f, indent=2)
            self._status_label.setText(f"Saved: {os.path.basename(self._config_path)}")
        except Exception as e:
            QMessageBox.critical(self, "Save Error", str(e))

    def _reset_config(self):
        """Reset config to defaults."""
        reply = QMessageBox.question(
            self, "Reset",
            "Reset all config fields to defaults?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._config_path = None
        self._build_output = ""
        self._build_output_text.clear()
        self._config = json.loads(json.dumps(_DEFAULT_CONFIG))
        self._sync_config_to_form()
        self._status_label.setText("Defaults loaded")
