"""
Beacon Detail Widget

Displays detailed system information for the selected beacon in a
read-only form layout (hostname, OS, process, IP, etc.), with an
embedded output viewer at the bottom. Supports copy-on-click,
color-coded elevation, and auto-scroll toggle.
"""

from datetime import datetime, timezone
from typing import Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QFormLayout, QLabel, QFrame, QGroupBox,
    QScrollArea, QTextEdit, QSplitter, QHBoxLayout, QPushButton, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QLineEdit, QCheckBox,
    QApplication,
)
from PyQt6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont, QColor, QTextCursor

from gui.api_client import PandragonAPI
from gui.widgets.notification_overlay import NotificationOverlay


class _InfoLabel(QLabel):
    """Clickable monospace label - copies text to clipboard on click."""

    def __init__(self, text: str = "-"):
        super().__init__(text)
        self.setObjectName("detailValue")
        self.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        f = QFont("Consolas", 10)
        f.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(f)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._copy_flash: Optional[QPropertyAnimation] = None

    def mousePressEvent(self, a0):
        if a0.button() == Qt.MouseButton.LeftButton:
            text = self.text()
            if text and text != "-":
                QApplication.clipboard().setText(text)
                self._flash_copied()
        super().mousePressEvent(a0)

    def _flash_copied(self):
        """Briefly show 'Copied!' tooltip."""
        orig_style = self.styleSheet()
        self.setStyleSheet("color: #00d4ff; background: transparent;")
        QTimer.singleShot(400, lambda: self.setStyleSheet(orig_style))

    def set_color(self, color: str):
        self.setStyleSheet(f"color: {color}; background: transparent; font-family: Consolas; font-size: 10pt;")


class BeaconDetailWidget(QWidget):
    """Read-only detail panel for the selected beacon with embedded output viewer."""

    def __init__(self, api: PandragonAPI, parent=None):
        super().__init__(parent)
        self.api = api
        self._notifications: Optional[NotificationOverlay] = None
        self.current_beacon_id: Optional[str] = None
        self._auto_scroll = True

        # Main vertical splitter: info (top) + output (bottom)
        main_splitter = QSplitter(Qt.Orientation.Vertical)

        # ── Top: Scrollable info panel ────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        container.setObjectName("beaconDetailContainer")
        self._layout = QVBoxLayout(container)
        self._layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # Identity group
        self._identity_group = self._make_group("Identity")
        self._identity_form = QFormLayout()
        self._identity_form.setSpacing(4)
        self._identity_fields: dict[str, _InfoLabel] = {}
        for label_text in ("Beacon ID", "Name", "Username", "Computer Name", "Domain"):
            lbl = _InfoLabel()
            self._identity_fields[label_text] = lbl
            self._identity_form.addRow(label_text, lbl)
        self._identity_group.setLayout(self._identity_form)
        self._layout.addWidget(self._identity_group)

        # OS group
        self._os_group = self._make_group("Operating System")
        self._os_form = QFormLayout()
        self._os_form.setSpacing(4)
        self._os_fields: dict[str, _InfoLabel] = {}
        for label_text in ("OS Version", "Architecture", "WoW64", "Elevated", "Domain Joined"):
            lbl = _InfoLabel()
            self._os_fields[label_text] = lbl
            self._os_form.addRow(label_text, lbl)
        self._os_group.setLayout(self._os_form)
        self._layout.addWidget(self._os_group)

        # Process group
        self._proc_group = self._make_group("Process")
        self._proc_form = QFormLayout()
        self._proc_form.setSpacing(4)
        self._proc_fields: dict[str, _InfoLabel] = {}
        for label_text in ("PID", "Process Name"):
            lbl = _InfoLabel()
            self._proc_fields[label_text] = lbl
            self._proc_form.addRow(label_text, lbl)
        self._proc_group.setLayout(self._proc_form)
        self._layout.addWidget(self._proc_group)

        # Hardware group
        self._hw_group = self._make_group("Hardware")
        self._hw_form = QFormLayout()
        self._hw_form.setSpacing(4)
        self._hw_fields: dict[str, _InfoLabel] = {}
        for label_text in ("RAM", "CPU Cores"):
            lbl = _InfoLabel()
            self._hw_fields[label_text] = lbl
            self._hw_form.addRow(label_text, lbl)
        self._hw_group.setLayout(self._hw_form)
        self._layout.addWidget(self._hw_group)

        # Network group
        self._net_group = self._make_group("Network")
        self._net_form = QFormLayout()
        self._net_form.setSpacing(4)
        self._net_fields: dict[str, _InfoLabel] = {}
        self._net_fields["Internal IPs"] = _InfoLabel()
        self._net_form.addRow("Internal IPs", self._net_fields["Internal IPs"])
        self._net_group.setLayout(self._net_form)
        self._layout.addWidget(self._net_group)

        # Async BOFs group (long-running BOFs)
        self._async_bof_group = self._make_group("Async BOFs (Long-Running)")
        async_bof_layout = QVBoxLayout()

        # Controls: Refresh + Auto-refresh toggle
        async_bof_controls = QHBoxLayout()
        self.async_bof_refresh_btn = QPushButton("Refresh")
        self.async_bof_refresh_btn.clicked.connect(self.refresh_async_bofs)
        async_bof_controls.addWidget(self.async_bof_refresh_btn)

        self.async_bof_auto_cb = QComboBox()
        self.async_bof_auto_cb.addItems(["Auto-refresh: Off", "Auto-refresh: 5s", "Auto-refresh: 10s"])
        self.async_bof_auto_cb.setCurrentIndex(1)  # Default to 5s
        self.async_bof_auto_cb.currentIndexChanged.connect(self._on_async_bof_auto_changed)
        async_bof_controls.addWidget(self.async_bof_auto_cb)

        async_bof_controls.addStretch()
        async_bof_layout.addLayout(async_bof_controls)

        # Async BOFs table: Task ID | Name | Started | Last Output | Actions
        self.async_bof_table = QTableWidget()
        self.async_bof_table.setColumnCount(5)
        self.async_bof_table.setHorizontalHeaderLabels(["Task ID", "Name", "Started", "Last Output", "Actions"])
        self.async_bof_table.setMaximumHeight(100)
        self.async_bof_table.setColumnWidth(0, 60)
        self.async_bof_table.setColumnWidth(1, 100)
        self.async_bof_table.setColumnWidth(2, 70)
        self.async_bof_table.setColumnWidth(3, 70)
        self.async_bof_table.horizontalHeader().setStretchLastSection(True)
        self.async_bof_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        async_bof_layout.addWidget(self.async_bof_table)

        # Status label for async BOF operations
        self.async_bof_status = QLabel("")
        self.async_bof_status.setObjectName("statusLabel")
        async_bof_layout.addWidget(self.async_bof_status)

        self._async_bof_group.setLayout(async_bof_layout)
        self._layout.addWidget(self._async_bof_group)

        self._layout.addStretch()
        scroll.setWidget(container)
        main_splitter.addWidget(scroll)

        # ── Bottom: Output viewer ──────────────────────────────
        output_container = QWidget()
        output_layout = QVBoxLayout(output_container)
        output_layout.setContentsMargins(0, 0, 0, 0)

        # Output controls row
        output_controls = QHBoxLayout()
        self.output_refresh_btn = QPushButton("Refresh")
        self.output_refresh_btn.clicked.connect(self.refresh_output)
        output_controls.addWidget(self.output_refresh_btn)

        self.output_clear_btn = QPushButton("Clear")
        self.output_clear_btn.clicked.connect(lambda: self.output_text.clear())
        output_controls.addWidget(self.output_clear_btn)

        self._auto_scroll_cb = QCheckBox("Auto-scroll")
        self._auto_scroll_cb.setChecked(True)
        self._auto_scroll_cb.stateChanged.connect(
            lambda state: setattr(self, '_auto_scroll', state == Qt.CheckState.Checked.value)
        )
        output_controls.addWidget(self._auto_scroll_cb)

        self.output_limit_label = QLabel("Limit:")
        output_controls.addWidget(self.output_limit_label)

        self.output_limit_combo = QComboBox()
        for lim in ["50", "100", "200", "500"]:
            self.output_limit_combo.addItem(lim)
        output_controls.addWidget(self.output_limit_combo)
        output_controls.addStretch()
        output_layout.addLayout(output_controls)

        # Output search bar
        search_row = QHBoxLayout()
        self.output_search = QLineEdit()
        self.output_search.setPlaceholderText("Search output\u2026")
        self.output_search.textChanged.connect(self._highlight_output)
        search_row.addWidget(self.output_search)
        self.output_match_label = QLabel("")
        self.output_match_label.setObjectName("statusLabel")
        search_row.addWidget(self.output_match_label)
        search_row.addStretch()
        output_layout.addLayout(search_row)

        # Output text area
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Consolas", 9))
        output_layout.addWidget(self.output_text)

        main_splitter.addWidget(output_container)
        main_splitter.setStretchFactor(0, 2)  # info gets 2 parts
        main_splitter.setStretchFactor(1, 3)  # output gets 3 parts

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(main_splitter)

        # Output auto-refresh timer
        self._output_timer = QTimer(self)
        self._output_timer.timeout.connect(self.refresh_output)

        # Async BOF auto-refresh timer
        self._async_bof_timer = QTimer(self)
        self._async_bof_timer.timeout.connect(self.refresh_async_bofs)

        self._clear_fields()

    # ── Public API ──────────────────────────────────────────────

    def set_notification_overlay(self, overlay: NotificationOverlay):
        self._notifications = overlay

    def update_beacon(self, beacon_id: Optional[str]) -> None:
        """Load and display details for the given beacon ID."""
        self.current_beacon_id = beacon_id
        if not beacon_id:
            self._clear_fields()
            self.output_text.clear()
            self._output_timer.stop()
            self._async_bof_timer.stop()
            return

        try:
            detail = self.api.get_beacon(beacon_id)
        except Exception:
            self._clear_fields()
            return

        self._set_field(self._identity_fields, "Beacon ID", detail.get("beacon_id", "-"))
        self._set_field(self._identity_fields, "Name", detail.get("name") or "-")
        self._set_field(self._identity_fields, "Username", detail.get("username") or "-")
        self._set_field(self._identity_fields, "Computer Name", detail.get("computer_name") or "-")
        self._set_field(self._identity_fields, "Domain", detail.get("domain") or "-")

        os_ver = ".".join(str(v) for v in [
            detail.get("os_major"), detail.get("os_minor"), detail.get("os_build"),
        ] if v is not None)
        self._set_field(self._os_fields, "OS Version", os_ver or "-")
        arch = detail.get("arch")
        if isinstance(arch, int):
            arch_str = "x64" if arch == 0 else "x86 (WoW64)" if arch == 1 else str(arch)
        elif isinstance(arch, str):
            arch_str = arch or "-"
        else:
            arch_str = "-"
        self._set_field(self._os_fields, "Architecture", arch_str)
        self._set_field(self._os_fields, "WoW64", self._bool(detail.get("is_wow64")))
        self._set_field(self._os_fields, "Domain Joined", self._bool(detail.get("is_domain_joined")))

        # Color-coded elevation
        elevated = detail.get("is_elevated")
        if elevated:
            self._os_fields["Elevated"].setText("Yes")
            self._os_fields["Elevated"].set_color("#00ff00")
        else:
            self._os_fields["Elevated"].setText("No")
            self._os_fields["Elevated"].set_color("#ff6666")

        pid = detail.get("pid")
        self._set_field(self._proc_fields, "PID", str(pid) if pid is not None else "-")
        self._set_field(self._proc_fields, "Process Name", detail.get("process_name") or "-")

        ram = detail.get("ram_mb")
        self._set_field(self._hw_fields, "RAM", f"{ram} MB" if ram is not None else "-")
        cores = detail.get("cpu_cores")
        self._set_field(self._hw_fields, "CPU Cores", str(cores) if cores is not None else "-")

        ips = detail.get("internal_ips") or []
        self._set_field(self._net_fields, "Internal IPs", ", ".join(ips) if ips else "-")

        # Refresh async BOFs
        self.refresh_async_bofs()
        self._output_timer.start(5000)
        self._async_bof_timer.start(5000)

    def refresh_output(self) -> None:
        """Fetch and display beacon output."""
        if not self.current_beacon_id:
            return
        try:
            limit = int(self.output_limit_combo.currentText())
            data = self.api.get_beacon_output(self.current_beacon_id, limit)
            self.output_text.clear()
            for entry in data.get("output", []):
                ts = datetime.fromtimestamp(entry["time"]).strftime("%H:%M:%S")
                self._append_output(
                    f"[{ts}] {entry['data']}",
                    timestamp_color="#888888",
                )
            if self._auto_scroll:
                self._scroll_to_end()
        except Exception:
            pass  # Silent fail; output is non-critical

    def refresh_async_bofs(self) -> None:
        if not self.current_beacon_id:
            return
        try:
            data = self.api.list_async_bofs(self.current_beacon_id)
            async_bofs = data.get("async_bofs", [])

            existing = {}
            for i in range(self.async_bof_table.rowCount()):
                tid_item = self.async_bof_table.item(i, 0)
                if tid_item:
                    existing[int(tid_item.text())] = i

            new_ids = {b.get("task_id", 0) for b in async_bofs}
            for tid in list(existing.keys()):
                if tid not in new_ids:
                    self.async_bof_table.removeRow(existing[tid])

            self.async_bof_table.setRowCount(len(async_bofs))
            for i, bof in enumerate(async_bofs):
                task_id = bof.get("task_id", 0)
                name = bof.get("bof_name", "BOF")
                started = bof.get("started", 0)
                last_output = bof.get("last_output", 0)

                if existing.get(task_id) == i:
                    continue

                self.async_bof_table.setItem(i, 0, QTableWidgetItem(str(task_id)))
                self.async_bof_table.setItem(i, 1, QTableWidgetItem(name))
                start_ts = datetime.fromtimestamp(started).strftime("%H:%M:%S") if started else "-"
                self.async_bof_table.setItem(i, 2, QTableWidgetItem(start_ts))
                last_ts = datetime.fromtimestamp(last_output).strftime("%H:%M:%S") if last_output else "-"
                self.async_bof_table.setItem(i, 3, QTableWidgetItem(last_ts))

                abort_btn = QPushButton("ABORT")
                abort_btn.setObjectName("AbortBtn")
                abort_btn.clicked.connect(lambda checked, tid=task_id: self._abort_async_bof(tid))
                self.async_bof_table.setCellWidget(i, 4, abort_btn)
        except Exception:
            pass

    def _abort_async_bof(self, task_id: int) -> None:
        """Send ABORT signal to a specific async BOF."""
        if not self.current_beacon_id:
            return
        try:
            result = self.api.abort_async_bof(self.current_beacon_id, task_id)
            if result.get("success"):
                self.async_bof_status.setText(f"ABORT sent to task {task_id}")
            # Refresh the list
            self.refresh_async_bofs()
        except Exception as e:
            self.async_bof_status.setText(f"Error: {e}")

    def _on_async_bof_auto_changed(self, index: int) -> None:
        """Handle auto-refresh dropdown change."""
        intervals = [0, 5000, 10000]  # Off, 5s, 10s
        if self._async_bof_timer.isActive():
            self._async_bof_timer.stop()
        interval = intervals[index]
        if interval > 0:
            self._async_bof_timer.start(interval)

    def handle_beacon_output(self, beacon_id: str, data: dict) -> None:
        """WebSocket event handler for real-time output append."""
        if self.current_beacon_id and beacon_id != self.current_beacon_id:
            return

        output_entries = data.get("output")
        if output_entries is not None:
            if isinstance(output_entries, list):
                for entry in output_entries:
                    ts = datetime.fromtimestamp(entry.get("time", 0)).strftime("%H:%M:%S")
                    self._append_output(
                        f"[{ts}] {entry.get('data', '')}",
                        timestamp_color="#888888",
                    )
            elif isinstance(output_entries, dict):
                ts = datetime.fromtimestamp(output_entries.get("time", 0)).strftime("%H:%M:%S")
                self._append_output(
                    f"[{ts}] {output_entries.get('data', '')}",
                    timestamp_color="#888888",
                )
        else:
            text_data = data.get("data", "")
            if text_data:
                ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                entry_type = data.get("type", "output")
                self._append_output(
                    f"[{ts}] [{entry_type.upper()}] {text_data}",
                    is_error=(entry_type.lower() == "error"),
                    timestamp_color="#888888",
                )

        if self._auto_scroll:
            self._scroll_to_end()

    # ── Output helpers ──────────────────────────────────────────

    def _append_output(self, text: str, is_error: bool = False,
                       timestamp_color: str = None):
        if timestamp_color and text.startswith("["):
            # Color the timestamp portion separately
            close = text.index("]") + 1
            ts_part = text[:close]
            data_part = text[close:]
            color = "#ff6666" if is_error else "#e0e0e0"
            html = (
                f'<span style="color:{timestamp_color}">{ts_part}</span>'
                f'<span style="color:{color}">{data_part}</span>'
            )
            self.output_text.append(html)
        else:
            color = QColor('#ff6666') if is_error else QColor('#e0e0e0')
            self.output_text.setTextColor(color)
            self.output_text.append(text)

    def _scroll_to_end(self):
        cursor = self.output_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.output_text.setTextCursor(cursor)

    def _highlight_output(self):
        text = self.output_search.text().lower()
        if not text:
            self.output_match_label.setText("")
            self.output_text.setExtraSelections([])
            return

        selections = []
        doc = self.output_text.document()
        block = doc.begin()
        matches = 0
        while block.isValid():
            pos = block.position()
            content = block.text().lower()
            idx = content.find(text)
            while idx >= 0:
                cur = self.output_text.textCursor()
                cur.setPosition(pos + idx)
                cur.setPosition(pos + idx + len(text), QTextCursor.MoveMode.KeepAnchor)
                sel = QTextEdit.ExtraSelection()
                sel.cursor = cur
                sel.format.setBackground(QColor(255, 200, 0, 100))
                selections.append(sel)
                matches += 1
                idx = content.find(text, idx + 1)
            block = block.next()

        self.output_text.setExtraSelections(selections)
        self.output_match_label.setText(f"{matches} match{'es' if matches != 1 else ''}")

    # ── Internal helpers ────────────────────────────────────────

    @staticmethod
    def _make_group(title: str) -> QGroupBox:
        group = QGroupBox(title)
        return group

    @staticmethod
    def _bool(val) -> str:
        return "Yes" if val else "No"

    def _set_field(self, group: dict[str, _InfoLabel], label: str, value: str) -> None:
        if label in group:
            group[label].setText(value)
            # Reset color to default
            group[label].setStyleSheet("color: #c8d8e8; background: transparent; font-family: Consolas; font-size: 10pt;")

    def _clear_fields(self) -> None:
        for group in (self._identity_fields, self._os_fields,
                      self._proc_fields, self._hw_fields, self._net_fields):
            for lbl in group.values():
                lbl.setText("-")
                lbl.setStyleSheet("color: #c8d8e8; background: transparent; font-family: Consolas; font-size: 10pt;")
