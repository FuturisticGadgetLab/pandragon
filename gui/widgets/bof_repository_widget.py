"""
BOF Repository Widget

Manages BOF .o files stored on the teamserver: list, upload, delete,
and execute on selected beacons.
"""

import base64
from typing import Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QMessageBox, QComboBox, QLineEdit, QGroupBox, QFormLayout,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont

from gui.api_client import PandragonAPI
from gui.widgets.notification_overlay import NotificationOverlay


class BOFRepositoryWidget(QWidget):
    """Server BOF file manager with upload, delete, and deploy-to-beacon."""

    def __init__(self, api: PandragonAPI, parent=None):
        super().__init__(parent)
        self.api = api
        self._notifications: Optional[NotificationOverlay] = None
        self._bofs: list[dict] = []

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # ── Toolbar ──────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self.refresh)
        toolbar.addWidget(self._refresh_btn)

        self._upload_btn = QPushButton("Upload BOF")
        self._upload_btn.clicked.connect(self._upload_bof)
        toolbar.addWidget(self._upload_btn)

        self._delete_btn = QPushButton("Delete")
        self._delete_btn.clicked.connect(self._delete_bof)
        toolbar.addWidget(self._delete_btn)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        # ── BOF table ────────────────────────────────────────────
        self._table = QTableWidget()
        self._table.setColumnCount(3)
        self._table.setHorizontalHeaderLabels(["Name", "Size", "Modified"])
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().hide()
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setFont(QFont("Consolas", 9))
        layout.addWidget(self._table, 1)

        # ── Deploy section ───────────────────────────────────────
        deploy_group = QGroupBox("Execute on Beacon")
        deploy_layout = QFormLayout(deploy_group)
        deploy_layout.setSpacing(6)

        beacon_row = QHBoxLayout()
        self._beacon_combo = QComboBox()
        self._beacon_combo.setMinimumWidth(300)
        self._beacon_combo.setPlaceholderText("Select a beacon\u2026")
        beacon_row.addWidget(self._beacon_combo)
        self._refresh_beacons_btn = QPushButton("Refresh")
        self._refresh_beacons_btn.clicked.connect(self._populate_beacons)
        beacon_row.addWidget(self._refresh_beacons_btn)
        beacon_row.addStretch()
        deploy_layout.addRow("Target Beacon:", beacon_row)

        self._args_input = QLineEdit()
        self._args_input.setPlaceholderText("arg1 arg2 ...")
        deploy_layout.addRow("Arguments:", self._args_input)

        self._execute_btn = QPushButton("Execute Selected BOF")
        self._execute_btn.clicked.connect(self._execute_bof)
        deploy_layout.addRow("", self._execute_btn)

        layout.addWidget(deploy_group)

        # Initial load
        QTimer.singleShot(500, self.refresh)

    def set_notification_overlay(self, overlay: NotificationOverlay):
        self._notifications = overlay

    # ── BOF list ─────────────────────────────────────────────────

    def refresh(self):
        try:
            self._bofs = self.api.list_bofs()
            self._populate_table()
        except Exception as e:
            if self._notifications:
                self._notifications.warning(f"Failed to list BOFs: {e}", 5000)

    def _populate_table(self):
        self._table.setRowCount(len(self._bofs))
        for i, bof in enumerate(self._bofs):
            self._table.setItem(i, 0, QTableWidgetItem(bof.get("filename", "")))
            size = bof.get("size", 0)
            size_str = f"{size} B" if size < 1024 else f"{size / 1024:.1f} KB"
            self._table.setItem(i, 1, QTableWidgetItem(size_str))
            mod = bof.get("modified", 0)
            from datetime import datetime
            mod_str = datetime.fromtimestamp(mod).strftime("%Y-%m-%d %H:%M") if mod else "-"
            self._table.setItem(i, 2, QTableWidgetItem(mod_str))
        self._table.resizeColumnsToContents()

    # ── Beacon list for deploy ───────────────────────────────────

    def _populate_beacons(self):
        try:
            beacons = self.api.list_beacons()
            self._beacon_combo.clear()
            for b in beacons:
                label = b.get("name") or b.get("computer_name") or b["beacon_id"][:16]
                self._beacon_combo.addItem(f"{b['beacon_id'][:12]}  {label}", b["beacon_id"])
        except Exception as e:
            if self._notifications:
                self._notifications.warning(f"Failed to list beacons: {e}", 3000)

    # ── Upload ───────────────────────────────────────────────────

    def _upload_bof(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select BOF File", "", "BOF Files (*.o *.obj);;All Files (*)"
        )
        if not path:
            return
        import os
        filename = os.path.basename(path)
        try:
            with open(path, "rb") as f:
                file_bytes = f.read()
            if not file_bytes:
                QMessageBox.warning(self, "Error", "File is empty")
                return
            MAX_UPLOAD = 4 * 1024 * 1024
            if len(file_bytes) > MAX_UPLOAD:
                QMessageBox.warning(self, "Error", f"File too large ({len(file_bytes)} bytes, max {MAX_UPLOAD})")
                return
            data_b64 = base64.b64encode(file_bytes).decode()
            self.api.upload_bof(filename, data_b64)
            if self._notifications:
                self._notifications.success(f"Uploaded {filename}", 3000)
            self.refresh()
        except Exception as e:
            QMessageBox.critical(self, "Upload Failed", str(e))

    # ── Delete ───────────────────────────────────────────────────

    def _delete_bof(self):
        row = self._table.currentRow()
        if row < 0 or row >= len(self._bofs):
            QMessageBox.warning(self, "Warning", "No BOF selected")
            return
        filename = self._bofs[row].get("filename", "")
        reply = QMessageBox.question(
            self, "Confirm Delete", f"Delete {filename} from server?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            self.api.delete_bof(filename)
            if self._notifications:
                self._notifications.success(f"Deleted {filename}", 3000)
            self.refresh()
        except Exception as e:
            QMessageBox.critical(self, "Delete Failed", str(e))

    # ── Execute ──────────────────────────────────────────────────

    def _execute_bof(self):
        row = self._table.currentRow()
        if row < 0 or row >= len(self._bofs):
            QMessageBox.warning(self, "Warning", "No BOF selected in the table")
            return
        if self._beacon_combo.currentIndex() < 0:
            QMessageBox.warning(self, "Warning", "No beacon selected")
            return
        beacon_id = self._beacon_combo.currentData()
        bof_filename = self._bofs[row].get("filename", "")
        args = self._args_input.text().strip()
        text = f"{bof_filename} {args}".strip()
        payload = base64.b64encode(text.encode()).decode()
        desc = f"bof: {bof_filename}"
        try:
            result = self.api.create_task(
                beacon_id=beacon_id, opcode=0x10, payload=payload,
                description=desc,
            )
            task_id = result.get("task_id", "?")
            if self._notifications:
                self._notifications.success(f"BOF queued (task {task_id})", 4000)
        except Exception as e:
            QMessageBox.critical(self, "Execute Failed", str(e))
