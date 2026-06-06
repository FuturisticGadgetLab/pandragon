"""
P2P Relay Management Widget for Pandragon Operator Console

Provides UI for managing P2P beacon relay chains:
- Enable/disable relay on parent beacons
- Add/remove child beacons from relay
- View relay status and pipe information
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QDialog, QLineEdit, QFormLayout, QDialogButtonBox, QGroupBox,
    QSpinBox, QCheckBox, QFrame
)
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QColor

from gui.widgets.notification_overlay import NotificationOverlay


class RelayWidget(QWidget):
    """Widget for managing P2P beacon relay chains."""

    relay_updated = pyqtSignal()

    def __init__(self, api, parent=None):
        super().__init__(parent)
        self.api = api
        self.relay_data = {}
        self._notifications: Optional[NotificationOverlay] = None
        self._init_ui()
        self.refresh()

    def set_notification_overlay(self, overlay: NotificationOverlay):
        self._notifications = overlay

    def _init_ui(self):
        """Initialize the UI components."""
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        title = QLabel("P2P Beacon Relay Management")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        btn_layout = QHBoxLayout()

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        btn_layout.addWidget(self.refresh_btn)

        self.enable_btn = QPushButton("Enable Relay")
        self.enable_btn.clicked.connect(self.enable_relay)
        btn_layout.addWidget(self.enable_btn)

        self.disable_btn = QPushButton("Disable Relay")
        self.disable_btn.clicked.connect(self.disable_relay)
        btn_layout.addWidget(self.disable_btn)

        self.add_child_btn = QPushButton("Add Child")
        self.add_child_btn.clicked.connect(self.add_child)
        btn_layout.addWidget(self.add_child_btn)

        self.remove_child_btn = QPushButton("Remove Child")
        self.remove_child_btn.clicked.connect(self.remove_child)
        btn_layout.addWidget(self.remove_child_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        status_group = QGroupBox("Relay Status")
        status_layout = QVBoxLayout()

        self.status_label = QLabel("Status: Loading...")
        status_layout.addWidget(self.status_label)

        self.parent_count_label = QLabel("Parent Beacons: 0")
        status_layout.addWidget(self.parent_count_label)

        self.child_count_label = QLabel("Child Beacons: 0")
        status_layout.addWidget(self.child_count_label)

        status_group.setLayout(status_layout)
        layout.addWidget(status_group)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Beacon ID", "Type", "Parent", "Pipe ID", "Pipe Name", "Status"
        ])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)

        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

        self.setLayout(layout)

    def refresh(self):
        """Refresh relay data from server."""
        try:
            self.relay_data = self.api.get_relay_graph()
            self._update_table()
            self._update_status()
        except Exception as e:
            self.status_label.setText(f"Status: Error - {e}")

    def _update_table(self):
        """Update the relay table with current data."""
        if not self.relay_data:
            self.table.setRowCount(0)
            return

        nodes = self.relay_data.get('nodes', [])
        edges = self.relay_data.get('edges', [])

        edge_lookup = {}
        for edge in edges:
            edge_lookup[edge['to']] = edge

        # Build lookup of existing rows by full beacon ID
        existing_rows = {}
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                bid = item.data(Qt.ItemDataRole.UserRole)
                if bid:
                    existing_rows[bid] = row

        current_ids = {n.get('id', '') for n in nodes}

        # Remove stale rows (bottom-up to preserve indices)
        stale_rows = sorted(
            [row for bid, row in existing_rows.items() if bid not in current_ids],
            reverse=True
        )
        for row in stale_rows:
            self.table.removeRow(row)

        # Rebuild lookup after removals
        existing_rows = {}
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                bid = item.data(Qt.ItemDataRole.UserRole)
                if bid:
                    existing_rows[bid] = row

        for node in nodes:
            beacon_id = node.get('id', '')
            short_id = beacon_id[:8] if len(beacon_id) > 8 else beacon_id
            transport = node.get('transport', 'direct')

            parent_id = ''
            full_parent_id = ''
            pipe_id = ''
            pipe_name = ''
            if transport == 'relay':
                edge = edge_lookup.get(node.get('id'), {})
                full_parent_id = edge.get('from', '')
                parent_id = full_parent_id[:8] if full_parent_id else ''
                pipe_id = str(edge.get('pipe_id', ''))

            is_alive = node.get('is_alive', True)
            status = "Alive" if is_alive else "Offline"

            if beacon_id in existing_rows:
                row = existing_rows[beacon_id]
                self.table.item(row, 0).setText(short_id)
                self.table.item(row, 1).setText(transport)
                self.table.item(row, 2).setText(parent_id)
                self.table.item(row, 2).setData(Qt.ItemDataRole.UserRole, full_parent_id)
                self.table.item(row, 3).setText(str(pipe_id))
                self.table.item(row, 4).setText(pipe_name)
                self.table.item(row, 5).setText(status)
                if not is_alive:
                    self.table.item(row, 5).setBackground(QColor(255, 200, 200))
                else:
                    self.table.item(row, 5).setBackground(QBrush())
            else:
                row = self.table.rowCount()
                self.table.insertRow(row)
                id_item = QTableWidgetItem(short_id)
                id_item.setData(Qt.ItemDataRole.UserRole, beacon_id)
                self.table.setItem(row, 0, id_item)
                self.table.setItem(row, 1, QTableWidgetItem(transport))
                parent_item = QTableWidgetItem(parent_id)
                parent_item.setData(Qt.ItemDataRole.UserRole, full_parent_id)
                self.table.setItem(row, 2, parent_item)
                self.table.setItem(row, 3, QTableWidgetItem(str(pipe_id)))
                self.table.setItem(row, 4, QTableWidgetItem(pipe_name))
                status_item = QTableWidgetItem(status)
                if not is_alive:
                    status_item.setBackground(QColor(255, 200, 200))
                self.table.setItem(row, 5, status_item)

    def _update_status(self):
        """Update status labels."""
        nodes = self.relay_data.get('nodes', []) if self.relay_data else []
        edges = self.relay_data.get('edges', []) if self.relay_data else []

        parent_count = 0
        parent_ids = set()
        for edge in edges:
            parent_ids.add(edge.get('from'))
        parent_count = len(parent_ids)

        self.status_label.setText("Status: Connected")
        self.parent_count_label.setText(f"Parent Beacons: {parent_count}")
        self.child_count_label.setText(f"Child Beacons: {len(edges)}")

    def enable_relay(self):
        """Enable relay on selected beacon."""
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Please select a beacon first.")
            return

        item = self.table.item(row, 0)
        beacon_id = item.data(Qt.ItemDataRole.UserRole) or item.text()

        dialog = EnableRelayDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            pipe_prefix = dialog.get_pipe_prefix()
            try:
                self.api.relay_enable(beacon_id, pipe_prefix)
                QMessageBox.information(self, "Relay Enabled",
                                       f"Relay enabled for beacon {beacon_id}")
                self.refresh()
                self.relay_updated.emit()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to enable relay: {e}")

    def disable_relay(self):
        """Disable relay on selected beacon."""
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Please select a beacon first.")
            return

        item = self.table.item(row, 0)
        beacon_id = item.data(Qt.ItemDataRole.UserRole) or item.text()

        reply = QMessageBox.question(
            self, "Confirm Disable",
            f"Disable relay on beacon {beacon_id}?\nThis will drain all children.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.api.relay_disable(beacon_id)
                QMessageBox.information(self, "Relay Disabled",
                                       f"Relay disabled for beacon {beacon_id}")
                self.refresh()
                self.relay_updated.emit()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to disable relay: {e}")

    def add_child(self):
        """Add a child beacon to relay."""
        dialog = AddChildDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            parent_id = dialog.get_parent_id()
            child_id = dialog.get_child_id()
            pipe_name = dialog.get_pipe_name()

            if not parent_id or not child_id:
                QMessageBox.warning(self, "Invalid Input", "Parent and Child IDs are required.")
                return

            try:
                self.api.relay_add_child(parent_id, child_id, pipe_name)
                QMessageBox.information(self, "Child Added",
                                       f"Child {child_id[:8]} added to relay")
                self.refresh()
                self.relay_updated.emit()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add child: {e}")

    def remove_child(self):
        """Remove selected child from relay."""
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Please select a child beacon.")
            return

        transport = self.table.item(row, 1).text()
        if transport != 'relay':
            QMessageBox.warning(self, "Not a Relay", "Selected beacon is not relayed.")
            return

        parent_item = self.table.item(row, 2)
        child_item = self.table.item(row, 0)
        parent_id = parent_item.data(Qt.ItemDataRole.UserRole) or parent_item.text()
        child_id = child_item.data(Qt.ItemDataRole.UserRole) or child_item.text()

        if not parent_id:
            QMessageBox.warning(self, "No Parent", "Parent ID not found.")
            return

        reply = QMessageBox.question(
            self, "Confirm Remove",
            f"Remove child {child_id} from parent {parent_id}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.api.relay_remove_child(parent_id, child_id)
                QMessageBox.information(self, "Child Removed",
                                       f"Child {child_id} removed from relay")
                self.refresh()
                self.relay_updated.emit()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to remove child: {e}")


class EnableRelayDialog(QDialog):
    """Dialog for enabling relay on a beacon."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enable P2P Relay")
        self.setMinimumWidth(400)

        layout = QFormLayout()

        self.pipe_prefix_edit = QLineEdit("msagent")
        self.pipe_prefix_edit.setPlaceholderText("msagent")
        layout.addRow("Pipe Name Prefix:", self.pipe_prefix_edit)

        info = QLabel("The pipe name will be generated as: {prefix}_{random_hex}")
        info.setWordWrap(True)
        layout.addRow(info)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

        self.setLayout(layout)

    def get_pipe_prefix(self) -> str:
        return self.pipe_prefix_edit.text().strip() or "msagent"


class AddChildDialog(QDialog):
    """Dialog for adding a child beacon to relay."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Child Beacon to Relay")
        self.setMinimumWidth(400)

        layout = QFormLayout()

        self.parent_id_edit = QLineEdit()
        self.parent_id_edit.setPlaceholderText("e.g., abcdef1234567890")
        self.parent_id_edit.setMaxLength(16)
        layout.addRow("Parent Beacon ID:", self.parent_id_edit)

        self.child_id_edit = QLineEdit()
        self.child_id_edit.setPlaceholderText("e.g., 1234567890abcdef")
        self.child_id_edit.setMaxLength(16)
        layout.addRow("Child Beacon ID:", self.child_id_edit)

        self.pipe_name_edit = QLineEdit()
        self.pipe_name_edit.setPlaceholderText("Auto-generated if empty")
        layout.addRow("Pipe Name (optional):", self.pipe_name_edit)

        info = QLabel("Child beacon will connect to parent via named pipe.")
        info.setWordWrap(True)
        layout.addRow(info)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

        self.setLayout(layout)

    def get_parent_id(self) -> str:
        return self.parent_id_edit.text().strip()

    def get_child_id(self) -> str:
        return self.child_id_edit.text().strip()

    def get_pipe_name(self) -> str:
        return self.pipe_name_edit.text().strip()
