"""
Task Queue Widget

Local task queue: tasks are queued here and flushed to the server
when a beacon activity event is received, or manually via the Flush buttons.
Supports drag-to-reorder and inline description editing.
"""

import base64
import logging
import uuid
from datetime import datetime
from typing import Optional

logger = logging.getLogger('pandragon.gui.task_queue')

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
    QPushButton, QLabel, QComboBox, QMessageBox, QHeaderView,
    QAbstractItemView,
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor

from gui.api_client import PandragonAPI
from gui.widgets.beacon_table import BeaconTableWidget
from gui.widgets.notification_overlay import NotificationOverlay


class _QueuedTask:
    """Represents a locally queued task waiting for beacon check-in."""

    def __init__(self, beacon_id: str, opcode: int, payload: str,
                 priority: str = "normal", description: str = "",
                 schedule_type: str = "immediate", delay_seconds: int = 0,
                 cron_expression: str = "", max_retries: int = 0):
        self.id = str(uuid.uuid4())[:8]
        self.beacon_id = beacon_id
        self.opcode = opcode
        self.payload = payload
        self.priority = priority
        self.description = description
        self.schedule_type = schedule_type
        self.delay_seconds = delay_seconds
        self.cron_expression = cron_expression
        self.max_retries = max_retries
        self.queued_at = datetime.now()
        self.status = "queued"  # queued | flushing | done | failed


class TaskQueueWidget(QWidget):
    """Local task queue with auto-flush on beacon check-in."""

    # Signal to notify beacon_table of count changes
    queue_counts_changed = pyqtSignal()

    OPCODE_NAMES = {
        0x00: "NO_TASKS", 0x01: "ECHO", 0x02: "SLEEP",
        0x10: "BOF_EXEC", 0x11: "FILE_DOWNLOAD",
        0x12: "FILE_UPLOAD", 0x13: "LIST_FILES", 0x1E: "ROTATE_KEY",
        0x20: "FILE_DOWNLOAD_START", 0x21: "FILE_DOWNLOAD_CHUNK",
        0x22: "FILE_UPLOAD_START", 0x23: "FILE_UPLOAD_CHUNK",
        0x25: "ETW_ENABLE", 0x26: "ETW_DISABLE",
        0x30: "INJECT", 0x31: "MIGRATE", 0x32: "HOLLOW",
        0xFF: "DIE",
    }

    def __init__(self, api: PandragonAPI, beacon_table: BeaconTableWidget, parent=None):
        super().__init__(parent)
        self.api = api
        self.beacon_table = beacon_table
        self._notifications: Optional[NotificationOverlay] = None

        # In-memory queue: beacon_id -> list of _QueuedTask
        self._queue: dict[str, list[_QueuedTask]] = {}
        self._task_id_map: dict[str, _QueuedTask] = {}

        layout = QVBoxLayout(self)

        # Controls
        controls = QHBoxLayout()
        self.flush_all_btn = QPushButton("Flush All Queues")
        self.flush_all_btn.clicked.connect(self._flush_all)
        self.flush_all_btn.setObjectName("FlushAllBtn")
        controls.addWidget(self.flush_all_btn)

        self.flush_selected_btn = QPushButton("Flush Selected")
        self.flush_selected_btn.clicked.connect(self._flush_selected)
        controls.addWidget(self.flush_selected_btn)

        self.cancel_btn = QPushButton("Cancel Selected")
        self.cancel_btn.clicked.connect(self._cancel_selected)
        controls.addWidget(self.cancel_btn)

        self.filter_combo = QComboBox()
        self.filter_combo.addItems(["All Beacons"])
        self.filter_combo.currentTextChanged.connect(self._refresh_view)
        controls.addWidget(QLabel("Filter:"))
        controls.addWidget(self.filter_combo)

        controls.addStretch()
        layout.addLayout(controls)

        # Task tree
        self.tree = QTreeWidget()
        self.tree.setColumnCount(6)
        self.tree.setHeaderLabels(["Task ID", "Beacon", "Opcode", "Priority", "Description", "Queued At"])
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.tree.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self.tree)

        # Status bar
        self.status_label = QLabel("No queued tasks")
        self.status_label.setObjectName("statusLabel")
        layout.addWidget(self.status_label)

    def set_notification_overlay(self, overlay: NotificationOverlay):
        self._notifications = overlay

    # ── Public API ──────────────────────────────────────────────

    def add_task(self, beacon_id: str, opcode: int, payload: str,
                 priority: str = "normal", description: str = "",
                 **kwargs) -> _QueuedTask:
        """Add a task to the local queue for the given beacon."""
        task = _QueuedTask(
            beacon_id=beacon_id, opcode=opcode, payload=payload,
            priority=priority, description=description, **kwargs
        )
        if beacon_id not in self._queue:
            self._queue[beacon_id] = []
        self._queue[beacon_id].append(task)
        self._refresh_view()
        self.queue_counts_changed.emit()
        return task

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a queued task before it's flushed."""
        for beacon_id, tasks in self._queue.items():
            for i, task in enumerate(tasks):
                if task.id == task_id:
                    task.status = "cancelled"
                    tasks.pop(i)
                    if not tasks:
                        del self._queue[beacon_id]
                    self._refresh_view()
                    self.queue_counts_changed.emit()
                    return True
        return False

    def cancel_all_for_beacon(self, beacon_id: str) -> int:
        """Cancel all queued tasks for a specific beacon. Returns count."""
        count = 0
        if beacon_id in self._queue:
            count = len(self._queue[beacon_id])
            del self._queue[beacon_id]
        self._refresh_view()
        self.queue_counts_changed.emit()
        return count

    def get_queue_count(self, beacon_id: str) -> int:
        """Return number of queued tasks for a beacon."""
        return len(self._queue.get(beacon_id, []))

    def get_total_count(self) -> int:
        """Return total number of queued tasks across all beacons."""
        return sum(len(v) for v in self._queue.values())

    def flush_beacon(self, beacon_id: str) -> tuple[int, int]:
        """
        Submit all queued tasks for a beacon to the server.
        Returns (success_count, fail_count).
        """
        tasks = self._queue.pop(beacon_id, [])
        success = 0
        failed = 0

        for task in tasks:
            task.status = "flushing"
            try:
                raw = base64.b64decode(task.payload)
                payload_hex = raw.hex()
                self.api.create_task(
                    beacon_id=beacon_id,
                    opcode=task.opcode,
                    payload=payload_hex,
                    description=task.description,
                )
                task.status = "done"
                success += 1
            except Exception as e:
                task.status = "failed"
                task.description = f"FAILED: {e}"
                if beacon_id not in self._queue:
                    self._queue[beacon_id] = []
                self._queue[beacon_id].append(task)
                failed += 1

        self._refresh_view()
        self.queue_counts_changed.emit()
        return success, failed

    def handle_beacon_activity(self, beacon_id: str):
        """WebSocket-driven auto-flush: called when a beacon checks in."""
        if beacon_id in self._queue:
            self.flush_beacon(beacon_id)

    # ── Internal ────────────────────────────────────────────────

    def _on_item_double_clicked(self, item: QTreeWidgetItem, column: int):
        """Double-click a task to edit its description inline."""
        if column == 4:
            self.tree.editItem(item, column)

    def _flush_all(self):
        """Flush all queued tasks for all beacons."""
        if not self._queue:
            QMessageBox.information(self, "Info", "No queued tasks")
            return

        total = self.get_total_count()
        reply = QMessageBox.question(
            self, "Confirm Flush",
            f"Submit {total} queued task(s) to the server?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        all_success = 0
        all_failed = 0
        for beacon_id in list(self._queue.keys()):
            s, f = self.flush_beacon(beacon_id)
            all_success += s
            all_failed += f

        msg = f"Flushed {all_success} task(s)"
        if all_failed:
            msg += f", {all_failed} failed (re-queued)"
        QMessageBox.information(self, "Flush Complete", msg)

    def _flush_selected(self):
        """Flush tasks for the selected beacon in the tree."""
        items = self.tree.selectedItems()
        if not items:
            QMessageBox.warning(self, "Warning", "No beacon/task selected")
            return

        beacons_to_flush = set()
        for item in items:
            # Could be a beacon group item or a task item
            bid = item.data(0, Qt.ItemDataRole.UserRole)
            if bid:
                beacons_to_flush.add(bid)

        if not beacons_to_flush:
            return

        for bid in beacons_to_flush:
            s, f = self.flush_beacon(bid)
            if s or f:
                QMessageBox.information(self, "Flush", f"Flushed {s}, failed {f} for {bid[:12]}")

    def _cancel_selected(self):
        """Cancel selected queued tasks."""
        items = self.tree.selectedItems()
        if not items:
            QMessageBox.warning(self, "Warning", "No task selected")
            return

        cancelled = 0
        for item in items:
            tid = item.data(0, Qt.ItemDataRole.UserRole)
            if tid and tid in self._task_id_map:
                if self.cancel_task(tid):
                    cancelled += 1

        if cancelled:
            QMessageBox.information(self, "Cancelled", f"Cancelled {cancelled} task(s)")

    def _refresh_view(self):
        """Rebuild the tree view from the current queue state."""
        filter_beacon = self.filter_combo.currentText()
        if filter_beacon == "All Beacons":
            filter_beacon = None

        # Update filter combo only when beacon set actually changes
        current_beacons = set(self._queue.keys())
        current_labels = {self.filter_combo.itemText(i) for i in range(self.filter_combo.count())}
        current_labels.discard("All Beacons")
        to_add = current_beacons - {c[:48] for c in current_labels}
        to_remove = {c for c in current_labels if c[:48] not in current_beacons}
        if to_add or to_remove:
            for label in sorted(to_remove):
                idx = self.filter_combo.findText(label)
                if idx >= 0:
                    self.filter_combo.removeItem(idx)
            for bid in sorted(to_add):
                self.filter_combo.addItem(bid)

        # Collect existing beacon group items
        existing_groups = {}
        for i in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(i)
            bid = item.data(0, Qt.ItemDataRole.UserRole)
            if bid:
                existing_groups[bid] = item

        # Determine visible beacon IDs
        visible_ids = set()
        for beacon_id, tasks in self._queue.items():
            if filter_beacon and beacon_id != filter_beacon:
                continue
            if tasks:
                visible_ids.add(beacon_id)

        # Remove stale beacon groups from tree
        for bid in list(existing_groups.keys()):
            if bid not in visible_ids:
                self.tree.invisibleRootItem().removeChild(existing_groups[bid])
                del existing_groups[bid]

        # Detach and re-attach remaining in sorted order
        for bid in list(existing_groups.keys()):
            if bid not in visible_ids:
                continue
            self.tree.invisibleRootItem().removeChild(existing_groups[bid])
        for bid in sorted(visible_ids):
            if bid in existing_groups:
                self.tree.addTopLevelItem(existing_groups[bid])

        self._task_id_map = {}
        total = 0

        for beacon_id in sorted(self._queue.keys()):
            if filter_beacon and beacon_id != filter_beacon:
                continue
            tasks = self._queue[beacon_id]
            if not tasks:
                continue

            # Get or create beacon group item
            group = existing_groups.get(beacon_id)
            if group is None:
                group = QTreeWidgetItem()
                group.setData(0, Qt.ItemDataRole.UserRole, beacon_id)
                group.setExpanded(True)
                self.tree.addTopLevelItem(group)
                existing_groups[beacon_id] = group

            group.setText(0, f"{beacon_id[:16]}...  ({len(tasks)} tasks)")

            # Build existing task lookup within this group
            existing_tasks = {}
            for i in range(group.childCount()):
                child = group.child(i)
                tid = child.data(0, Qt.ItemDataRole.UserRole)
                if tid:
                    existing_tasks[tid] = child

            current_task_ids = {t.id for t in tasks}

            # Remove stale task items
            for tid in list(existing_tasks.keys()):
                if tid not in current_task_ids:
                    group.removeChild(existing_tasks[tid])

            # Add/update task items
            for task in tasks:
                total += 1
                self._task_id_map[task.id] = task

                item = existing_tasks.get(task.id)
                if item is None:
                    item = QTreeWidgetItem(group)
                    item.setText(0, task.id)
                    item.setData(0, Qt.ItemDataRole.UserRole, task.id)

                item.setText(1, beacon_id[:16])
                opcode_name = self.OPCODE_NAMES.get(task.opcode, f"0x{task.opcode:02x}")
                status_prefix = ""
                if task.status == "failed":
                    status_prefix = "[FAILED] "
                elif task.status == "flushing":
                    status_prefix = "[FLUSHING] "
                item.setText(2, f"{status_prefix}{opcode_name}")
                item.setText(3, task.priority)
                desc = task.description[:60] if task.description else ""
                item.setText(4, desc)
                item.setText(5, task.queued_at.strftime("%H:%M:%S"))

                if task.status == "failed":
                    item.setForeground(2, QColor("#ff4444"))
                elif task.status == "flushing":
                    item.setForeground(2, QColor("#ffaa00"))
                else:
                    item.setForeground(2, QBrush())

        if total == 0:
            self.status_label.setText("No queued tasks")
        else:
            self.status_label.setText(f"{total} task(s) queued across {len(self._queue)} beacon(s)")
