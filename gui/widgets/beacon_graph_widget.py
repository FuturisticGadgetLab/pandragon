"""
Beacon Topology Graph Widget for Pandragon Operator Console

Provides visual graph representation of P2P beacon relay chains.
This is a LOCAL visualization tool - it does not affect actual beacon connections.
Operators can manually link beacons for visualization purposes only.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QGraphicsView, QGraphicsScene, QGraphicsItem, QGraphicsTextItem,
    QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsPolygonItem, QMenu,
    QDialog, QLineEdit, QFormLayout, QDialogButtonBox, QMessageBox,
    QSpinBox, QComboBox, QFrame, QGroupBox, QGridLayout,
    QGraphicsObject,
)
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal, QPointF, QLineF, QRectF
from PyQt6.QtGui import QFont, QColor, QPen, QBrush, QAction, QPainter, QTransform, QImage
from PyQt6.QtGui import QPolygonF

from gui.widgets.notification_overlay import NotificationOverlay

class BeaconGraphWidget(QWidget):
    """
    Visual graph widget for beacon topology visualization.
    This is purely for operator visualization - no network impact.
    """
    graph_updated = pyqtSignal()
    node_selected = pyqtSignal(str)

    def __init__(self, api, parent=None):
        super().__init__(parent)
        self.api = api
        self.nodes = {}
        self.edges = []
        self._node_items = {}
        self._edge_items = []
        self.selected_item = None
        self._notifications: Optional[NotificationOverlay] = None
        self._init_ui()
        self.refresh()

    def set_notification_overlay(self, overlay: NotificationOverlay):
        self._notifications = overlay

    def _init_ui(self):
        """Initialize the UI components."""
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        # Title
        title = QLabel("Beacon Topology")
        title.setFont(QFont("Consolas", 13, QFont.Weight.Bold))
        layout.addWidget(title)

        # Control buttons - brutalist minimal
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(6)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setFixedWidth(90)
        self.refresh_btn.clicked.connect(self.refresh)
        btn_layout.addWidget(self.refresh_btn)

        self.layout_btn = QPushButton("Layout")
        self.layout_btn.setFixedWidth(90)
        self.layout_btn.clicked.connect(self._auto_layout)
        btn_layout.addWidget(self.layout_btn)

        self.fit_btn = QPushButton("Fit")
        self.fit_btn.setFixedWidth(70)
        self.fit_btn.clicked.connect(self._fit_view)
        btn_layout.addWidget(self.fit_btn)

        self.export_btn = QPushButton("Export")
        self.export_btn.setFixedWidth(80)
        self.export_btn.clicked.connect(self._export_image)
        btn_layout.addWidget(self.export_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Graph view - clean brutalist container
        self.scene = QGraphicsScene(self)
        self.scene.setItemIndexMethod(QGraphicsScene.ItemIndexMethod.NoIndex)
        self.view = BeaconGraphicsView(self.scene, self)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setBackgroundBrush(QBrush(QColor(18, 18, 18)))
        self.view.setFrameStyle(QFrame.Shape.NoFrame)
        layout.addWidget(self.view)

        # Info panel - monospace, compact
        info_group = QGroupBox("Node")
        info_group.setFont(QFont("Consolas", 8))
        self.info_layout = QGridLayout()
        self.info_layout.setContentsMargins(6, 6, 6, 6)
        self.info_layout.setSpacing(4)

        self.info_beacon_id = QLabel("-")
        self.info_beacon_id.setFont(QFont("Consolas", 9))
        self.info_type = QLabel("-")
        self.info_type.setFont(QFont("Consolas", 9))
        self.info_ip = QLabel("-")
        self.info_ip.setFont(QFont("Consolas", 9))
        self.info_status = QLabel("-")
        self.info_status.setFont(QFont("Consolas", 9))

        for lbl, val in [("ID", self.info_beacon_id), ("Type", self.info_type),
                         ("IP", self.info_ip), ("Status", self.info_status)]:
            k = QLabel(lbl)
            k.setFont(QFont("Consolas", 8))
            self.info_layout.addWidget(k, self.info_layout.rowCount(), 0)
            self.info_layout.addWidget(val, self.info_layout.rowCount() - 1, 1)

        info_group.setLayout(self.info_layout)
        layout.addWidget(info_group)

        self.setLayout(layout)

    def refresh(self):
        """Refresh graph data from server."""
        try:
            data = self.api.get_relay_graph()
            if data:
                self.nodes = {n['id']: n for n in data.get('nodes', [])}
                self.edges = data.get('edges', [])
                self._update_scene()
        except Exception as e:
            print(f"Error refreshing graph: {e}")

    def _filter_nodes(self, text: str):
        """Filter nodes by beacon ID."""
        text = text.lower()
        for item in self.scene.items():
            if isinstance(item, NodeGraphicsItem):
                node_id = item.node_id.lower()
                visible = not text or text in node_id
                item.setVisible(visible)
            elif isinstance(item, EdgeGraphicsItem):
                item.setVisible(bool(not text or self._edge_has_visible_nodes(item)))

    def _edge_has_visible_nodes(self, edge_item) -> bool:
        """Check if edge connects two visible nodes."""
        from_id, to_id = edge_item.from_node, edge_item.to_node
        for item in self.scene.items():
            if isinstance(item, NodeGraphicsItem):
                if item.node_id == from_id or item.node_id == to_id:
                    if item.isVisible():
                        return True
        return False

    def _zoom_in(self):
        self.view.scale(1.25, 1.25)

    def _zoom_out(self):
        self.view.scale(0.8, 0.8)

    def _fit_view(self):
        self.view.fitInView(self.scene.itemsBoundingRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def _auto_layout(self):
        """Apply force-directed layout algorithm."""
        if not self.nodes:
            return
        # Simple hierarchical layout based on depth
        nodes_by_depth = {}
        for node_id, node_data in self.nodes.items():
            depth = node_data.get('depth', 0)
            if depth not in nodes_by_depth:
                nodes_by_depth[depth] = []
            nodes_by_depth[depth].append(node_id)

        # Position nodes by depth
        y_spacing = 150
        for depth, node_ids in sorted(nodes_by_depth.items()):
            x_spacing = max(200, 800 // max(len(node_ids), 1))
            for i, node_id in enumerate(node_ids):
                if node_id in self.nodes:
                    self.nodes[node_id]['x'] = 100 + i * x_spacing
                    self.nodes[node_id]['y'] = 100 + depth * y_spacing
        self._update_scene()

    def _export_image(self):
        """Export graph to PNG image."""
        from PyQt6.QtWidgets import QFileDialog
        from PyQt6.QtGui import QImage, QPainter
        from PyQt6.QtCore import QRectF

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Graph", "beacon_topology.png", "PNG Files (*.png)"
        )
        if not file_path:
            return

        rect = self.scene.itemsBoundingRect()
        if rect.isEmpty():
            rect = QRectF(0, 0, 800, 600)

        image = QImage(rect.size().toSize(), QImage.Format.Format_ARGB32)
        image.fill(Qt.GlobalColor.transparent)

        painter = QPainter(image)
        self.scene.render(painter)
        image.save(file_path)
        QMessageBox.information(self, "Export Complete", f"Graph saved to {file_path}")

    def _on_node_double_clicked(self, node_id: str, node_data: dict):
        """Handle double-click on node to open beacon detail."""
        self.node_selected.emit(node_id)

    def _update_scene(self):
        """Update the graphics scene with current data."""
        # Build current edge key set for comparison
        current_edge_keys = set()
        for edge in self.edges:
            from_id = edge.get('from')
            to_id = edge.get('to')
            if from_id in self.nodes and to_id in self.nodes:
                current_edge_keys.add((from_id, to_id))

        # Remove stale edges
        for edge_item in list(self._edge_items):
            key = (edge_item.from_node, edge_item.to_node)
            if key not in current_edge_keys:
                self.scene.removeItem(edge_item)
                self._edge_items.remove(edge_item)
                if edge_item in edge_item.from_item._connected_edges:
                    edge_item.from_item._connected_edges.remove(edge_item)
                if edge_item in edge_item.to_item._connected_edges:
                    edge_item.to_item._connected_edges.remove(edge_item)

        # Remove stale nodes
        for node_id in list(self._node_items.keys()):
            if node_id not in self.nodes:
                item = self._node_items.pop(node_id)
                self.scene.removeItem(item)

        # Add/update nodes
        for idx, (node_id, node_data) in enumerate(self.nodes.items()):
            if node_id in self._node_items:
                item = self._node_items[node_id]
                raw_x = node_data.get('x')
                raw_y = node_data.get('y')
                x = raw_x if raw_x is not None else (idx * 150 % 600)
                y = raw_y if raw_y is not None else (idx * 100 % 400)
                if item.pos() != QPointF(x, y):
                    item.setPos(x, y)
                item.node_data = node_data
                transport = node_data.get('transport', 'direct')
                is_alive = node_data.get('is_alive', True)
                if not is_alive:
                    item._brush = QBrush(QColor(150, 150, 150))
                elif transport == 'relay':
                    item._brush = QBrush(QColor(100, 200, 100))
                else:
                    item._brush = QBrush(QColor(200, 100, 100))
                display_id = node_id[:12] + "..." if len(node_id) > 12 else node_id
                item.label.setPlainText(display_id)
                item.update()
            else:
                raw_x = node_data.get('x')
                raw_y = node_data.get('y')
                x = raw_x if raw_x is not None else (idx * 150 % 600)
                y = raw_y if raw_y is not None else (idx * 100 % 400)
                item = NodeGraphicsItem(node_id, node_data, x, y, self)
                item.setPos(x, y)
                item.node_double_clicked.connect(self._on_node_double_clicked)
                self.scene.addItem(item)
                self._node_items[node_id] = item

        # Add new edges
        existing_edge_keys = {(e.from_node, e.to_node) for e in self._edge_items}
        for edge in self.edges:
            from_id = edge.get('from')
            to_id = edge.get('to')
            key = (from_id, to_id)
            if from_id in self._node_items and to_id in self._node_items and key not in existing_edge_keys:
                from_item = self._node_items[from_id]
                to_item = self._node_items[to_id]
                edge_item = EdgeGraphicsItem(from_item, to_item, edge, self)
                self.scene.addItem(edge_item)
                self._edge_items.append(edge_item)
                from_item._connected_edges.append(edge_item)
                to_item._connected_edges.append(edge_item)

        self.view.fitInView(
            self.scene.itemsBoundingRect(),
            Qt.AspectRatioMode.KeepAspectRatio
        )

    def add_node(self):
        """Add a new node manually."""
        dialog = AddNodeDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            node_id = dialog.get_beacon_id()
            node_type = dialog.get_type()
            ip = dialog.get_ip()
            os_info = dialog.get_os()
            self.nodes[node_id] = {
                'id': node_id,
                'transport': node_type,
                'is_alive': True,
                'last_seen': 0,
                'metadata': {'ip': ip, 'os': os_info}
            }
            self._update_scene()
            self.graph_updated.emit()

    def add_edge(self):
        """Add a new edge manually."""
        dialog = AddEdgeDialog(list(self.nodes.keys()), self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            from_id = dialog.get_from_id()
            to_id = dialog.get_to_id()
            pipe_id = dialog.get_pipe_id()
            if from_id and to_id:
                self.edges.append({
                    'from': from_id,
                    'to': to_id,
                    'pipe_id': pipe_id
                })
                self._update_scene()
                self.graph_updated.emit()

    def remove_selected(self):
        """Remove selected node or edge."""
        if self.selected_item:
            if isinstance(self.selected_item, NodeGraphicsItem):
                node_id = self.selected_item.node_id
                if node_id in self.nodes:
                    del self.nodes[node_id]
                    self.edges = [
                        e for e in self.edges
                        if e.get('from') != node_id and e.get('to') != node_id
                    ]
            elif isinstance(self.selected_item, EdgeGraphicsItem):
                edge_data = self.selected_item.edge_data
                if edge_data in self.edges:
                    self.edges.remove(edge_data)
            self._update_scene()
            self.graph_updated.emit()

    def clear_all(self):
        """Clear all nodes and edges."""
        reply = QMessageBox.question(
            self, "Confirm Clear", "Clear all nodes and links?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.nodes = {}
            self.edges = []
            self._update_scene()
            self.graph_updated.emit()

    def save_layout(self):
        """Save current layout."""
        for item in self.scene.items():
            if isinstance(item, NodeGraphicsItem):
                node_id = item.node_id
                pos = item.pos()
                self.nodes[node_id]['x'] = pos.x()
                self.nodes[node_id]['y'] = pos.y()
        QMessageBox.information(self, "Layout Saved", "Layout saved locally.")
        self.graph_updated.emit()

    def set_node_info(self, node_id, node_data):
        """Update node information display."""
        display_id = node_id[:16] if len(node_id) > 16 else node_id
        self.info_beacon_id.setText(display_id)
        self.info_type.setText(node_data.get('transport', 'unknown'))
        metadata = node_data.get('metadata', {}) or {}
        self.info_ip.setText(metadata.get('ip', node_data.get('internal_ips', '-') if isinstance(node_data.get('internal_ips'), str) else '-'))
        status = "Alive" if node_data.get('is_alive', True) else "Offline"
        self.info_status.setText(status)


class EnableRelayDialog(QDialog):
    """Dialog for enabling relay on a beacon."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enable P2P Relay")
        self.setMinimumWidth(350)

        layout = QFormLayout()
        layout.setSpacing(8)

        self.pipe_prefix_edit = QLineEdit("msagent")
        self.pipe_prefix_edit.setPlaceholderText("msagent")
        layout.addRow("Pipe Prefix:", self.pipe_prefix_edit)

        info = QLabel("Pipe will be: {prefix}_{random_hex}")
        info.setFont(QFont("Consolas", 8))
        info.setStyleSheet("color: #888;")
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

    def __init__(self, node_ids, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Child to Relay")
        self.setMinimumWidth(350)

        layout = QFormLayout()
        layout.setSpacing(8)

        self.child_combo = QComboBox()
        self.child_combo.addItems(["- select -"] + node_ids)
        layout.addRow("Child Beacon:", self.child_combo)

        self.pipe_name_edit = QLineEdit()
        self.pipe_name_edit.setPlaceholderText("auto")
        layout.addRow("Pipe Name:", self.pipe_name_edit)

        info = QLabel("Child connects to this node via named pipe")
        info.setFont(QFont("Consolas", 8))
        info.setStyleSheet("color: #888;")
        layout.addRow(info)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

        self.setLayout(layout)

    def get_child_id(self) -> str:
        text = self.child_combo.currentText()
        return "" if text == "- select -" else text

    def get_pipe_name(self) -> str:
        return self.pipe_name_edit.text().strip()


class BeaconGraphicsView(QGraphicsView):
    """Custom graphics view for beacon graph with zoom and pan."""

    def __init__(self, scene, parent=None):
        super().__init__(scene, parent)
        self.parent_widget = parent
        self._panning = False
        self._pan_start = QPointF()

    def wheelEvent(self, a0):
        factor = 1.15
        if a0.angleDelta().y() > 0:
            self.scale(factor, factor)
        else:
            self.scale(1 / factor, 1 / factor)

    def mousePressEvent(self, a0):
        if a0.button() == Qt.MouseButton.MiddleButton:
            self._panning = True
            self._pan_start = a0.pos()
            self.setCursor(Qt.CursorShape.ClosedHandCursor)
            a0.accept()
            return
        item = self.scene().itemAt(self.mapToScene(a0.pos()), self.transform())
        if item:
            if isinstance(item, (NodeGraphicsItem, EdgeGraphicsItem)):
                self.parent_widget.selected_item = item
                item.setSelected(True)
                if isinstance(item, NodeGraphicsItem):
                    self.parent_widget.set_node_info(item.node_id, item.node_data)
            else:
                self.parent_widget.selected_item = None
        super().mousePressEvent(a0)

    def mouseMoveEvent(self, a0):
        if self._panning:
            delta = self._pan_start - a0.pos()
            self._pan_start = a0.pos()
            self.horizontalScrollBar().setValue(
                self.horizontalScrollBar().value() + int(delta.x())
            )
            self.verticalScrollBar().setValue(
                self.verticalScrollBar().value() + int(delta.y())
            )
            a0.accept()
            return
        super().mouseMoveEvent(a0)

    def mouseReleaseEvent(self, a0):
        if a0.button() == Qt.MouseButton.MiddleButton:
            self._panning = False
            self.setCursor(Qt.CursorShape.ArrowCursor)
            a0.accept()
            return
        super().mouseReleaseEvent(a0)


class NodeGraphicsItem(QGraphicsObject):
    """Graphics item representing a beacon node."""
    node_double_clicked = pyqtSignal(str, dict)

    def __init__(self, node_id, node_data, x, y, parent=None):
        super().__init__()
        self.node_id = node_id
        self.node_data = node_data
        self.parent_widget = parent
        self._connected_edges = []
        self.setPos(x, y)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)

        transport = node_data.get('transport', 'direct')
        is_alive = node_data.get('is_alive', True)

        if not is_alive:
            self._brush = QBrush(QColor(150, 150, 150))
        elif transport == 'relay':
            self._brush = QBrush(QColor(100, 200, 100))
        else:
            self._brush = QBrush(QColor(200, 100, 100))

        self._pen = QPen(Qt.GlobalColor.black, 2)

        display_id = node_id[:12] + "..." if len(node_id) > 12 else node_id
        self.label = QGraphicsTextItem(display_id)
        font = QFont("Consolas", 8)
        self.label.setFont(font)
        self.label.setDefaultTextColor(QColor(50, 50, 50))
        self.label.setPos(-30, -45)
        self.label.setParentItem(self)
        self.label.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIgnoresTransformations)

    def boundingRect(self):
        return QRectF(-30, -30, 60, 60)

    def paint(self, painter, option, widget=None):
        painter.setBrush(self._brush)
        painter.setPen(self._pen)
        painter.drawEllipse(self.boundingRect())

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self._connected_edges:
                edge.update_position()
        return super().itemChange(change, value)

    def mouseDoubleClickEvent(self, a0):
        self.node_double_clicked.emit(self.node_id, self.node_data)
        super().mouseDoubleClickEvent(a0)

    def contextMenuEvent(self, a0):
        menu = QMenu()
        menu.setFont(QFont("Consolas", 9))

        edit_action = menu.addAction("Edit")
        edit_action.triggered.connect(lambda: self.edit_node())

        menu.addSeparator()

        # Relay management actions
        transport = self.node_data.get('transport', 'direct')
        is_alive = self.node_data.get('is_alive', True)

        enable_action = menu.addAction("Enable Relay")
        enable_action.setEnabled(transport == 'direct' and is_alive)
        enable_action.triggered.connect(lambda: self.enable_relay())

        disable_action = menu.addAction("Disable Relay")
        disable_action.setEnabled(transport == 'relay')
        disable_action.triggered.connect(lambda: self.disable_relay())

        add_child_action = menu.addAction("Add Child")
        add_child_action.setEnabled(transport == 'relay')
        add_child_action.triggered.connect(lambda: self.add_child())

        remove_child_action = menu.addAction("Remove from Parent")
        remove_child_action.setEnabled(transport == 'relay')
        remove_child_action.triggered.connect(lambda: self.remove_child())

        menu.exec(self.parent_widget.view.viewport().mapToGlobal(a0.pos().toPoint()))

    def enable_relay(self):
        dialog = EnableRelayDialog(self.parent_widget)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            pipe_prefix = dialog.get_pipe_prefix()
            try:
                self.parent_widget.api.relay_enable(self.node_id, pipe_prefix)
                # Refresh from server to reflect actual state
                self.parent_widget.refresh()
            except Exception as e:
                QMessageBox.critical(self.parent_widget, "Error", f"Failed to enable relay: {e}")

    def disable_relay(self):
        reply = QMessageBox.question(
            self.parent_widget, "Disable Relay",
            f"Disable relay on beacon {self.node_id[:8]}?\nThis will drain all children.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.parent_widget.api.relay_disable(self.node_id)
                self.parent_widget.refresh()
            except Exception as e:
                QMessageBox.critical(self.parent_widget, "Error", f"Failed to disable relay: {e}")

    def add_child(self):
        dialog = AddChildDialog(list(self.parent_widget.nodes.keys()), self.parent_widget)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            child_id = dialog.get_child_id()
            pipe_name = dialog.get_pipe_name()
            if not child_id:
                QMessageBox.warning(self.parent_widget, "Invalid", "Child ID required")
                return
            try:
                self.parent_widget.api.relay_add_child(self.node_id, child_id, pipe_name)
                self.parent_widget.refresh()
            except Exception as e:
                QMessageBox.critical(self.parent_widget, "Error", f"Failed to add child: {e}")

    def remove_child(self):
        # Find parent via edge data
        parent_id = None
        for e in self.parent_widget.edges:
            if e.get('to') == self.node_id:
                parent_id = e.get('from')
                break
        if not parent_id:
            QMessageBox.warning(self.parent_widget, "No Parent", "No parent beacon found")
            return
        reply = QMessageBox.question(
            self.parent_widget, "Remove Child",
            f"Remove this beacon from parent {parent_id[:8]}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.parent_widget.api.relay_remove_child(parent_id, self.node_id)
                self.parent_widget.refresh()
            except Exception as e:
                QMessageBox.critical(self.parent_widget, "Error", f"Failed to remove child: {e}")

    def edit_node(self):
        """Edit node properties."""
        dialog = EditNodeDialog(
            self.node_id, self.node_data, self.parent_widget
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.node_data['metadata']['ip'] = dialog.get_ip()
            self.node_data['metadata']['os'] = dialog.get_os()
            self.parent_widget.set_node_info(self.node_id, self.node_data)


class EdgeGraphicsItem(QGraphicsLineItem):
    """Graphics item representing an edge between nodes."""
    def __init__(self, from_item, to_item, edge_data, parent=None):
        super().__init__()
        self.from_node = from_item.node_id if hasattr(from_item, 'node_id') else ''
        self.to_node = to_item.node_id if hasattr(to_item, 'node_id') else ''
        self.from_item = from_item
        self.to_item = to_item
        self.edge_data = edge_data
        self.parent_widget = parent
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setPen(QPen(Qt.GlobalColor.darkBlue, 2))
        self.arrow = None
        self.label = None
        self.update_position()
        self._create_arrow()
        self._create_label()

    def _create_arrow(self):
        """Create direction arrow at the end of the line."""
        self.arrow = QGraphicsPolygonItem()
        self.arrow.setParentItem(self)
        self._update_arrow()

    def _create_label(self):
        """Create label showing edge metadata."""
        latency = self.edge_data.get('latency_ms', 0)
        if latency:
            self.label = QGraphicsTextItem(f"{latency}ms")
            font = QFont("Arial", 7)
            self.label.setFont(font)
            self.label.setDefaultTextColor(QColor(100, 100, 100))
            self.label.setParentItem(self)

    def _update_arrow(self):
        """Update arrow position and rotation."""
        line = self.line()
        if line.length() < 1:
            return

        # Arrow at the end of the line
        angle = line.angle()
        arrow_size = 10

        # Calculate arrow polygon
        import math
        rad = math.radians(angle)
        x1 = line.x2() - arrow_size * math.cos(rad - math.pi / 6)
        y1 = line.y2() - arrow_size * math.sin(rad - math.pi / 6)
        x2 = line.x2() - arrow_size * math.cos(rad + math.pi / 6)
        y2 = line.y2() - arrow_size * math.sin(rad + math.pi / 6)

        polygon = QPolygonF([
            QPointF(line.x2(), line.y2()),
            QPointF(x1, y1),
            QPointF(x2, y2)
        ])
        self.arrow.setPolygon(polygon)
        self.arrow.setBrush(QBrush(QColor(100, 100, 200)))
        self.arrow.setPen(QPen(Qt.GlobalColor.darkBlue, 1))

    def update_position(self):
        """Update edge position based on connected nodes."""
        line = QLineF(self.from_item.pos() + self.from_item.boundingRect().center(),
                      self.to_item.pos() + self.to_item.boundingRect().center())
        self.setLine(line)
        self._update_arrow()

        # Update label position
        if self.label:
            mid = line.pointAt(0.5)
            self.label.setPos(mid.x() - 15, mid.y() + 5)


class AddNodeDialog(QDialog):
    """Dialog for adding a new node."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Beacon Node")
        self.setMinimumWidth(400)
        layout = QFormLayout()

        self.beacon_id_edit = QLineEdit()
        self.beacon_id_edit.setPlaceholderText("e.g., abcdef1234567890")
        layout.addRow("Beacon ID:", self.beacon_id_edit)

        self.type_combo = QComboBox()
        self.type_combo.addItems(["direct", "relay"])
        layout.addRow("Type:", self.type_combo)

        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("192.168.1.100")
        layout.addRow("IP Address:", self.ip_edit)

        self.os_edit = QLineEdit()
        self.os_edit.setPlaceholderText("Windows 10 Pro")
        layout.addRow("OS:", self.os_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
        self.setLayout(layout)

    def get_beacon_id(self):
        return self.beacon_id_edit.text().strip()

    def get_type(self):
        return self.type_combo.currentText()

    def get_ip(self):
        return self.ip_edit.text().strip()

    def get_os(self):
        return self.os_edit.text().strip()


class AddEdgeDialog(QDialog):
    """Dialog for adding a new edge."""
    def __init__(self, nodes, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Link")
        self.setMinimumWidth(400)
        layout = QFormLayout()

        self.from_combo = QComboBox()
        self.from_combo.addItems(nodes)
        layout.addRow("From Node:", self.from_combo)

        self.to_combo = QComboBox()
        self.to_combo.addItems(nodes)
        layout.addRow("To Node:", self.to_combo)

        self.pipe_id_edit = QLineEdit()
        self.pipe_id_edit.setPlaceholderText("1")
        layout.addRow("Pipe ID:", self.pipe_id_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
        self.setLayout(layout)

    def get_from_id(self):
        return self.from_combo.currentText()

    def get_to_id(self):
        return self.to_combo.currentText()

    def get_pipe_id(self):
        return self.pipe_id_edit.text().strip()


class EditNodeDialog(QDialog):
    """Dialog for editing node properties."""
    def __init__(self, node_id, node_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Edit Node: {node_id[:8]}")
        self.setMinimumWidth(400)
        layout = QFormLayout()

        metadata = node_data.get('metadata', {})
        self.ip_edit = QLineEdit(metadata.get('ip', ''))
        layout.addRow("IP Address:", self.ip_edit)

        self.os_edit = QLineEdit(metadata.get('os', ''))
        layout.addRow("OS:", self.os_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok |
            QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
        self.setLayout(layout)

    def get_ip(self):
        return self.ip_edit.text().strip()

    def get_os(self):
        return self.os_edit.text().strip()