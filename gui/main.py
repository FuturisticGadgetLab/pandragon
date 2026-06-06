"""
Pandragon Operator Console: Main Window Assembly

Integrates an embedded connection panel (no separate dialogs), theme manager,
notification overlay, and all widget panels into the main application window.
"""

import sys

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QLineEdit, QCheckBox, QPushButton,
    QStackedWidget, QFrame, QMessageBox, QSizePolicy,
)
from PyQt6.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve, QParallelAnimationGroup,
)
from PyQt6.QtGui import QPalette, QColor, QFont

from gui.api_client import PandragonAPI
from gui.theme import ThemeManager
from gui.widgets.beacon_table import BeaconTableWidget
from gui.widgets.beacon_detail import BeaconDetailWidget
from gui.widgets.task_queue_widget import TaskQueueWidget
from gui.widgets.relay_widget import RelayWidget
from gui.widgets.beacon_graph_widget import BeaconGraphWidget
from gui.widgets.config_builder_widget import ConfigBuilderWidget
from gui.widgets.bof_repository_widget import BOFRepositoryWidget
from gui.widgets.options_widget import OptionsWidget
from gui.widgets.splash_screen import SplashScreen
from gui.widgets.startup_splash import StartSplash
from gui.widgets.notification_overlay import NotificationOverlay
from gui.state import load as load_state, save as save_state

_MONO = QFont("Consolas", 10)
_MONO.setStyleHint(QFont.StyleHint.Monospace)
_MONO_BOLD = QFont("Consolas", 10, QFont.Weight.Bold)
_MONO_BOLD.setStyleHint(QFont.StyleHint.Monospace)
_MONO_TITLE = QFont("Consolas", 18, QFont.Weight.Bold)
_MONO_TITLE.setStyleHint(QFont.StyleHint.Monospace)

_INPUT_STYLE = (
    "QLineEdit {"
    "  background-color: #252525;"
    "  border: 1px solid #444;"
    "  color: #e0e0e0;"
    "  padding: 6px 8px;"
    "}"
    "QLineEdit:focus { border: 1px solid #888; }"
)
_BTN_STYLE = (
    "QPushButton {"
    "  background-color: #2a2a2a;"
    "  border: 1px solid #555;"
    "  color: #e0e0e0;"
    "  padding: 6px 12px;"
    "}"
    "QPushButton:hover { border: 1px solid #888; }"
    "QPushButton:disabled { color: #555; border: 1px solid #333; }"
)
_CHECK_STYLE = (
    "QCheckBox { color: #aaa; spacing: 6px; }"
    "QCheckBox::indicator {"
    "  width: 14px; height: 14px;"
    "  background-color: #252525;"
    "  border: 1px solid #444;"
    "}"
    "QCheckBox::indicator:checked { background-color: #555; }"
)
_CONNECT_BTN_STYLE = (
    "QPushButton#connectBtn {"
    "  background-color: #1a3a1a;"
    "  border: 1px solid #2a5a2a;"
    "  color: #8f8;"
    "  padding: 6px 12px;"
    "}"
    "QPushButton#connectBtn:hover { border: 1px solid #4a8a4a; }"
    "QPushButton#connectBtn:disabled { color: #353; border: 1px solid #1a2a1a; }"
)
_CANCEL_BTN_STYLE = (
    "QPushButton#cancelBtn {"
    "  background-color: #2a1a1a;"
    "  border: 1px solid #4a2a2a;"
    "  color: #f88;"
    "  padding: 6px 12px;"
    "}"
    "QPushButton#cancelBtn:hover { border: 1px solid #8a4a4a; }"
)
_TOKEN_BTN_STYLE = (
    "QPushButton#tokenToggle {"
    "  background-color: #252525;"
    "  border: 1px solid #444;"
    "  border-left: none;"
    "  color: #888;"
    "  padding: 6px 8px;"
    "  min-width: 48px;"
    "}"
    "QPushButton#tokenToggle:hover { color: #ccc; border: 1px solid #888; border-left: none; }"
    "QPushButton#tokenToggle:checked { color: #e0e0e0; }"
)
_PROGRESS_STYLE = (
    "QWidget#SplashScreen { background: transparent; }"
)


class ConnectPanel(QWidget):
    """Embedded connection panel shown before the main tab interface."""

    def __init__(self, on_connected, parent=None):
        super().__init__(parent)
        self._on_connected = on_connected
        self._connecting_api = None
        saved = load_state()

        self.setStyleSheet("background-color: #1e1e1e;")

        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        form = QVBoxLayout()
        form.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        form.setSpacing(6)
        form.setContentsMargins(0, 0, 0, 0)

        form_w = 400

        title = QLabel("PANDRAGON")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(_MONO_TITLE)
        title.setStyleSheet("color: #e0e0e0; background: transparent; border: none;")
        title.setFixedWidth(form_w)
        form.addWidget(title, alignment=Qt.AlignmentFlag.AlignHCenter)

        subtitle = QLabel("serexp . FGL")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setFont(_MONO)
        subtitle.setStyleSheet("color: #666; background: transparent; border: none;")
        subtitle.setFixedWidth(form_w)
        form.addWidget(subtitle, alignment=Qt.AlignmentFlag.AlignHCenter)

        form.addSpacing(16)

        self._url = QLineEdit(saved.get("last_url", "wss://127.0.0.1:6767/ws"))
        self._url.setPlaceholderText("WebSocket URL")
        self._url.setFont(_MONO)
        self._url.setStyleSheet(_INPUT_STYLE)
        self._url.setFixedWidth(form_w)
        self._url.returnPressed.connect(self._do_connect)
        form.addWidget(self._url, alignment=Qt.AlignmentFlag.AlignHCenter)

        self._username = QLineEdit(saved.get("last_username", "operator"))
        self._username.setPlaceholderText("Username")
        self._username.setFont(_MONO)
        self._username.setStyleSheet(_INPUT_STYLE)
        self._username.setFixedWidth(form_w)
        self._username.returnPressed.connect(self._do_connect)
        form.addWidget(self._username, alignment=Qt.AlignmentFlag.AlignHCenter)

        token_row = QHBoxLayout()
        self._token = QLineEdit(saved.get("last_token", ""))
        self._token.setPlaceholderText("Token (required)")
        self._token.setFont(_MONO)
        self._token.setStyleSheet(_INPUT_STYLE + "QLineEdit { border-right: none; }")
        self._token.setFixedWidth(form_w - 48)
        self._token.returnPressed.connect(self._do_connect)
        token_row.addWidget(self._token)

        self._token_toggle = QPushButton("SHOW")
        self._token_toggle.setObjectName("tokenToggle")
        self._token_toggle.setFont(_MONO)
        self._token_toggle.setStyleSheet(_TOKEN_BTN_STYLE)
        self._token_toggle.setFixedSize(48, self._token.sizeHint().height() + 14)
        self._token_toggle.setCheckable(True)
        self._token_toggle.clicked.connect(self._toggle_token_visibility)
        token_row.addWidget(self._token_toggle)

        tw = QWidget()
        tw.setLayout(token_row)
        tw.setFixedWidth(form_w)
        form.addWidget(tw, alignment=Qt.AlignmentFlag.AlignHCenter)

        chk_row = QHBoxLayout()
        self._skip_verify = QCheckBox("Skip SSL verify")
        self._skip_verify.setFont(_MONO)
        self._skip_verify.setStyleSheet(_CHECK_STYLE)
        chk_row.addWidget(self._skip_verify)

        chk_row.addStretch()

        self._remember = QCheckBox("Remember")
        self._remember.setFont(_MONO)
        self._remember.setStyleSheet(_CHECK_STYLE)
        self._remember.setChecked(bool(saved.get("last_token", "")))
        chk_row.addWidget(self._remember)

        cw = QWidget()
        cw.setLayout(chk_row)
        cw.setFixedWidth(form_w)
        form.addWidget(cw, alignment=Qt.AlignmentFlag.AlignHCenter)

        form.addSpacing(4)

        btn_row = QHBoxLayout()
        self._connect_btn = QPushButton("Connect")
        self._connect_btn.setObjectName("connectBtn")
        self._connect_btn.setFont(_MONO_BOLD)
        self._connect_btn.setStyleSheet(_CONNECT_BTN_STYLE)
        self._connect_btn.setMinimumHeight(32)
        self._connect_btn.clicked.connect(self._do_connect)
        btn_row.addWidget(self._connect_btn)

        self._cancel_btn = QPushButton("Cancel")
        self._cancel_btn.setObjectName("cancelBtn")
        self._cancel_btn.setFont(_MONO)
        self._cancel_btn.setStyleSheet(_CANCEL_BTN_STYLE)
        self._cancel_btn.setMinimumHeight(32)
        self._cancel_btn.clicked.connect(self._cancel_connect)
        self._cancel_btn.setVisible(False)
        btn_row.addWidget(self._cancel_btn)

        bw = QWidget()
        bw.setLayout(btn_row)
        bw.setFixedWidth(form_w)
        form.addWidget(bw, alignment=Qt.AlignmentFlag.AlignHCenter)

        self._progress = SplashScreen()
        self._progress.setFixedWidth(form_w)
        self._progress.setStyleSheet("background: transparent;")
        form.addWidget(self._progress, alignment=Qt.AlignmentFlag.AlignHCenter)

        outer.addLayout(form)

    def animate_in(self):
        pass

    def _toggle_token_visibility(self):
        if self._token.echoMode() == QLineEdit.EchoMode.Password:
            self._token.setEchoMode(QLineEdit.EchoMode.Normal)
            self._token_toggle.setText("HIDE")
        else:
            self._token.setEchoMode(QLineEdit.EchoMode.Password)
            self._token_toggle.setText("SHOW")

    def _cancel_connect(self):
        if self._connecting_api:
            self._connecting_api.disconnect()
            self._connecting_api = None
        self._cancel_btn.setVisible(False)
        self._connect_btn.setText("Connect")
        self._connect_btn.setEnabled(True)
        self._progress.clear_stages()
        self._progress.add_stage("Connection cancelled", "info")

    def _do_connect(self):
        url = self._url.text().strip()
        token = self._token.text().strip()
        username = self._username.text().strip()
        verify_ssl = not self._skip_verify.isChecked()

        if not token:
            self._progress.clear_stages()
            self._progress.add_stage("Token is required", "fail")
            return

        self._progress.clear_stages()
        self._progress.add_stage("Connecting to teamserver...", "busy")
        self._progress.add_stage("Authenticating...", "busy")

        self._connect_btn.setText("Connecting...")
        self._connect_btn.setEnabled(False)
        self._cancel_btn.setVisible(True)

        QApplication.processEvents()

        api = PandragonAPI(url)
        self._connecting_api = api
        auth_error = [None]

        def _on_auth_error(err):
            auth_error[0] = err

        api.connection_error.connect(_on_auth_error)

        if not api.connect(token, username, ssl_verify=verify_ssl):
            msg = auth_error[0] or "Failed to authenticate"
            self._progress.clear_stages()
            self._progress.add_stage(msg, "fail")
            self._progress.add_stage("Check your connection details and try again", "info")
            self._connect_btn.setText("Connect")
            self._connect_btn.setEnabled(True)
            self._cancel_btn.setVisible(False)
            self._connecting_api = None
            return

        self._progress.update_stage(0, "ok", "Connected to teamserver")
        self._progress.update_stage(1, "ok", "Authenticated")
        self._progress.add_stage("Loading interface...", "ok")

        _updates = {"last_url": url, "last_username": username}
        if self._remember.isChecked():
            _updates["last_token"] = token
        else:
            _updates["last_token"] = ""
        save_state(_updates)

        self._connecting_api = None
        QTimer.singleShot(300, lambda: self._on_connected(api))


class MainWindow(QMainWindow):
    """Main application window with embedded connect panel and tabbed interface."""

    def __init__(self, theme_mgr: ThemeManager):
        super().__init__()
        self.theme_mgr = theme_mgr
        self.api: PandragonAPI = None
        self._splash_done = False
        self._tabs = None

        # Post-connect UI elements (created in _on_connected)
        self._status_bar_widgets = []
        self._status_indicator = None
        self._operator_label = None

        self.setWindowTitle("Pandragon Operator Console")

        self._stack = QStackedWidget()

        self._splash = StartSplash(self)
        self._splash.finished.connect(self._on_splash_done)
        self._stack.addWidget(self._splash)

        self._connect_panel = ConnectPanel(self._on_connected, self)
        self._stack.addWidget(self._connect_panel)

        self._tabs_container = QWidget()
        self._stack.addWidget(self._tabs_container)
        self._tab_layout = QVBoxLayout(self._tabs_container)
        self._tab_layout.setContentsMargins(0, 0, 0, 0)

        self._stack.setCurrentIndex(0)
        self.setCentralWidget(self._stack)

        self.resize(640, 420)

    # ── Disconnect / Reconnect ─────────────────────────────────────────

    def _disconnect(self):
        if self.api:
            self.api.disconnect()
            self.api = None

        for w in self._status_bar_widgets:
            try:
                self.statusBar().removeWidget(w)
                w.deleteLater()
            except Exception:
                pass
        self._status_bar_widgets.clear()
        self._status_indicator = None
        self._operator_label = None
        self.statusBar().clearMessage()

        while self._tab_layout.count():
            item = self._tab_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self._connect_panel = ConnectPanel(self._on_connected, self)
        self._stack.insertWidget(1, self._connect_panel)
        self._stack.setCurrentIndex(1)
        self.resize(480, 400)
        self.setWindowTitle("Pandragon Operator Console")

    # ── Splash / transitions ──────────────────────────────────────────

    def _on_splash_done(self):
        if self._splash_done:
            return
        self._splash_done = True
        self.resize(480, 400)
        self._crossfade(0, 1, callback=self._after_connect_fade)

    def _after_connect_fade(self):
        self._stack.removeWidget(self._splash)
        self._splash.deleteLater()
        self._connect_panel.animate_in()

    def _crossfade(self, old_idx, new_idx, duration=300, callback=None):
        old_widget = self._stack.widget(old_idx)
        new_widget = self._stack.widget(new_idx)

        if not old_widget or not new_widget:
            return

        new_widget.show()
        new_widget.setWindowOpacity(0.0)
        self._stack.setCurrentIndex(new_idx)

        self._fade_old = QPropertyAnimation(old_widget, b"windowOpacity")
        self._fade_old.setDuration(duration)
        self._fade_old.setStartValue(1.0)
        self._fade_old.setEndValue(0.0)
        self._fade_old.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._fade_new = QPropertyAnimation(new_widget, b"windowOpacity")
        self._fade_new.setDuration(duration)
        self._fade_new.setStartValue(0.0)
        self._fade_new.setEndValue(1.0)
        self._fade_new.setEasingCurve(QEasingCurve.Type.OutCubic)

        self._crossfade_group = QParallelAnimationGroup(self)
        self._crossfade_group.addAnimation(self._fade_old)
        self._crossfade_group.addAnimation(self._fade_new)

        if callback:
            self._crossfade_group.finished.connect(callback)

        self._crossfade_group.start()

    def _on_connected(self, api):
        self.api = api

        self._stack.removeWidget(self._connect_panel)
        self._connect_panel.deleteLater()

        tabs = QTabWidget()
        self._tabs = tabs

        from PyQt6.QtWidgets import QSplitter
        beacon_split = QSplitter(Qt.Orientation.Horizontal)

        self.beacon_table = BeaconTableWidget(api, self)
        self.beacon_detail = BeaconDetailWidget(api, self)

        beacon_split.addWidget(self.beacon_table)
        beacon_split.addWidget(self.beacon_detail)
        beacon_split.setStretchFactor(0, 2)
        beacon_split.setStretchFactor(1, 1)
        tabs.addTab(beacon_split, "Beacons")

        self.task_queue = TaskQueueWidget(api, self.beacon_table, self)
        self.beacon_table.task_queue = self.task_queue
        tabs.addTab(self.task_queue, "Task Queue")

        self.relay_widget = RelayWidget(api, self)
        tabs.addTab(self.relay_widget, "P2P Relay")

        self.graph_widget = BeaconGraphWidget(api, self)
        tabs.addTab(self.graph_widget, "Topology Graph")

        self.config_builder = ConfigBuilderWidget(self)
        self.config_builder.set_api(api)
        tabs.addTab(self.config_builder, "Config Builder")

        self.bof_repo = BOFRepositoryWidget(api, self)
        tabs.addTab(self.bof_repo, "BOF Repository")

        self.options_widget = OptionsWidget(self._disconnect, self.theme_mgr, self)
        tabs.addTab(self.options_widget, "Options")

        self._tab_layout.addWidget(tabs)

        self.notifications = NotificationOverlay(self)
        self.beacon_table.set_notification_overlay(self.notifications)
        self.beacon_detail.set_notification_overlay(self.notifications)
        self.task_queue.set_notification_overlay(self.notifications)
        self.relay_widget.set_notification_overlay(self.notifications)
        self.graph_widget.set_notification_overlay(self.notifications)
        self.bof_repo.set_notification_overlay(self.notifications)

        self._build_post_connect_ui()
        self._wire_events()

        self._crossfade(1, 2, duration=400, callback=self._after_tabs_fade)
        self.beacon_table.refresh()

    def _after_tabs_fade(self):
        QTimer.singleShot(0, lambda: self.resize(1280, 800))

    def _build_post_connect_ui(self):
        """Build status bar — only after connection. No menu bar."""
        sb = self.statusBar()

        # Left side: status + operator (addWidget = left-aligned)
        self._status_indicator = QLabel("[DISCONNECTED]")
        self._status_indicator.setFont(_MONO_BOLD)
        self._status_indicator.setStyleSheet("color: #ffaa00;")
        sb.addWidget(self._status_indicator)
        self._status_bar_widgets.append(self._status_indicator)

        self._operator_label = QLabel("")
        self._operator_label.setFont(_MONO)
        self._operator_label.setStyleSheet("color: #888;")
        sb.addWidget(self._operator_label)
        self._status_bar_widgets.append(self._operator_label)

        # Right side: quote + branding (permanent = right-aligned)
        sep1 = QLabel("  |  ")
        sep1.setStyleSheet("color: #444;")
        sb.addPermanentWidget(sep1)
        self._status_bar_widgets.append(sep1)

        quote = QLabel('\u201cThe bird of Hermes is my Name\u2026\u201d')
        quote.setFont(_MONO)
        quote.setStyleSheet("color: #555;")
        sb.addPermanentWidget(quote)
        self._status_bar_widgets.append(quote)

        sep2 = QLabel("  |  ")
        sep2.setStyleSheet("color: #444;")
        sb.addPermanentWidget(sep2)
        self._status_bar_widgets.append(sep2)

        brand = QLabel("PANDRAGON . serexp / FGL")
        brand.setFont(_MONO_BOLD)
        brand.setStyleSheet("color: #666;")
        sb.addPermanentWidget(brand)
        self._status_bar_widgets.append(brand)

        sep3 = QLabel("  |  ")
        sep3.setStyleSheet("color: #444;")
        sb.addPermanentWidget(sep3)
        self._status_bar_widgets.append(sep3)

        theme_lbl = QLabel("Theme:")
        theme_lbl.setFont(_MONO)
        theme_lbl.setStyleSheet("color: #666;")
        sb.addPermanentWidget(theme_lbl)
        self._status_bar_widgets.append(theme_lbl)

        theme_switcher = self.theme_mgr.make_switcher()
        sb.addPermanentWidget(theme_switcher)
        self._status_bar_widgets.append(theme_switcher)

    def _on_graph_node_selected(self, beacon_id):
        tabs = self._tabs
        if tabs:
            tabs.setCurrentIndex(0)
        self.beacon_table.select_beacon_by_id(beacon_id)
        self.beacon_detail.update_beacon(beacon_id)

    def _wire_events(self):
        self.relay_widget.relay_updated.connect(self.graph_widget.refresh)
        self.beacon_table.beacon_selected.connect(self.beacon_detail.update_beacon)
        self.graph_widget.node_selected.connect(self._on_graph_node_selected)

        self.api.beacon_output.connect(self.beacon_detail.handle_beacon_output)
        self.api.beacon_activity.connect(self._on_beacon_activity)
        self.api.beacon_removed.connect(self._on_beacon_removed)

        self.api.connected.connect(
            lambda: (
                self._set_connection_status(True),
                self.notifications.success("Connected to teamserver", 3000),
            )
        )
        self.api.disconnected.connect(
            lambda: (
                self._set_connection_status(False),
                self.notifications.warning("Disconnected from teamserver - reconnecting...", 0),
            )
        )
        self.api.connection_error.connect(
            lambda err: (
                self._set_connection_status(False, err),
                self.notifications.error(f"Connection error: {err}", 0),
            )
        )

        self.api.operator_joined.connect(self._on_operator_joined)
        self.api.operator_left.connect(self._on_operator_left)

    def _set_connection_status(self, connected, error=None):
        if connected:
            self._status_indicator.setText("[CONNECTED]")
            self._status_indicator.setStyleSheet("color: #8f8;")
            self.setWindowTitle("Pandragon Operator Console [CONNECTED]")
        elif error:
            self._status_indicator.setText("[ERROR]")
            self._status_indicator.setStyleSheet("color: #f44;")
            self.setWindowTitle("Pandragon Operator Console [ERROR]")
        else:
            self._status_indicator.setText("[DISCONNECTED]")
            self._status_indicator.setStyleSheet("color: #fa0;")
            self.setWindowTitle("Pandragon Operator Console [DISCONNECTED]")

    def _on_operator_joined(self, username):
        self._operator_label.setText(f"  {username} joined")
        self.notifications.info(f"Operator joined: {username}", 5000)
        QTimer.singleShot(5000, lambda: self._operator_label.setText(""))

    def _on_operator_left(self, username):
        self._operator_label.setText(f"  {username} left")
        self.notifications.info(f"Operator left: {username}", 5000)
        QTimer.singleShot(5000, lambda: self._operator_label.setText(""))

    def _on_beacon_activity(self, bid, data):
        self.beacon_table.refresh()
        self.beacon_detail.update_beacon(
            self.beacon_table.get_selected_beacon_id()
        )
        self.task_queue.handle_beacon_activity(bid)

    def _on_beacon_removed(self, bid):
        self.beacon_table.refresh()
        if self.beacon_detail.current_beacon_id == bid:
            self.beacon_detail.update_beacon(None)


# ── Application Entry ──────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(224, 224, 224))
    palette.setColor(QPalette.ColorRole.Base, QColor(37, 37, 37))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(40, 40, 40))
    palette.setColor(QPalette.ColorRole.Text, QColor(224, 224, 224))
    palette.setColor(QPalette.ColorRole.Button, QColor(42, 42, 42))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(224, 224, 224))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 68, 68))
    palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(0, 0, 0))
    app.setPalette(palette)

    theme = ThemeManager(app)

    window = MainWindow(theme)
    window.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
