"""
Action Dialogs

Specialized input dialogs for beacon actions triggered from the
right-click context menu. Each dialog collects the parameters
needed to construct and submit a task via the REST API.
"""

import os
import base64
from pathlib import Path

from PyQt6.QtWidgets import (
    QDialog, QFormLayout, QLineEdit, QComboBox, QSpinBox, QHBoxLayout,
    QDialogButtonBox, QMessageBox, QLabel, QCheckBox, QPushButton,
    QFileDialog,
)
from PyQt6.QtGui import QFont

# Maximum allowed file sizes for validation (bytes)
MAX_BOF_SIZE = 1 * 1024 * 1024       # 1 MB
MAX_SHELLCODE_SIZE = 1 * 1024 * 1024  # 1 MB


class _BaseActionDialog(QDialog):
    """Base class for action dialogs with common helpers."""

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(400)
        self._layout = QFormLayout(self)
        self._build_buttons()

    def _build_buttons(self):
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self._layout.addRow("", buttons)


# ── BOF Exec ────────────────────────────────────────────────────

class BOFExecDialog(_BaseActionDialog):
    """Collects BOF file path and arguments."""

    def __init__(self, parent=None):
        super().__init__("BOF Exec", parent)

        # BOF file row with browse button
        bof_row = QHBoxLayout()
        self.bof_path_input = QLineEdit()
        self.bof_path_input.setPlaceholderText("/path/to/beacon.o")
        self.bof_browse_btn = QPushButton("Browse...")
        self.bof_browse_btn.clicked.connect(self._browse_bof)
        bof_row.addWidget(self.bof_path_input)
        bof_row.addWidget(self.bof_browse_btn)
        self._layout.addRow("Local BOF File:", bof_row)

        # Server BOFs combo (populated by set_server_bofs)
        self._server_bofs_combo = QComboBox()
        self._server_bofs_combo.addItem("(select from server)")
        self._server_bofs_combo.currentIndexChanged.connect(self._on_server_bof_selected)
        self._layout.addRow("Server BOF:", self._server_bofs_combo)

        self.args_input = QLineEdit()
        self.args_input.setPlaceholderText("arg1 arg2 ...")
        self._layout.addRow("Arguments:", self.args_input)

        # Conversion toolbar
        conv_row = QHBoxLayout()
        conv_row.setSpacing(4)
        b64_btn = QPushButton("Text \u2192 B64")
        b64_btn.clicked.connect(self._text_to_b64)
        conv_row.addWidget(b64_btn)
        hex_btn = QPushButton("Text \u2192 Hex")
        hex_btn.clicked.connect(self._text_to_hex)
        conv_row.addWidget(hex_btn)
        file_b64_btn = QPushButton("File \u2192 B64")
        file_b64_btn.clicked.connect(self._file_to_b64)
        conv_row.addWidget(file_b64_btn)
        conv_row.addStretch()
        self._layout.addRow("", conv_row)

    def set_server_bofs(self, filenames: list[str]):
        self._server_bofs_combo.blockSignals(True)
        self._server_bofs_combo.clear()
        self._server_bofs_combo.addItem("(select from server)")
        for fn in filenames:
            self._server_bofs_combo.addItem(fn)
        self._server_bofs_combo.blockSignals(False)

    def _on_server_bof_selected(self, index: int):
        if index <= 0:
            return
        self.bof_path_input.setText(self._server_bofs_combo.currentText())

    def _text_to_b64(self):
        text = self.args_input.text()
        if not text:
            return
        self.args_input.setText(base64.b64encode(text.encode()).decode())

    def _text_to_hex(self):
        text = self.args_input.text()
        if not text:
            return
        self.args_input.setText(text.encode().hex())

    def _file_to_b64(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select File", "", "All Files (*)"
        )
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            self.args_input.setText(base64.b64encode(data).decode())
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read file: {e}")

    def _browse_bof(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select BOF File", "", "BOF Files (*.o *.obj);;All Files (*)"
        )
        if path:
            self.bof_path_input.setText(path)

    def get_bof_path(self) -> str:
        return self.bof_path_input.text()

    def get_arguments(self) -> str:
        return self.args_input.text()

    def accept(self):
        """Validate BOF file exists and is within size limits before accepting."""
        bof_path = self.get_bof_path()
        if not bof_path:
            QMessageBox.warning(self, "Validation Error", "BOF file path is required.")
            return
        if not os.path.isfile(bof_path):
            QMessageBox.warning(self, "Validation Error", f"BOF file not found:\n{bof_path}")
            return
        file_size = os.path.getsize(bof_path)
        if file_size == 0:
            QMessageBox.warning(self, "Validation Error", "BOF file is empty.")
            return
        if file_size > MAX_BOF_SIZE:
            QMessageBox.warning(
                self, "Validation Error",
                f"BOF file too large ({file_size} bytes). Max allowed: {MAX_BOF_SIZE} bytes"
            )
            return
        super().accept()


# ── Inject Process ──────────────────────────────────────────────

class InjectProcessDialog(_BaseActionDialog):
    """Collects target PID and BOF file path for injection."""

    def __init__(self, parent=None):
        super().__init__("Inject Process", parent)
        self.pid_spin = QSpinBox()
        self.pid_spin.setRange(0, 999999)
        self.pid_spin.setValue(0)
        self._layout.addRow("Target PID:", self.pid_spin)

        # Payload file row with browse button
        bof_row = QHBoxLayout()
        self.bof_path_input = QLineEdit()
        self.bof_path_input.setPlaceholderText("/path/to/shellcode.bin")
        self.bof_browse_btn = QPushButton("Browse...")
        self.bof_browse_btn.clicked.connect(self._browse_payload)
        bof_row.addWidget(self.bof_path_input)
        bof_row.addWidget(self.bof_browse_btn)
        self._layout.addRow("BOF / Payload:", bof_row)

    def _browse_payload(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Payload File", "",
            "Payload Files (*.o *.obj *.bin *.raw);;All Files (*)"
        )
        if path:
            self.bof_path_input.setText(path)

    def get_pid(self) -> int:
        return self.pid_spin.value()

    def get_bof_path(self) -> str:
        return self.bof_path_input.text()

    def accept(self):
        """Validate payload file exists and is within size limits before accepting."""
        bof_path = self.get_bof_path()
        if not bof_path:
            QMessageBox.warning(self, "Validation Error", "Payload file path is required.")
            return
        if not os.path.isfile(bof_path):
            QMessageBox.warning(self, "Validation Error", f"Payload file not found:\n{bof_path}")
            return
        file_size = os.path.getsize(bof_path)
        if file_size == 0:
            QMessageBox.warning(self, "Validation Error", "Payload file is empty.")
            return
        if file_size > MAX_SHELLCODE_SIZE:
            QMessageBox.warning(
                self, "Validation Error",
                f"Payload file too large ({file_size} bytes). Max allowed: {MAX_SHELLCODE_SIZE} bytes"
            )
            return
        super().accept()


# ── File Download ───────────────────────────────────────────────

class FileDownloadDialog(_BaseActionDialog):
    """Collects remote path and optional local save path."""

    def __init__(self, parent=None):
        super().__init__("Download File", parent)
        self.remote_path_input = QLineEdit()
        self.remote_path_input.setPlaceholderText("C:\\Users\\target\\secret.txt")
        self._layout.addRow("Remote Path:", self.remote_path_input)

        self.local_path_input = QLineEdit()
        self.local_path_input.setPlaceholderText("C:\\Users\\target\\secret.txt (optional)")
        self._layout.addRow("Local Save Path (optional):", self.local_path_input)

    def get_remote_path(self) -> str:
        return self.remote_path_input.text()

    def get_local_path(self) -> str:
        return self.local_path_input.text()


# ── File Upload ─────────────────────────────────────────────────

class FileUploadDialog(_BaseActionDialog):
    """Collects local file path and remote destination."""

    def __init__(self, parent=None):
        super().__init__("Upload File", parent)

        # Local file row with browse button
        local_row = QHBoxLayout()
        self.local_path_input = QLineEdit()
        self.local_path_input.setPlaceholderText("C:\\Users\\target\\tool.exe")
        self.local_browse_btn = QPushButton("Browse...")
        self.local_browse_btn.clicked.connect(self._browse_local)
        local_row.addWidget(self.local_path_input)
        local_row.addWidget(self.local_browse_btn)
        self._layout.addRow("Local File:", local_row)

        self.remote_path_input = QLineEdit()
        self.remote_path_input.setPlaceholderText("C:\\Users\\Public\\tool.exe")
        self._layout.addRow("Remote Destination:", self.remote_path_input)

    def _browse_local(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Upload", "", "All Files (*)"
        )
        if path:
            self.local_path_input.setText(path)

    def get_local_path(self) -> str:
        return self.local_path_input.text()

    def get_remote_path(self) -> str:
        return self.remote_path_input.text()

    def accept(self):
        """Validate local file exists before accepting."""
        local_path = self.get_local_path()
        if not local_path:
            QMessageBox.warning(self, "Validation Error", "Local file path is required.")
            return
        if not os.path.isfile(local_path):
            QMessageBox.warning(self, "Validation Error", f"Local file not found:\n{local_path}")
            return
        file_size = os.path.getsize(local_path)
        if file_size == 0:
            QMessageBox.warning(self, "Validation Error", "Local file is empty.")
            return
        super().accept()


# ── List Files ──────────────────────────────────────────────────

class ListFilesDialog(_BaseActionDialog):
    """Collects remote directory path to list."""

    def __init__(self, parent=None):
        super().__init__("List Files", parent)
        self.dir_path_input = QLineEdit()
        self.dir_path_input.setPlaceholderText("C:\\")
        self._layout.addRow("Remote Directory:", self.dir_path_input)

    def get_directory_path(self) -> str:
        return self.dir_path_input.text()


# ── Sleep ───────────────────────────────────────────────────────

class SleepDialog(_BaseActionDialog):
    """Collects sleep interval in seconds."""

    def __init__(self, parent=None):
        super().__init__("Set Sleep Interval", parent)
        self.sleep_spin = QSpinBox()
        self.sleep_spin.setRange(1, 86400)
        self.sleep_spin.setValue(60)
        self.sleep_spin.setSuffix(" seconds")
        self._layout.addRow("Sleep Interval:", self.sleep_spin)

    def get_sleep_seconds(self) -> int:
        return self.sleep_spin.value()


# ── ETW Toggle ──────────────────────────────────────────────────

class ETWDialog(_BaseActionDialog):
    """Toggle ETW enable/disable selector."""

    def __init__(self, parent=None):
        super().__init__("ETW Toggle", parent)
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Enable", "Disable"])
        self._layout.addRow("Action:", self.action_combo)

    def get_action(self) -> str:
        """Return 'enable' or 'disable'."""
        return self.action_combo.currentText().lower()


# ── Exit Beacon ─────────────────────────────────────────────────

class ExitDialog(_BaseActionDialog):
    """Confirmation dialog for exiting a beacon."""

    def __init__(self, parent=None):
        super().__init__("Exit Beacon", parent)
        label = QLabel(
            "Are you sure you want to terminate this beacon?\n"
            "The beacon will stop checking in and all pending tasks will be lost."
        )
        label.setWordWrap(True)
        font = QFont()
        font.setBold(True)
        label.setFont(font)
        self._layout.addRow(label)

# ── Execute PE via Donut ────────────────────────────────────────

class ExecutePEDialog(_BaseActionDialog):
    """Upload a PE to the server; server converts to shellcode via Donut
    and queues a shellcode_loader BOF execution."""

    def __init__(self, parent=None):
        super().__init__("Execute PE / Assembly", parent)

        file_row = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("C:\\Tools\\mimikatz.exe")
        browse = QPushButton("Browse...")
        browse.clicked.connect(self._browse)
        file_row.addWidget(self.file_input)
        file_row.addWidget(browse)
        self._layout.addRow("PE File:", file_row)

        self.filename_input = QLineEdit()
        self.filename_input.setPlaceholderText("mimikatz.exe")
        self._layout.addRow("PE Filename:", self.filename_input)

        self.arch_combo = QComboBox()
        self.arch_combo.addItems(["x64", "x86", "Both"])
        self._layout.addRow("Architecture:", self.arch_combo)

        self.bypass_combo = QComboBox()
        self.bypass_combo.addItems(["AMSI+WLDP", "AMSI only", "WLDP only", "None"])
        self._layout.addRow("Bypass:", self.bypass_combo)

        self.args_input = QLineEdit()
        self.args_input.setPlaceholderText("sekurlsa::logonpasswords")
        self._layout.addRow("Arguments:", self.args_input)

        self.cls_input = QLineEdit()
        self.cls_input.setPlaceholderText("SharpHound.Program (optional for .NET)")
        self._layout.addRow(".NET Class:", self.cls_input)

        self.method_input = QLineEdit()
        self.method_input.setPlaceholderText("Main (optional for .NET)")
        self._layout.addRow(".NET Method:", self.method_input)

        self.runtime_input = QLineEdit()
        self.runtime_input.setPlaceholderText("v4.0.30319 (optional for .NET)")
        self._layout.addRow(".NET Runtime:", self.runtime_input)

        conv_row = QHBoxLayout()
        conv_row.setSpacing(4)
        file_b64_btn = QPushButton("PE \u2192 B64")
        file_b64_btn.clicked.connect(self._file_to_b64)
        conv_row.addWidget(file_b64_btn)
        conv_row.addStretch()
        self._layout.addRow("", conv_row)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select PE File", "",
            "PE Files (*.exe *.dll);;All Files (*)"
        )
        if path:
            self.file_input.setText(path)
            if not self.filename_input.text():
                self.filename_input.setText(Path(path).name)

    def _file_to_b64(self):
        path = self.file_input.text()
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            self.args_input.setText(base64.b64encode(data).decode())
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read file: {e}")

    def get_file_path(self) -> str:
        return self.file_input.text()

    def get_filename(self) -> str:
        return self.filename_input.text() or "unknown.exe"

    def get_arch_value(self) -> int:
        idx = self.arch_combo.currentIndex()
        return 3 if idx == 2 else idx + 1

    def get_bypass_value(self) -> int:
        idx = self.bypass_combo.currentIndex()
        return 3 if idx == 0 else (1 if idx == 1 else (2 if idx == 2 else 0))

    def get_args(self) -> str:
        return self.args_input.text()

    def get_cls(self) -> str:
        return self.cls_input.text()

    def get_method(self) -> str:
        return self.method_input.text()

    def get_runtime(self) -> str:
        return self.runtime_input.text()

    def accept(self):
        if not self.get_file_path():
            QMessageBox.warning(self, "Validation Error", "PE file path is required.")
            return
        if not os.path.isfile(self.get_file_path()):
            QMessageBox.warning(self, "Validation Error", f"File not found:\n{self.get_file_path()}")
            return
        super().accept()
