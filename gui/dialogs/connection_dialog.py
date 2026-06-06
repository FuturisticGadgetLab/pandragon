"""
Connection Dialog

Dialog for entering teamserver connection details (URL, token, username).
"""

from PyQt6.QtWidgets import (
    QDialog, QFormLayout, QLineEdit, QCheckBox, QDialogButtonBox,
)


class ConnectionDialog(QDialog):
    """Dialog for entering teamserver connection details"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Connect to Teamserver")
        self.setFixedSize(450, 260)

        layout = QFormLayout(self)

        self.url_input = QLineEdit("wss://127.0.0.1:6767/ws")
        layout.addRow("WebSocket URL:", self.url_input)

        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Operator token (required)")
        layout.addRow("Token:", self.token_input)

        self.username_input = QLineEdit("operator")
        layout.addRow("Username:", self.username_input)

        self.skip_verify = QCheckBox("Skip SSL certificate verification")
        self.skip_verify.setToolTip("Enable for self-signed HTTPS teamservers (wss://)")
        layout.addRow("", self.skip_verify)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow("", buttons)

    def get_url(self) -> str:
        return self.url_input.text()

    def get_token(self) -> str:
        return self.token_input.text()

    def get_username(self) -> str:
        return self.username_input.text()

    def get_verify_ssl(self) -> bool:
        return not self.skip_verify.isChecked()
