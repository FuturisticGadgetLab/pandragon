"""
Audit Logger for Security Events

Dedicated audit logging for security-relevant events.
"""

import logging
import threading
import sys
from logging.handlers import RotatingFileHandler
from typing import Optional


class AuditLogger:
    """
    Audit logging for security events.

    Logs all security-relevant events to a separate audit log file.
    Thread-safe with rotating file handler.

    Attributes:
        enabled: Whether audit logging is active
        log_file: Path to audit log file
    """

    def __init__(self, audit_config: Optional[dict] = None):
        """
        Initialize audit logger.

        Args:
            audit_config: Dict from config's "audit" section
                         (e.g. {"enabled": True, "target": "audit.log"})
        """
        cfg = audit_config or {}
        self.enabled = cfg.get("enabled", True)
        self.log_file = cfg.get("target", "pandragon_audit.log")
        self._lock = threading.Lock()

        self._audit_logger = logging.getLogger('pandragon.audit')
        self._audit_logger.setLevel(logging.INFO)

        if not self.enabled:
            self._audit_logger.addHandler(logging.NullHandler())
            return

        if not self._audit_logger.handlers:
            try:
                handler = RotatingFileHandler(
                    self.log_file,
                    maxBytes=50 * 1024 * 1024,
                    backupCount=10,
                    encoding='utf-8'
                )
                handler.setFormatter(logging.Formatter(
                    fmt='%(asctime)s [AUDIT] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                ))
                self._audit_logger.addHandler(handler)
            except Exception as e:
                print(f"Warning: Could not create audit log handler: {e}", file=sys.stderr)

    def log_replay_detected(self, beacon_id: str, ip: str, reason: str) -> None:
        """
        Log replay attack detection.

        Args:
            beacon_id: Beacon identifier
            ip: Client IP address
            reason: Reason for rejection (sequence_number, nonce, timestamp)
        """
        self._audit_logger.warning(
            f"REPLAY_ATTACK beacon_id={beacon_id} ip={ip} reason={reason}"
        )

    def log_command(self, beacon_id: str, operator: str, command: str) -> None:
        """
        Log operator command.

        Args:
            beacon_id: Target beacon identifier
            operator: Operator username
            command: Command issued
        """
        self._audit_logger.info(
            f"COMMAND beacon_id={beacon_id} operator={operator} command={command}"
        )

    def log_file_operation(
        self,
        beacon_id: str,
        operation: str,
        path: str,
        success: bool
    ) -> None:
        """
        Log file operation (upload/download).

        Args:
            beacon_id: Beacon identifier
            operation: Operation type (upload, download)
            path: File path
            success: Whether operation succeeded
        """
        status = "SUCCESS" if success else "FAILED"
        self._audit_logger.info(
            f"FILE_OP beacon_id={beacon_id} op={operation} path={path} status={status}"
        )

    def log_operator_login(self, username: str, ip: str, success: bool) -> None:
        """
        Log operator login attempt.

        Args:
            username: Operator username
            ip: Client IP address
            success: Whether login was successful
        """
        status = "SUCCESS" if success else "FAILED"
        self._audit_logger.info(
            f"OPERATOR_LOGIN username={username} ip={ip} status={status}"
        )


