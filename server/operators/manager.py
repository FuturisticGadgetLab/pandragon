"""
Operator Session Management

Manages operator authentication, sessions, and credentials.
"""

import os
import json
import time
import uuid
import secrets
import threading
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List

# Use absolute import within server package
from core.config import get_session_timeout


logger = logging.getLogger('pandragon.operators')


@dataclass
class OperatorSession:
    """
    Represents a connected operator.

    Attributes:
        operator_id: Unique operator identifier
        username: Operator username
        token: Authentication token
        connected_at: When session started
        last_activity: Last activity timestamp
        commands_issued: Number of commands issued
        is_authenticated: Whether operator is authenticated
    """
    operator_id: str
    username: str
    token: str
    connected_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    commands_issued: int = 0
    sid: Optional[str] = None  # SocketIO session ID
    is_authenticated: bool = False

    def touch(self) -> None:
        """Update last activity timestamp"""
        self.last_activity = time.time()

    def is_session_expired(self, timeout_seconds: int) -> bool:
        """
        Check if session has expired.

        Args:
            timeout_seconds: Session timeout in seconds

        Returns:
            True if session expired
        """
        if not self.is_authenticated:
            return False
        return (time.time() - self.last_activity) > timeout_seconds


class OperatorManager:
    """
    Manages operator sessions and authentication.

    Handles operator creation, authentication, credential persistence,
    and session timeout management.

    Attributes:
        operators: Dictionary of operator sessions by ID
        tokens: Map of tokens to operator IDs

    Example:
        manager = OperatorManager()
        op = manager.create_operator("admin")
        manager.save_credentials()
    """

    def __init__(self, cred_file: str = "operators.json"):
        """
        Initialize operator manager.

        Args:
            cred_file: Path to credentials file
        """
        self.cred_file = cred_file
        self.operators: Dict[str, OperatorSession] = {}  # by operator_id
        self.tokens: Dict[str, str] = {}  # token -> operator_id
        self.usernames: Dict[str, str] = {}  # username -> operator_id
        self._lock = threading.Lock()

        # Load operator credentials from file
        self._load_credentials()

    def _load_credentials(self) -> None:
        """Load operator credentials from file"""
        if not os.path.exists(self.cred_file):
            logger.info(f"No credentials file: {self.cred_file}")
            return

        try:
            with open(self.cred_file, 'r') as f:
                data = json.load(f)
                for username, token in data.get("operators", {}).items():
                    self.create_operator(username, token)
            logger.info(f"Loaded {len(self.usernames)} operator(s) from {self.cred_file}")
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")

    def save_credentials(self) -> None:
        """Save operator credentials to file"""
        with self._lock:
            try:
                data = {
                    "operators": {op.username: op.token for op in self.operators.values()}
                }
                with open(self.cred_file, 'w') as f:
                    json.dump(data, f, indent=2)
                logger.info(f"Saved {len(self.operators)} operator(s) to {self.cred_file}")
            except Exception as e:
                logger.error(f"Failed to save credentials: {e}")

    def create_operator(
        self,
        username: str,
        token: Optional[str] = None
    ) -> OperatorSession:
        """
        Create a new operator with secure token generation.

        Args:
            username: Operator username
            token: Optional custom token (auto-generated if None)

        Returns:
            New OperatorSession

        Raises:
            ValueError: If username already exists
        """
        with self._lock:
            if username in self.usernames:
                raise ValueError(f"Operator '{username}' already exists")

            operator_id = str(uuid.uuid4())[:8]
            if token is None:
                # Generate 256-bit token (64 hex characters)
                token = secrets.token_hex(32)

            op = OperatorSession(
                operator_id=operator_id,
                username=username,
                token=token
            )
            self.operators[operator_id] = op
            self.tokens[token] = operator_id
            self.usernames[username] = operator_id

            logger.info(f"Created operator: {username} ({operator_id})")

        self.save_credentials()
        return op

    def authenticate(self, token: str) -> Optional[OperatorSession]:
        """
        Authenticate operator by token.

        Args:
            token: Operator authentication token

        Returns:
            OperatorSession if authenticated, None otherwise
        """
        with self._lock:
            operator_id = self.tokens.get(token)
            if operator_id:
                op = self.operators[operator_id]
                op.is_authenticated = True
                op.touch()
                logger.info(f"Operator authenticated: {op.username}")
                return op
            return None

    def get_by_sid(self, sid: str) -> Optional[OperatorSession]:
        """
        Get operator by SocketIO session ID.

        Args:
            sid: SocketIO session ID

        Returns:
            OperatorSession or None
        """
        with self._lock:
            for op in self.operators.values():
                if op.sid == sid:
                    return op
            return None

    def cleanup_expired_sessions(self) -> List[str]:
        """
        Check all operator sessions and disconnect expired ones.

        Returns:
            List of disconnected operator IDs
        """
        disconnected = []
        timeout_seconds = get_session_timeout() * 60

        with self._lock:
            for op_id, op in list(self.operators.items()):
                if op.is_authenticated and op.is_session_expired(timeout_seconds):
                    logger.info(f"Session timeout: disconnecting {op.username}")
                    op.is_authenticated = False
                    disconnected.append(op_id)

        return disconnected

    def attach_session(self, operator_id: str, sid: str) -> None:
        """
        Attach SocketIO session ID to operator.

        Args:
            operator_id: Operator ID
            sid: SocketIO session ID
        """
        with self._lock:
            if operator_id in self.operators:
                self.operators[operator_id].sid = sid
                self.operators[operator_id].touch()

    def detach_session(self, sid: str) -> None:
        """
        Detach SocketIO session ID.

        Args:
            sid: SocketIO session ID
        """
        with self._lock:
            for op in self.operators.values():
                if op.sid == sid:
                    op.sid = None
                    op.touch()
                    break

    def list_operators(self) -> List[OperatorSession]:
        """
        List all operators.

        Returns:
            List of OperatorSession objects
        """
        return list(self.operators.values())

    def get_operator(self, username: str) -> Optional[OperatorSession]:
        """
        Get operator by username.

        Args:
            username: Operator username

        Returns:
            OperatorSession or None
        """
        operator_id = self.usernames.get(username)
        if operator_id:
            return self.operators.get(operator_id)
        return None

    def remove_operator(self, username: str) -> bool:
        """
        Remove an operator.

        Args:
            username: Operator username

        Returns:
            True if removed, False if not found
        """
        with self._lock:
            if username in self.usernames:
                operator_id = self.usernames.pop(username)
                op = self.operators.pop(operator_id, None)
                if op:
                    self.tokens.pop(op.token, None)
                logger.info(f"Removed operator: {username}")
                return True
            return False

    def get_stats(self) -> Dict:
        """
        Get operator statistics.

        Returns:
            Dictionary with operator stats
        """
        now = time.time()
        return {
            'total_operators': len(self.operators),
            'authenticated': sum(1 for op in self.operators.values() if op.is_authenticated),
            'connected': sum(1 for op in self.operators.values() if op.sid is not None),
        }
