"""
Session Persistence Manager

JSON-based session storage for beacons and operators.
"""

import os
import json
import time
import hashlib
import threading
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any

# Use absolute import within server package
from core.config import get_logger


logger = get_logger()

# Default session file location
SESSION_FILE = os.path.join(os.path.dirname(__file__), '..', 'sessions.json')
AUTO_SAVE_INTERVAL = 30  # Seconds between auto-saves


@dataclass
class CommandEntry:
    """Represents a single command in history"""
    timestamp: float
    operator_id: str
    operator_name: str
    command: str
    payload_size: int
    status: str = "pending"
    result: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> 'CommandEntry':
        return cls(**data)


@dataclass
class BeaconSessionData:
    """Persistent beacon session data"""
    beacon_id: str
    first_seen: float
    last_seen: float
    last_ip: str = ""
    user_agent: str = ""
    crypto_key_hash: str = ""
    total_checkins: int = 0
    command_history: List[dict] = field(default_factory=list)
    output_log: List[dict] = field(default_factory=list)
    malleable_config: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = asdict(self)
        data['command_history'] = [
            c.to_dict() if isinstance(c, CommandEntry) else c
            for c in self.command_history
        ]
        return data

    @classmethod
    def from_dict(cls, data: dict) -> 'BeaconSessionData':
        cmd_history = []
        for cmd in data.get('command_history', []):
            if isinstance(cmd, dict):
                cmd_history.append(CommandEntry.from_dict(cmd))
            else:
                cmd_history.append(cmd)
        data['command_history'] = cmd_history
        return cls(**data)


@dataclass
class OperatorSessionData:
    """Persistent operator session data"""
    operator_id: str
    username: str
    first_login: float
    last_login: float
    last_ip: str = ""
    total_commands: int = 0
    command_history: List[dict] = field(default_factory=list)
    sessions: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data['command_history'] = [
            c.to_dict() if isinstance(c, CommandEntry) else c
            for c in self.command_history
        ]
        return data

    @classmethod
    def from_dict(cls, data: dict) -> 'OperatorSessionData':
        cmd_history = []
        for cmd in data.get('command_history', []):
            if isinstance(cmd, dict):
                cmd_history.append(CommandEntry.from_dict(cmd))
        data['command_history'] = cmd_history
        return cls(**data)


class SessionManager:
    """
    JSON-based session persistence manager.

    Provides automatic saving of beacon sessions, command history
    tracking, and operator session persistence.

    Example:
        manager = SessionManager()
        manager.update_beacon_session(beacon_id, crypto_key, ip="192.168.1.1")
        manager.save_sessions()
    """

    def __init__(self, session_file: str = SESSION_FILE):
        """
        Initialize session manager.

        Args:
            session_file: Path to session file
        """
        self.session_file = session_file
        self._lock = threading.Lock()
        self._beacons: Dict[str, BeaconSessionData] = {}
        self._operators: Dict[str, OperatorSessionData] = {}

        # Load existing sessions
        self.load_sessions()

    def load_sessions(self):
        """Load sessions from JSON file"""
        with self._lock:
            if not os.path.exists(self.session_file):
                logger.info(f"No existing session file: {self.session_file}")
                return

            try:
                with open(self.session_file, 'r') as f:
                    data = json.load(f)

                # Load beacon sessions
                for beacon_id, beacon_data in data.get('beacons', {}).items():
                    self._beacons[beacon_id] = BeaconSessionData.from_dict(beacon_data)

                # Load operator sessions
                for op_id, op_data in data.get('operators', {}).items():
                    self._operators[op_id] = OperatorSessionData.from_dict(op_data)

                logger.info(
                    f"Loaded {len(self._beacons)} beacon sessions, "
                    f"{len(self._operators)} operator sessions"
                )
            except Exception as e:
                logger.error(f"Failed to load sessions: {e}")

    def save_sessions(self):
        """Save all sessions to JSON file"""
        with self._lock:
            try:
                data = {
                    'version': 1,
                    'saved_at': datetime.now(timezone.utc).isoformat(),
                    'beacons': {k: v.to_dict() for k, v in self._beacons.items()},
                    'operators': {k: v.to_dict() for k, v in self._operators.items()}
                }

                # Write atomically (write to temp, then rename)
                temp_file = self.session_file + '.tmp'
                with open(temp_file, 'w') as f:
                    json.dump(data, f, indent=2)

                os.replace(temp_file, self.session_file)
                logger.debug(f"Saved {len(self._beacons)} beacon sessions")
            except Exception as e:
                logger.error(f"Failed to save sessions: {e}")

    def update_beacon_session(
        self,
        beacon_id: str,
        crypto_key: bytes,
        ip: str = "",
        user_agent: str = "",
        malleable_config: dict = None
    ):
        """Create or update beacon session"""
        with self._lock:
            now = time.time()
            crypto_key_hash = hashlib.sha256(crypto_key).hexdigest()[:16]

            if beacon_id in self._beacons:
                session = self._beacons[beacon_id]
                session.last_seen = now
                session.total_checkins += 1
                if ip:
                    session.last_ip = ip
                if user_agent:
                    session.user_agent = user_agent
            else:
                session = BeaconSessionData(
                    beacon_id=beacon_id,
                    first_seen=now,
                    last_seen=now,
                    last_ip=ip,
                    user_agent=user_agent,
                    crypto_key_hash=crypto_key_hash,
                    total_checkins=1,
                    malleable_config=malleable_config or {}
                )
                self._beacons[beacon_id] = session
                logger.info(f"Created new beacon session: {beacon_id}")

    @property
    def beacon_count(self) -> int:
        """Number of tracked beacon sessions."""
        return len(self._beacons)

    @property
    def operator_count(self) -> int:
        """Number of tracked operator sessions."""
        return len(self._operators)

    def get_beacon_session(self, beacon_id: str) -> Optional[BeaconSessionData]:
        """Get beacon session data"""
        with self._lock:
            return self._beacons.get(beacon_id)

    def list_beacons(self) -> List[BeaconSessionData]:
        """List all beacon sessions"""
        with self._lock:
            return list(self._beacons.values())

    def remove_beacon(self, beacon_id: str):
        """Remove beacon session"""
        with self._lock:
            if beacon_id in self._beacons:
                del self._beacons[beacon_id]
                logger.info(f"Removed beacon session: {beacon_id}")

    def update_operator_session(
        self,
        operator_id: str,
        username: str,
        ip: str = ""
    ):
        """Create or update operator session"""
        with self._lock:
            now = time.time()

            if operator_id in self._operators:
                session = self._operators[operator_id]
                session.last_login = now
                session.last_ip = ip
            else:
                session = OperatorSessionData(
                    operator_id=operator_id,
                    username=username,
                    first_login=now,
                    last_login=now,
                    last_ip=ip
                )
                self._operators[operator_id] = session
                logger.info(f"Created new operator session: {operator_id}")

    def get_operator_session(self, operator_id: str) -> Optional[OperatorSessionData]:
        """Get operator session data"""
        with self._lock:
            return self._operators.get(operator_id)

    def list_operators(self) -> List[OperatorSessionData]:
        """List all operator sessions"""
        with self._lock:
            return list(self._operators.values())



