"""
Pandragon WebSocket API Client

Unified client using raw WebSocket (websocket-client) for all teamserver
interaction. Synchronous request/response pattern with background thread
for real-time event dispatch via Qt signals.

Supports:
- Request-ID based response matching for concurrent requests
- Auto-reconnection with exponential backoff
- Heartbeat monitoring
"""

import json
import ssl
import time
import threading
import logging
from typing import Optional, Dict

logger = logging.getLogger('pandragon.gui.api')

import websocket
from PyQt6.QtCore import QObject, pyqtSignal


class PandragonAPI(QObject):
    _REQ_TIMEOUT = 30.0
    _AUTH_TIMEOUT = 10.0
    _MAX_RECONNECT_DELAY = 60.0
    _HEARTBEAT_INTERVAL = 15.0
    _HEARTBEAT_TIMEOUT = 30.0

    # --- Real-time event signals ---
    beacon_output = pyqtSignal(str, dict)
    beacon_activity = pyqtSignal(str, dict)
    command_issued = pyqtSignal(str, dict)
    command_result = pyqtSignal(str, dict)
    beacon_removed = pyqtSignal(str)
    operator_joined = pyqtSignal(str)
    operator_left = pyqtSignal(str)
    list_files_result = pyqtSignal(str, dict)

    # --- Connection state signals ---
    connected = pyqtSignal()
    disconnected = pyqtSignal()
    connection_error = pyqtSignal(str)

    def __init__(self, url: str, parent=None):
        super().__init__(parent)
        self._url = url
        self._token: str = ""
        self._username: str = "operator"
        self._ssl_verify: bool = True
        self._ws: Optional[websocket.WebSocketApp] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._authenticated = False
        self._reconnect_delay = 1.0
        self._last_data_time = 0.0

        # Request-ID based pending map
        self._next_req_id = 0
        self._pending: Dict[int, dict] = {}
        self._lock = threading.Lock()

    # ── Connection ───────────────────────────────────────────────

    def connect(self, token: str, username: str = "operator", ssl_verify: bool = True) -> bool:
        if self._running:
            return True

        self._token = token
        self._username = username
        self._ssl_verify = ssl_verify
        self._reconnect_delay = 1.0
        self._last_data_time = time.time()

        return self._do_connect()

    def _do_connect(self) -> bool:
        self._auth_result: Optional[dict] = None
        self._auth_event = threading.Event()

        self._ws = websocket.WebSocketApp(
            self._url,
            on_open=lambda ws: self._on_open(ws),
            on_message=self._on_message,
            on_error=self._on_error,
            on_close=self._on_close,
        )

        sslopt = None
        if not self._ssl_verify:
            sslopt = {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}

        self._thread = threading.Thread(
            target=lambda: self._ws.run_forever(
                sslopt=sslopt, ping_interval=self._HEARTBEAT_INTERVAL,
                ping_timeout=10,
            ), daemon=True
        )
        self._thread.start()

        if not self._auth_event.wait(timeout=self._AUTH_TIMEOUT):
            self._running = False
            self.connection_error.emit("Auth timeout")
            return False

        if self._auth_result and self._auth_result.get('success'):
            self._authenticated = True
            self._reconnect_delay = 1.0
            self.connected.emit()
            return True

        error = (self._auth_result or {}).get('error', 'Auth failed')
        self.connection_error.emit(error)
        return False

    def disconnect(self):
        self._running = False
        self._authenticated = False
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass

    def is_connected(self) -> bool:
        return self._authenticated and self._running

    # ── Reconnection ─────────────────────────────────────────────

    def _start_reconnect(self):
        if not self._running:
            return
        delay = min(self._reconnect_delay, self._MAX_RECONNECT_DELAY)
        self._reconnect_delay *= 2
        logger.info(f"Reconnecting in {delay:.0f}s...")
        threading.Timer(delay, self._try_reconnect).start()

    def _try_reconnect(self):
        if not self._running or self._authenticated:
            return
        logger.info("Attempting reconnection...")
        success = self._do_connect()
        if not success:
            self._start_reconnect()

    # ── Request helpers ──────────────────────────────────────────

    def _send_request(self, msg: dict) -> dict:
        with self._lock:
            req_id = self._next_req_id
            self._next_req_id += 1
            msg['id'] = req_id
            evt = threading.Event()
            self._pending[req_id] = {'event': evt, 'result': None, 'type': msg.get('type', '')}

        try:
            if self._ws and self._ws.sock and self._ws.sock.connected:
                self._ws.send(json.dumps(msg))
            else:
                raise ConnectionError("WebSocket not connected")
        except Exception as e:
            with self._lock:
                self._pending.pop(req_id, None)
            raise ConnectionError(f"Send failed: {e}")

        if not evt.wait(timeout=self._REQ_TIMEOUT):
            with self._lock:
                self._pending.pop(req_id, None)
            raise TimeoutError(f"Request timeout: {msg.get('type')}")

        with self._lock:
            pending = self._pending.pop(req_id, {})
            result = pending.get('result', {})
        return result

    def _send_and_check(self, msg: dict) -> dict:
        result = self._send_request(msg)
        if not result.get('success', True):
            raise RuntimeError(result.get('error', 'Unknown error'))
        return result

    # ── WebSocket callbacks ──────────────────────────────────────

    def _on_open(self, ws):
        ws.send(json.dumps({
            'type': 'authenticate',
            'token': self._token,
            'username': self._username,
        }))

    def _on_message(self, ws, message: str):
        try:
            data = json.loads(message)
        except json.JSONDecodeError:
            return

        self._last_data_time = time.time()
        msg_type = data.get('type', '')
        msg_id = data.get('id')

        # Auth response
        if msg_type == 'authenticated':
            self._auth_result = data
            self._auth_event.set()
            return

        # Match pending request by ID
        if msg_id is not None:
            with self._lock:
                pending = self._pending.get(msg_id)
                if pending is not None:
                    pending['result'] = data
                    pending['event'].set()
                    return

        # Real-time events
        self._dispatch_event(msg_type, data)

    def _dispatch_event(self, msg_type: str, data: dict):
        if msg_type == 'beacon_output_log':
            beacon_id = data.get('beacon_id', '')
            self.beacon_output.emit(beacon_id, data)

        elif msg_type == 'operator_joined':
            name = data.get('username', '')
            self.operator_joined.emit(name)

        elif msg_type == 'operator_left':
            name = data.get('username', '')
            self.operator_left.emit(name)

        elif msg_type == 'beacon_removed':
            beacon_id = data.get('beacon_id', '')
            self.beacon_removed.emit(beacon_id)

        elif msg_type == 'beacon_activity':
            beacon_id = data.get('beacon_id', '')
            self.beacon_activity.emit(beacon_id, data)

    def _on_error(self, ws, error):
        self.connection_error.emit(str(error))

    def _on_close(self, ws, close_status_code, close_msg):
        was_auth = self._authenticated
        self._authenticated = False
        # Fail all pending requests
        with self._lock:
            for req_id, pending in list(self._pending.items()):
                pending['result'] = {'success': False, 'error': 'Connection closed'}
                pending['event'].set()
        if was_auth:
            self.disconnected.emit()
        if self._running:
            self._start_reconnect()

    # ── Public API methods ───────────────────────────────────────

    def list_beacons(self) -> list:
        result = self._send_request({'type': 'list_beacons'})
        return result.get('beacons', [])

    def get_beacon(self, beacon_id: str) -> dict:
        return self._send_request({'type': 'get_beacon', 'beacon_id': beacon_id})

    def get_beacon_output(self, beacon_id: str, limit: int = 100) -> dict:
        return self._send_request({
            'type': 'get_output', 'beacon_id': beacon_id, 'limit': limit,
        })

    def remove_beacon(self, beacon_id: str) -> dict:
        return self._send_and_check({'type': 'remove_beacon', 'beacon_id': beacon_id})

    def rotate_key(self, beacon_id: str) -> dict:
        return self._send_and_check({'type': 'rotate_key', 'beacon_id': beacon_id})

    def list_async_bofs(self, beacon_id: str) -> dict:
        return self._send_request({'type': 'list_async_bofs', 'beacon_id': beacon_id})

    def abort_async_bof(self, beacon_id: str, task_id: int) -> dict:
        return self._send_request({
            'type': 'abort_async_bof', 'beacon_id': beacon_id, 'task_id': task_id,
        })

    def create_task(self, beacon_id: str, opcode: int, payload: str = "",
                    priority: str = "NORMAL", schedule_type: str = "immediate",
                    execute_at: float = None, delay_seconds: float = None,
                    cron_expression: str = None, max_retries: int = 0,
                    description: str = "", child_tasks: list = None) -> dict:
        return self._send_and_check({
            'type': 'command',
            'beacon_id': beacon_id,
            'opcode': opcode,
            'payload': payload,
            'command': description,
        })

    def get_relay_graph(self) -> dict:
        return self._send_request({'type': 'get_relay_graph'})

    def relay_enable(self, beacon_id: str, pipe_name_prefix: str = "msagent") -> dict:
        return self._send_and_check({
            'type': 'relay_enable',
            'beacon_id': beacon_id,
            'pipe_name_prefix': pipe_name_prefix,
        })

    def relay_disable(self, beacon_id: str) -> dict:
        return self._send_and_check({
            'type': 'relay_disable',
            'beacon_id': beacon_id,
        })

    def relay_add_child(self, parent_beacon_id: str, child_beacon_id: str,
                        pipe_name: str = "") -> dict:
        return self._send_and_check({
            'type': 'relay_add_child',
            'parent_beacon_id': parent_beacon_id,
            'child_beacon_id': child_beacon_id,
            'pipe_name': pipe_name,
        })

    def relay_remove_child(self, parent_beacon_id: str, child_beacon_id: str) -> dict:
        return self._send_and_check({
            'type': 'relay_remove_child',
            'parent_beacon_id': parent_beacon_id,
            'child_beacon_id': child_beacon_id,
        })

    def rename_beacon(self, beacon_id: str, name: str) -> dict:
        return self._send_and_check({
            'type': 'rename_beacon',
            'beacon_id': beacon_id,
            'name': name,
        })

    def list_bofs(self) -> list:
        result = self._send_request({'type': 'list_bofs'})
        return result.get('bofs', [])

    def upload_bof(self, filename: str, data: str) -> dict:
        return self._send_and_check({
            'type': 'upload_bof',
            'filename': filename,
            'data': data,
        })

    def delete_bof(self, filename: str) -> dict:
        return self._send_and_check({
            'type': 'delete_bof',
            'filename': filename,
        })

    def register_beacon(self, beacon_id: str, crypto_key: str, allowed_routes: list) -> dict:
        return self._send_and_check({
            'type': 'register_beacon',
            'beacon_id': beacon_id,
            'crypto_key': crypto_key,
            'allowed_routes': allowed_routes,
        })
