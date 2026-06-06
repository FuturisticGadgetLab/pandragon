"""
Binary Output Detector and Auto-Saver

Detects binary (non-UTF8) beacon output and automatically saves it to disk.
Used for handling screenshots, file transfers, and other binary BOF outputs.
"""

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger('pandragon.binary_output')

# Output directory
OUTPUT_DIR = Path(__file__).parent.parent / "data" / "beacon_outputs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Image magic bytes for detection
IMAGE_MAGIC = {
    b'\x89PNG\r\n\x1a\n': 'png',
    b'\xff\xd8\xff': 'jpg',
    b'GIF8': 'gif',
    b'BM': 'bmp',
}


def detect_and_save_binary_output(beacon_id: str, payload: bytes) -> Optional[dict]:
    """
    Detect if payload is binary (non-UTF8) data and auto-save to disk.

    Args:
        beacon_id: Beacon identifier
        payload: Raw output bytes from beacon

    Returns:
        dict with file info if binary detected, None if text
        {
            'is_binary': True,
            'file_path': str,
            'file_id': str,
            'file_type': str,  # 'png', 'jpg', 'bin', etc.
            'file_size': int
        }
    """
    # Try strict UTF-8 decode; text if it succeeds
    try:
        payload.decode('utf-8')
        return None  # Text output, no special handling needed
    except UnicodeDecodeError:
        pass  # Binary data detected

    # Determine file type from magic bytes
    file_type = 'bin'  # Default: unknown binary
    for magic, ext in IMAGE_MAGIC.items():
        if payload.startswith(magic):
            file_type = ext
            break

    # Special case: WebP has RIFF at offset 0 but 'WEBP' at offset 8
    if file_type == 'bin' and len(payload) > 12:
        if payload[:4] == b'RIFF' and payload[8:12] == b'WEBP':
            file_type = 'webp'

    # Generate file ID: <timestamp>_<beacon_id_short>_<hash_prefix>.<ext>
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    payload_hash = hashlib.sha256(payload).hexdigest()[:8]
    beacon_short = beacon_id[:8] if len(beacon_id) > 8 else beacon_id
    file_id = f"{timestamp}_{beacon_short}_{payload_hash}.{file_type}"

    # Save to disk
    file_path = OUTPUT_DIR / file_id
    file_path.write_bytes(payload)

    logger.info(f"[{beacon_id}] Binary output detected: {file_type.upper()} "
                f"({len(payload)} bytes) -> {file_path}")

    return {
        'is_binary': True,
        'file_path': str(file_path),
        'file_id': file_id,
        'file_type': file_type,
        'file_size': len(payload),
    }
