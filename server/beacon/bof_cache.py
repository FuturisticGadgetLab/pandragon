"""
BOF Content Cache for Pandragon Teamserver

Provides server-side BOF deduplication:
- Track BOFs by SHA256(content) hash
- Assign random bof_id to each unique BOF
- Re-sending same BOF uses same bof_id with bof_len=0
- First send includes full BOF data; subsequent sends omit it
"""

import hashlib
import secrets
import threading
import logging

logger = logging.getLogger('pandragon.bof_cache')


class BofCache:
    """
    Server-side BOF deduplication cache.

    Maps SHA256(bof_content) -> (bof_id, bof_data)
    bof_id is a randomly generated 32-bit unsigned integer.
    """

    def __init__(self):
        self._hash_to_entry: dict[bytes, dict] = {}  # hash -> {bof_id, bof_data}
        self._bof_id_to_hash: dict[int, bytes] = {}   # bof_id -> hash (reverse lookup)
        self._lock = threading.Lock()

    def get_bof_id(self, bof_data: bytes) -> tuple[int, bool]:
        """
        Get or create bof_id for BOF content.

        Args:
            bof_data: Raw BOF binary content

        Returns:
            (bof_id, is_cached): bof_id and whether this was a cache hit (True=re-send, False=first send)
        """
        content_hash = hashlib.sha256(bof_data).digest()

        with self._lock:
            if content_hash in self._hash_to_entry:
                entry = self._hash_to_entry[content_hash]
                logger.debug(f"BOF cache hit: hash={content_hash.hex()[:16]}... bof_id={entry['bof_id']}")
                return entry['bof_id'], True

            bof_id = struct_unpack_I(secrets.token_bytes(4))
            self._hash_to_entry[content_hash] = {
                'bof_id': bof_id,
                'bof_data': bof_data,
            }
            self._bof_id_to_hash[bof_id] = content_hash
            logger.debug(f"BOF cache miss: new bof_id={bof_id} size={len(bof_data)} bytes")
            return bof_id, False

    def get_bof_data(self, bof_id: int) -> bytes | None:
        """Retrieve stored BOF data by bof_id. Returns None if not found."""
        with self._lock:
            content_hash = self._bof_id_to_hash.get(bof_id)
            if content_hash is None:
                return None
            entry = self._hash_to_entry.get(content_hash)
            return entry['bof_data'] if entry else None

    def get_count(self) -> int:
        """Return number of cached BOFs."""
        with self._lock:
            return len(self._hash_to_entry)


def struct_unpack_I(data: bytes) -> int:
    """Unpack 4 bytes as little-endian unsigned 32-bit int."""
    return int.from_bytes(data[:4], 'little')

