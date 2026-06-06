import logging
import threading
from typing import Dict, Set

logger = logging.getLogger('pandragon.beacon.cache_state')


class BeaconCacheState:
    """Thread-safe tracking of which BOF IDs are cached per beacon."""

    def __init__(self):
        self._cache: Dict[str, Set[int]] = {}
        self._lock = threading.Lock()

    def update(self, beacon_id: str, bof_ids: list[int]) -> None:
        """Update the cached BOF IDs for a beacon (thread-safe)."""
        with self._lock:
            self._cache[beacon_id] = set(bof_ids)
        logger.debug(f"[{beacon_id}] Cache state updated: {bof_ids}")

    def is_cached(self, beacon_id: str, bof_id: int) -> bool:
        """Check if a BOF ID is cached for a given beacon (thread-safe)."""
        with self._lock:
            if beacon_id not in self._cache:
                return False
            return bof_id in self._cache[beacon_id]

    def get_cached(self, beacon_id: str) -> Set[int]:
        """Get all cached BOF IDs for a beacon (thread-safe)."""
        with self._lock:
            return self._cache.get(beacon_id, set()).copy()

    def remove(self, beacon_id: str) -> None:
        """Remove cache state for a beacon (thread-safe)."""
        with self._lock:
            if beacon_id in self._cache:
                del self._cache[beacon_id]
        logger.debug(f"[{beacon_id}] Cache state removed")

    def clear(self) -> None:
        """Clear all cache state (thread-safe)."""
        with self._lock:
            self._cache.clear()
        logger.debug("All beacon cache state cleared")

