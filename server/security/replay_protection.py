"""
Replay Protection

LRU cache for nonce tracking and replay attack prevention.
"""

import threading
from collections import OrderedDict
from typing import Optional


class LRUCache:
    """
    Thread-safe LRU cache for nonce tracking.

    Provides O(1) lookup and automatic eviction when capacity is reached.
    Used for replay attack prevention.

    Attributes:
        capacity: Maximum number of entries to track

    Example:
        >>> cache = LRUCache(capacity=100)
        >>> cache.add(b"nonce1")
        >>> cache.contains(b"nonce1")
        True
    """

    def __init__(self, capacity: int = 1000):
        """
        Initialize LRU cache.

        Args:
            capacity: Maximum entries before eviction (default: 1000)
        """
        self.capacity = capacity
        self._cache: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def contains(self, key: bytes) -> bool:
        """
        Check if key exists in cache.

        Args:
            key: Key to check

        Returns:
            True if key exists, False otherwise
        """
        with self._lock:
            return key in self._cache

    def add(self, key: bytes) -> None:
        """
        Add key to cache, evicting oldest if at capacity.

        Args:
            key: Key to add
        """
        with self._lock:
            if key in self._cache:
                # Move to end (most recently used)
                self._cache.move_to_end(key)
            else:
                self._cache[key] = True
                if len(self._cache) > self.capacity:
                    # Remove oldest (least recently used)
                    self._cache.popitem(last=False)

    def clear(self) -> None:
        """Clear all entries from cache"""
        with self._lock:
            self._cache.clear()

    def __len__(self) -> int:
        """Get current cache size"""
        with self._lock:
            return len(self._cache)
