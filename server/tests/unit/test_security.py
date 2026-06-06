"""
Unit Tests for Security Components

Tests for replay protection.
"""

import pytest
import time
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from security.replay_protection import LRUCache


class TestLRUCache:
    """Test LRU cache for nonce tracking"""

    def test_basic_operations(self, lru_cache):
        """Test basic add and contains operations"""
        lru_cache.add(b"nonce1")
        lru_cache.add(b"nonce2")
        
        assert lru_cache.contains(b"nonce1") is True
        assert lru_cache.contains(b"nonce2") is True
        assert lru_cache.contains(b"nonce3") is False

    def test_capacity_eviction(self):
        """Test that oldest entries are evicted when capacity is reached"""
        cache = LRUCache(capacity=3)
        
        cache.add(b"1")
        cache.add(b"2")
        cache.add(b"3")
        
        # Add one more, should evict oldest
        cache.add(b"4")
        
        assert cache.contains(b"1") is False  # Evicted
        assert cache.contains(b"2") is True
        assert cache.contains(b"3") is True
        assert cache.contains(b"4") is True
        assert len(cache) == 3

    def test_access_refreshes(self):
        """Test that accessing an entry refreshes its position"""
        cache = LRUCache(capacity=3)
        
        cache.add(b"1")
        cache.add(b"2")
        cache.add(b"3")
        
        # Access "1" to refresh it
        cache.add(b"1")  # Re-add moves to end
        
        # Add new entry, should evict "2" (now oldest)
        cache.add(b"4")
        
        assert cache.contains(b"1") is True  # Refreshed
        assert cache.contains(b"2") is False  # Evicted
        assert cache.contains(b"3") is True
        assert cache.contains(b"4") is True

    def test_clear(self, lru_cache):
        """Test clearing the cache"""
        lru_cache.add(b"1")
        lru_cache.add(b"2")
        
        lru_cache.clear()
        
        assert len(lru_cache) == 0
        assert lru_cache.contains(b"1") is False
