"""
Unit Tests for Beacon Components

Tests for beacon registry and sessions.
"""

import pytest
import time
import json
import sys
import os
import hashlib

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from beacon.registry import BeaconSession, BeaconRegistry


class TestBeaconSession:
    """Test beacon session functionality"""

    @pytest.mark.asyncio
    async def test_seq_num_validation(self, crypto_key, beacon_id):
        """Test sequence number validation"""
        session = BeaconSession(
            beacon_id=beacon_id.hex(),
            crypto_key=crypto_key
        )

        # First sequence number should be valid
        assert await session.validate_seq_num(1) is True
        assert session.last_seq_num == 1

        # Increasing sequence numbers should be valid
        assert await session.validate_seq_num(2) is True
        assert await session.validate_seq_num(3) is True

        # Replay (old sequence number) should be rejected
        assert await session.validate_seq_num(2) is False

    @pytest.mark.asyncio
    async def test_seq_num_wraparound(self, crypto_key, beacon_id):
        """Test sequence number wraparound handling"""
        session = BeaconSession(
            beacon_id=beacon_id.hex(),
            crypto_key=crypto_key,
            last_seq_num=0xFFFFFFFF  # Max uint32
        )

        # After overflow, small sequence numbers should be accepted
        assert await session.validate_seq_num(5) is True
        assert session.last_seq_num == 5

    @pytest.mark.asyncio
    async def test_nonce_validation(self, crypto_key, beacon_id):
        """Test nonce validation"""
        session = BeaconSession(
            beacon_id=beacon_id.hex(),
            crypto_key=crypto_key
        )

        nonce1 = b"n" * 24
        nonce2 = b"m" * 24

        # First use of nonce should be valid
        assert await session.validate_nonce(nonce1) is True

        # Replay of same nonce should be rejected
        assert await session.validate_nonce(nonce1) is False

        # New nonce should be valid
        assert await session.validate_nonce(nonce2) is True

    @pytest.mark.asyncio
    async def test_task_queue(self, crypto_key, beacon_id):
        """Test task queue operations"""
        session = BeaconSession(
            beacon_id=beacon_id.hex(),
            crypto_key=crypto_key
        )

        # Queue tasks
        await session.queue_task(0x01, b"payload1")
        await session.queue_task(0x02, b"payload2")

        # Pop tasks
        task1 = await session.pop_task()
        assert task1["opcode"] == 0x01
        assert task1["payload"] == b"payload1"
        assert task1["seq_num"] == 0

        task2 = await session.pop_task()
        assert task2["opcode"] == 0x02
        assert task2["payload"] == b"payload2"
        assert task2["seq_num"] == 1

        # No more tasks
        assert await session.pop_task() is None

    @pytest.mark.asyncio
    async def test_touch_updates_timestamp(self, crypto_key, beacon_id):
        """Test that touch updates last_seen timestamp"""
        session = BeaconSession(
            beacon_id=beacon_id.hex(),
            crypto_key=crypto_key
        )

        old_timestamp = session.last_seen
        time.sleep(0.1)

        await session.touch()

        assert session.last_seen > old_timestamp


class TestBeaconRegistry:
    """Test beacon registry functionality"""

    @pytest.fixture
    def known_beacons_file(self, temp_dir, crypto_key):
        """Create a known_beacons.json file with a test beacon"""
        beacon_id = hashlib.sha256(crypto_key).digest()[:8].hex()
        data = {
            "version": 2,
            "beacons": {
                beacon_id: {
                    "crypto_key": crypto_key.hex(),
                    "allowed_routes": [
                        {
                            "path": "/api/checkin",
                            "user_agent": "Pandragon-Beacon/1.0",
                            "http_method": "POST",
                            "malleable_config": None,
                        }
                    ],
                }
            },
        }
        path = os.path.join(temp_dir, "known_beacons.json")
        with open(path, 'w') as f:
            json.dump(data, f)
        return path

    @pytest.mark.asyncio
    async def test_register_known_beacon(self, crypto_key, known_beacons_file):
        """Test registering a known beacon"""
        registry = BeaconRegistry(known_beacons_path=known_beacons_file)
        beacon = await registry.register(crypto_key)

        assert beacon is not None
        assert len(beacon.beacon_id) == 16  # 8 bytes as hex
        assert beacon.crypto_key == crypto_key
        assert len(beacon.allowed_routes) == 1

    @pytest.mark.asyncio
    async def test_unknown_beacon_rejected(self, crypto_key, temp_dir):
        """Test that unknown beacons are rejected"""
        empty_file = os.path.join(temp_dir, "known_beacons.json")
        with open(empty_file, 'w') as f:
            json.dump({"version": 2, "beacons": {}}, f)

        registry = BeaconRegistry(known_beacons_path=empty_file)

        beacon = await registry.register(crypto_key)
        assert beacon is None

    @pytest.mark.asyncio
    async def test_get_by_beacon_id(self, crypto_key, known_beacons_file):
        """Test getting beacon by ID"""
        registry = BeaconRegistry(known_beacons_path=known_beacons_file)
        registered = await registry.register(crypto_key)

        beacon_id = hashlib.sha256(crypto_key).digest()[:8]
        retrieved = await registry.get_by_beacon_id(beacon_id)

        assert retrieved is not None
        assert retrieved.beacon_id == registered.beacon_id

    @pytest.mark.asyncio
    async def test_unknown_id_rejected(self, temp_dir):
        """Test that unknown beacon IDs are rejected"""
        empty_file = os.path.join(temp_dir, "known_beacons.json")
        with open(empty_file, 'w') as f:
            json.dump({"version": 2, "beacons": {}}, f)

        registry = BeaconRegistry(known_beacons_path=empty_file)
        result = await registry.get_by_beacon_id(b"\x00" * 8)

        assert result is None

    @pytest.mark.asyncio
    async def test_list_beacons(self, crypto_key, known_beacons_file):
        """Test listing all beacons"""
        registry = BeaconRegistry(known_beacons_path=known_beacons_file)

        await registry.register(crypto_key)
        beacons = registry.list_beacons()
        assert len(beacons) == 1

    @pytest.mark.asyncio
    async def test_remove_beacon(self, crypto_key, known_beacons_file):
        """Test removing a beacon from active sessions"""
        registry = BeaconRegistry(known_beacons_path=known_beacons_file)
        await registry.register(crypto_key)

        beacon_id_hex = hashlib.sha256(crypto_key).digest()[:8].hex()
        await registry.remove(beacon_id_hex)

        # get() only checks active sessions (no re-registration)
        result = registry.get(beacon_id_hex)
        assert result is None

    def test_find_candidates(self, crypto_key, known_beacons_file):
        """Test route-based candidate lookup"""
        registry = BeaconRegistry(known_beacons_path=known_beacons_file)

        candidates = registry.find_candidates(
            path="/api/checkin",
            user_agent="Pandragon-Beacon/1.0",
            http_method="POST",
        )

        assert len(candidates) == 1
        beacon_id, route_info = candidates[0]
        assert route_info["path"] == "/api/checkin"
        assert route_info["user_agent"] == "Pandragon-Beacon/1.0"
        assert route_info["http_method"] == "POST"

    def test_find_candidates_no_match(self, crypto_key, known_beacons_file):
        """Test candidate lookup with no matching routes"""
        registry = BeaconRegistry(known_beacons_path=known_beacons_file)

        candidates = registry.find_candidates(
            path="/hacker/path",
            user_agent="Hacker-Agent",
            http_method="GET",
        )

        assert len(candidates) == 0

    def test_is_route_allowed(self, crypto_key, known_beacons_file):
        """Test route permission check"""
        registry = BeaconRegistry(known_beacons_path=known_beacons_file)
        beacon_id = hashlib.sha256(crypto_key).digest()[:8].hex()

        assert registry.is_route_allowed(beacon_id, "/api/checkin") is True
        assert registry.is_route_allowed(beacon_id, "/evil/path") is False

    def test_find_tcp_candidates(self, temp_dir, crypto_key):
        """Test port-based TCP candidate lookup"""
        beacon_id = hashlib.sha256(crypto_key).digest()[:8].hex()
        data = {
            "version": 2,
            "beacons": {
                beacon_id: {
                    "crypto_key": crypto_key.hex(),
                    "allowed_routes": [
                        {
                            "transport_type": "TCP",
                            "path": "",
                            "port": 9090,
                            "host": "0.0.0.0",
                            "user_agent": "",
                            "http_method": "GET",
                            "malleable_config": None,
                        }
                    ],
                }
            },
        }
        path = os.path.join(temp_dir, "known_beacons.json")
        with open(path, 'w') as f:
            json.dump(data, f)

        registry = BeaconRegistry(known_beacons_path=path)
        candidates = registry.find_tcp_candidates(port=9090)
        assert len(candidates) == 1
        cid, info = candidates[0]
        assert cid == beacon_id
        assert info["port"] == 9090
        assert info["transport_type"] == "TCP"

    def test_find_tcp_candidates_wrong_port(self, temp_dir, crypto_key):
        """Test TCP candidate lookup with non-matching port"""
        beacon_id = hashlib.sha256(crypto_key).digest()[:8].hex()
        data = {
            "version": 2,
            "beacons": {
                beacon_id: {
                    "crypto_key": crypto_key.hex(),
                    "allowed_routes": [
                        {
                            "transport_type": "TCP",
                            "path": "",
                            "port": 9090,
                            "host": "0.0.0.0",
                            "user_agent": "",
                            "http_method": "GET",
                            "malleable_config": None,
                        }
                    ],
                }
            },
        }
        path = os.path.join(temp_dir, "known_beacons.json")
        with open(path, 'w') as f:
            json.dump(data, f)

        registry = BeaconRegistry(known_beacons_path=path)
        candidates = registry.find_tcp_candidates(port=8080)
        assert len(candidates) == 0

    def test_find_tcp_candidates_ip_filter(self, temp_dir, crypto_key):
        """Test TCP candidate lookup with IP/host filter"""
        beacon_id = hashlib.sha256(crypto_key).digest()[:8].hex()
        data = {
            "version": 2,
            "beacons": {
                beacon_id: {
                    "crypto_key": crypto_key.hex(),
                    "allowed_routes": [
                        {
                            "transport_type": "TCP",
                            "path": "",
                            "port": 9090,
                            "host": "192.168.1.100",
                            "user_agent": "",
                            "http_method": "GET",
                            "malleable_config": None,
                        }
                    ],
                }
            },
        }
        path = os.path.join(temp_dir, "known_beacons.json")
        with open(path, 'w') as f:
            json.dump(data, f)

        registry = BeaconRegistry(known_beacons_path=path)

        # Wrong IP should not match
        candidates = registry.find_tcp_candidates(port=9090, remote_ip="10.0.0.1")
        assert len(candidates) == 0

        # Correct IP should match
        candidates = registry.find_tcp_candidates(port=9090, remote_ip="192.168.1.100")
        assert len(candidates) == 1

    @pytest.mark.asyncio
    async def test_missing_file_all_beacons_rejected(self, temp_dir):
        """Test that missing known_beacons.json rejects all"""
        missing = os.path.join(temp_dir, "nonexistent.json")
        registry = BeaconRegistry(known_beacons_path=missing)

        assert await registry.register(os.urandom(32)) is None
        assert await registry.get_by_beacon_id(b"\x01" * 8) is None
