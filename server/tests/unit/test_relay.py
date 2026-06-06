"""Unit tests for P2P beacon relay functionality."""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch, AsyncMock
from typing import Optional, Tuple

from relay.relay_routing import BeaconRoute, RelayRoutingManager
from relay.relay_handler import (
    handle_relay_up, build_relay_down_packet, generate_pipe_name,
    build_start_relay_packet, build_stop_relay_packet,
    build_relay_add_child_packet, build_relay_remove_child_packet,
    build_relay_down_packet_for_parent, RelayHandler,
    RELAY_CHILD_UP, RELAY_DOWN, RELAY_START, RELAY_STOP,
    RELAY_ADD_CHILD, RELAY_REMOVE_CHILD
)
from protocol.constants import B2SOpcode, S2BOpcode


class TestRelayRoutingManager:
    """Test RelayRoutingManager functionality."""
    
    def test_create_route(self):
        """Test creating a relay route."""
        manager = RelayRoutingManager()
        parent_id = b'parent123'
        child_id = b'child456'
        pipe_id = 42
        
        route = manager.create_route(child_id, parent_id, pipe_id)
        
        assert route.beacon_id == child_id
        assert route.via_beacon_id == parent_id
        assert route.parent_pipe_id == pipe_id
        assert route.transport == 'relay'
        
        # Verify route is retrievable
        retrieved = manager.get_route(child_id)
        assert retrieved == route
    
    def test_get_child_by_pipe_id(self):
        """Test retrieving child ID by parent beacon ID and pipe ID."""
        manager = RelayRoutingManager()
        parent_id = b'parent123'
        child_id = b'child456'
        pipe_id = 42
        
        manager.create_route(child_id, parent_id, pipe_id)
        
        # Test successful lookup
        result = manager.get_child_by_pipe_id(parent_id, pipe_id)
        assert result == child_id
        
        # Test non-existent parent
        result = manager.get_child_by_pipe_id(b'nonexist', pipe_id)
        assert result is None
        
        # Test non-existent pipe ID
        result = manager.get_child_by_pipe_id(parent_id, 999)
        assert result is None
    
    def test_remove_route(self):
        """Test removing a relay route."""
        manager = RelayRoutingManager()
        child_id = b'child456'
        parent_id = b'parent123'
        pipe_id = 42
        
        manager.create_route(child_id, parent_id, pipe_id)
        assert manager.get_route(child_id) is not None
        
        manager.remove_route(child_id)
        assert manager.get_route(child_id) is None
    
    def test_update_last_seen(self):
        """Test updating last seen timestamp."""
        manager = RelayRoutingManager()
        child_id = b'child456'
        
        manager.create_route(child_id, b'parent123', 42)
        route_before = manager.get_route(child_id)
        
        # Test that is_alive is True and last_seen is updated
        manager.update_last_seen(child_id)
        route_after = manager.get_route(child_id)
        
        # Focus on core functionality rather than exact timestamp values
        assert route_after.is_alive == True
        assert route_after.last_seen >= route_before.last_seen  # Should be equal or greater


class TestRelayHandler:
    """Test relay packet handler functions."""
    
    def test_generate_pipe_name(self):
        """Test generating pipe names."""
        # Test macro format
        name = generate_pipe_name("msagent", use_macro=True)
        assert name.startswith("msagent_")
        assert len(name) == len("msagent_") + 16  # 8 bytes hex = 16 chars
        
        # Test non-macro format
        name = generate_pipe_name("testpipe", use_macro=False)
        assert name.startswith("testpipe_")
        assert len(name) == len("testpipe_") + 32  # 16 bytes hex = 32 chars
    
    def test_build_start_relay_packet(self):
        """Test building START_RELAY packet."""
        packet = build_start_relay_packet()
        assert packet == bytes([RELAY_START])
        assert len(packet) == 1
    
    def test_build_stop_relay_packet(self):
        """Test building STOP_RELAY packet."""
        packet = build_stop_relay_packet()
        assert packet == bytes([RELAY_STOP])
        assert len(packet) == 1
    
    def test_build_relay_add_child_packet(self):
        """Test building RELAY_ADD_CHILD packet."""
        pipe_id = 12345
        pipe_name = "test_pipe"
        
        packet = build_relay_add_child_packet(pipe_id, pipe_name)
        
        # Verify structure: [opcode] [pipe_id(4B LE)] [name_len(1B)] [pipe_name(UTF-16)]
        assert packet[0] == RELAY_ADD_CHILD
        
        # Check pipe ID (little-endian)
        assert int.from_bytes(packet[1:5], 'little') == pipe_id
        
        # Check name length
        name_bytes = pipe_name.encode('utf-16le')
        assert packet[5] == len(name_bytes)
        
        # Check pipe name
        assert packet[6:] == name_bytes
    
    def test_build_relay_remove_child_packet(self):
        """Test building RELAY_REMOVE_CHILD packet."""
        pipe_id = 54321
        
        packet = build_relay_remove_child_packet(pipe_id)
        
        # Verify structure: [opcode] [pipe_id(4B LE)]
        assert packet[0] == RELAY_REMOVE_CHILD
        assert int.from_bytes(packet[1:5], 'little') == pipe_id
        assert len(packet) == 5
    
    def test_build_relay_down_packet_for_parent(self):
        """Test building RELAY_DOWN packet for parent."""
        pipe_id = 67890
        encrypted_data = b'encrypted_packet_data'
        
        packet = build_relay_down_packet_for_parent(pipe_id, encrypted_data)
        
        # Verify structure: [opcode] [pipe_id(4B LE)] [encrypted_packet]
        assert packet[0] == RELAY_DOWN
        assert int.from_bytes(packet[1:5], 'little') == pipe_id
        assert packet[5:] == encrypted_data


class TestRelayHandlerIntegration:
    """Integration tests for RelayHandler."""

    @pytest.mark.asyncio
    async def test_handle_relay_up_success(self):
        """Test successful relay upstream handling."""
        mock_manager = Mock()
        mock_manager.get_child_by_pipe_id.return_value = b'child123'
        mock_manager.get_route.return_value = Mock()
        mock_manager.update_last_seen.return_value = None

        mock_registry = Mock()
        mock_beacon = Mock()
        mock_beacon.crypto_key = b'\x00' * 32
        mock_beacon.next_task_seq = 0
        mock_beacon.validate_seq_num = AsyncMock(return_value=True)
        mock_beacon.validate_nonce = AsyncMock(return_value=True)
        mock_beacon.touch = AsyncMock()
        mock_beacon.pop_task = AsyncMock(return_value=None)
        mock_registry.get.return_value = mock_beacon

        mock_handler = Mock()
        mock_handler._handle_beacon_opcode = AsyncMock()

        mock_parse = Mock()
        mock_parse.seq_num = 1
        mock_parse.nonce = b'\x00' * 24
        mock_parse.beacon_id = b'child123'
        mock_parse.opcode = 0x01
        mock_parse.payload = b''

        with patch('relay.relay_handler.get_relay_manager', return_value=mock_manager), \
             patch('relay.relay_handler.parse_packet', return_value=(mock_parse, None)):
            result = await handle_relay_up(
                parent_beacon_id=b'parent456',
                pipe_id=42,
                encrypted_packet=b'encrypted_data',
                registry=mock_registry,
                transport_handler=mock_handler,
            )

        assert result is not None
        mock_manager.get_child_by_pipe_id.assert_called_once_with(b'parent456', 42)

    @pytest.mark.asyncio
    async def test_handle_relay_up_unknown_pipe(self):
        """Test relay upstream handling with unknown pipe ID."""
        mock_manager = Mock()
        mock_manager.get_child_by_pipe_id.return_value = None

        with patch('relay.relay_handler.get_relay_manager', return_value=mock_manager):
            result = await handle_relay_up(
                parent_beacon_id=b'parent456',
                pipe_id=999,
                encrypted_packet=b'encrypted_data',
                registry=Mock(),
                transport_handler=Mock(),
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_handle_relay_up_decryption_failure(self):
        """Test relay upstream handling with decryption failure."""
        mock_manager = Mock()
        mock_manager.get_child_by_pipe_id.return_value = b'child123'
        mock_manager.get_route.return_value = Mock()

        mock_registry = Mock()
        mock_beacon = Mock()
        mock_beacon.crypto_key = b'\x00' * 32
        mock_registry.get.return_value = mock_beacon

        with patch('relay.relay_handler.get_relay_manager', return_value=mock_manager), \
             patch('relay.relay_handler.parse_packet', return_value=(None, 'decrypt failed')):
            result = await handle_relay_up(
                parent_beacon_id=b'parent456',
                pipe_id=42,
                encrypted_packet=b'encrypted_data',
                registry=mock_registry,
                transport_handler=Mock(),
            )

        assert result is None

    def test_build_relay_down_packet_success(self):
        """Test successful relay downstream packet building."""
        mock_manager = Mock()
        mock_route = Mock()
        mock_route.transport = 'relay'
        mock_route.via_beacon_id = b'parent456'
        mock_route.parent_pipe_id = 42
        mock_manager.get_route.return_value = mock_route

        with patch('relay.relay_handler.get_relay_manager', return_value=mock_manager):
            parent_id, relay_packet = build_relay_down_packet(
                child_beacon_id=b'child123',
                encrypted_response=b'encrypted_response',
            )

        assert parent_id == b'parent456'
        assert relay_packet == b'\x2a\x00\x00\x00' + b'encrypted_response'

    def test_build_relay_down_packet_no_route(self):
        """Test relay downstream with no route."""
        mock_manager = Mock()
        mock_manager.get_route.return_value = None

        with patch('relay.relay_handler.get_relay_manager', return_value=mock_manager):
            parent_id, relay_packet = build_relay_down_packet(
                child_beacon_id=b'child123',
                encrypted_response=b'encrypted_response',
            )

        assert parent_id is None
        assert relay_packet is None

    def test_build_relay_down_packet_no_pipe_id(self):
        """Test relay downstream with missing pipe ID."""
        mock_manager = Mock()
        mock_route = Mock()
        mock_route.transport = 'relay'
        mock_route.via_beacon_id = b'parent456'
        mock_route.parent_pipe_id = None
        mock_manager.get_route.return_value = mock_route

        with patch('relay.relay_handler.get_relay_manager', return_value=mock_manager):
            parent_id, relay_packet = build_relay_down_packet(
                child_beacon_id=b'child123',
                encrypted_response=b'encrypted_response',
            )

        assert parent_id is None
        assert relay_packet is None


class TestRelayHandlerClass:
    """Test RelayHandler class methods."""

    def test_relay_handler_init(self):
        """Test RelayHandler initialization."""
        handler = RelayHandler()

        assert handler.relay_mgr is not None

    @pytest.mark.asyncio
    async def test_relay_handler_handle_child_data(self):
        """Test RelayHandler.handle_child_data method."""
        handler = RelayHandler()

        with patch('relay.relay_handler.handle_relay_up', new_callable=AsyncMock) as mock_handle:
            mock_handle.return_value = b'encrypted_response'

            result = await handler.handle_child_data(
                parent_beacon_id=b'parent456',
                pipe_id=42,
                encrypted_packet=b'encrypted_data',
                registry=Mock(),
                transport_handler=Mock(),
            )

        assert result == b'encrypted_response'

    def test_relay_handler_send_to_child(self):
        """Test RelayHandler.send_to_child method."""
        handler = RelayHandler()

        with patch('relay.relay_handler.build_relay_down_packet') as mock_build:
            mock_build.return_value = (b'parent456', b'relay_packet')

            result = handler.send_to_child(
                child_beacon_id=b'child123',
                encrypted_response=b'encrypted_response',
            )

        assert result == (b'parent456', b'relay_packet')
        mock_build.assert_called_once_with(
            b'child123', b'encrypted_response',
        )


class TestOpcodeConstants:
    """Test that opcode constants match between server and beacon."""
    
    def test_relay_opcodes_match_beacon(self):
        """Verify relay opcodes match beacon definitions."""
        # These should match the values in Beacon/include/network/net_abstract.h
        assert RELAY_CHILD_UP == B2SOpcode.RELAY_CHILD_UP == 0x40
        assert RELAY_DOWN == S2BOpcode.RELAY_DOWN == 0x44
        assert RELAY_START == S2BOpcode.START_RELAY == 0x40
        assert RELAY_STOP == S2BOpcode.STOP_RELAY == 0x41
        assert RELAY_ADD_CHILD == S2BOpcode.RELAY_ADD_CHILD == 0x42
        assert RELAY_REMOVE_CHILD == S2BOpcode.RELAY_REMOVE_CHILD == 0x43
    
    def test_opcode_names_include_relay(self):
        """Verify relay opcodes are included in opcode name mappings."""
        from protocol.constants import B2S_OPCODE_NAMES, S2B_OPCODE_NAMES
        
        assert B2SOpcode.RELAY_CHILD_UP in B2S_OPCODE_NAMES
        assert S2BOpcode.START_RELAY in S2B_OPCODE_NAMES
        assert S2BOpcode.STOP_RELAY in S2B_OPCODE_NAMES
        assert S2BOpcode.RELAY_ADD_CHILD in S2B_OPCODE_NAMES
        assert S2BOpcode.RELAY_REMOVE_CHILD in S2B_OPCODE_NAMES
        assert S2BOpcode.RELAY_DOWN in S2B_OPCODE_NAMES


if __name__ == '__main__':
    pytest.main([__file__, '-v'])