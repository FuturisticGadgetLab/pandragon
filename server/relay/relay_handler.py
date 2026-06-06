"""P2P Beacon Relay Handler Module.

Handles incoming relay packets from parent beacons and routes them to child beacons.
"""

import logging
import secrets
from typing import Optional, Tuple

from .relay_routing import BeaconRoute, get_relay_manager
from protocol.constants import B2SOpcode, S2BOpcode
from protocol import parse_packet, serialize_response, parse_header, PANDRAGON_MAGIC

logger = logging.getLogger('pandragon.relay_handler')

# Relay opcodes (matching beacon side)
RELAY_CHILD_UP = B2SOpcode.RELAY_CHILD_UP
RELAY_DOWN = S2BOpcode.RELAY_DOWN
RELAY_START = S2BOpcode.START_RELAY
RELAY_STOP = S2BOpcode.STOP_RELAY
RELAY_ADD_CHILD = S2BOpcode.RELAY_ADD_CHILD
RELAY_REMOVE_CHILD = S2BOpcode.RELAY_REMOVE_CHILD


async def handle_relay_up(
    parent_beacon_id: bytes,
    pipe_id: int,
    encrypted_packet: bytes,
    registry,
    transport_handler,
) -> Optional[bytes]:
    """Handle incoming RELAY_CHILD_UP from parent beacon.

    Args:
        parent_beacon_id: Parent beacon's 8-byte ID
        pipe_id: Parent's local pipe_id for this child
        encrypted_packet: Encrypted child packet
        registry: BeaconRegistry for child key lookup
        transport_handler: BeaconTransportHandler for opcode dispatch

    Returns:
        Encrypted response for child (to be sent back via parent), or None
    """
    relay_mgr = get_relay_manager()

    child_id = relay_mgr.get_child_by_pipe_id(parent_beacon_id, pipe_id)
    if not child_id:
        logger.warning(
            f"RELAY_UP: Unknown pipe_id={pipe_id} from parent {parent_beacon_id.hex()}"
        )
        return None

    child_id_hex = child_id.hex()
    route = relay_mgr.get_route(child_id)
    if not route:
        logger.warning(f"RELAY_UP: No route for child {child_id_hex}")
        return None

    relay_mgr.update_last_seen(child_id)

    # Get child's beacon session for crypto key
    child_beacon = registry.get(child_id_hex)
    if not child_beacon:
        logger.warning(f"RELAY_UP: Child {child_id_hex} not registered")
        return None

    child_key = child_beacon.crypto_key

    try:
        parsed, err = parse_packet(encrypted_packet, child_key, direction_s2b=False)
        if parsed is None:
            logger.error(f"RELAY_UP: Failed to decrypt child packet: {err}")
            return None
    except Exception as e:
        logger.error(f"RELAY_UP: Decrypt exception: {e}")
        return None

    # Validate seq num and nonce
    if not await child_beacon.validate_seq_num(parsed.seq_num):
        logger.warning(f"RELAY_UP: Child {child_id_hex} seq_num replay")
        return None
    if not await child_beacon.validate_nonce(parsed.nonce):
        logger.warning(f"RELAY_UP: Child {child_id_hex} nonce replay")
        return None

    await child_beacon.touch()

    # Process the child's opcode via transport handler dispatch
    await transport_handler._handle_beacon_opcode(child_beacon, parsed)

    # Build response
    task = await child_beacon.pop_task()
    if not task:
        response_packet = serialize_response(
            opcode=S2BOpcode.NO_TASKS,
            beacon_id=child_id,
            seq_num=child_beacon.next_task_seq,
            payload=b"",
            key=child_key,
        )
        child_beacon.next_task_seq += 1
    else:
        response_packet = serialize_response(
            opcode=task["opcode"],
            beacon_id=child_id,
            seq_num=task["seq_num"],
            payload=task.get("payload", b""),
            key=child_key,
        )
        logger.info(f"RELAY_UP: Dispatching to child {child_id_hex}: opcode=0x{task['opcode']:02x}")

    logger.debug(
        f"RELAY_UP: Processed {len(encrypted_packet)} bytes from child {child_id_hex} "
        f"via parent {parent_beacon_id.hex()}"
    )
    return response_packet


def build_relay_down_packet(
    child_beacon_id: bytes,
    encrypted_response: bytes,
) -> Tuple[Optional[bytes], Optional[bytes]]:
    """Build a RELAY_DOWN packet to send to child via parent.

    Returns:
        (parent_beacon_id, relay_down_packet) or (None, None) on error
    """
    relay_mgr = get_relay_manager()
    
    route = relay_mgr.get_route(child_beacon_id)
    if not route or route.transport != 'relay':
        logger.error(f"RELAY_DOWN: No relay route for child {child_beacon_id.hex()}")
        return None, None
        
    parent_beacon_id = route.via_beacon_id
    pipe_id = route.parent_pipe_id
    
    if pipe_id is None:
        logger.error(f"RELAY_DOWN: No pipe_id for child {child_beacon_id.hex()}")
        return None, None
        
    # Build RELAY_DOWN payload: [pipe_id (4B LE)] [encrypted_packet]
    pipe_id_bytes = pipe_id.to_bytes(4, 'little')
    relay_payload = pipe_id_bytes + encrypted_response
    
    return parent_beacon_id, relay_payload


def generate_pipe_name(prefix: str = "msagent", use_macro: bool = True) -> str:
    """Generate a random pipe name for relay.
    
    Args:
        prefix: Prefix for the pipe name
        use_macro: If True, use macro format for server-side expansion
        
    Returns:
        Pipe name (e.g., "msagent_a1b2c3d4e5f6")
    """
    if use_macro:
        # Use macro format that server will expand
        random_hex = secrets.token_hex(8)
        return f"{prefix}_{random_hex}"
    else:
        # Direct random name
        random_hex = secrets.token_hex(16)
        return f"{prefix}_{random_hex}"


def build_start_relay_packet() -> bytes:
    """Build START_RELAY command packet.
    
    Returns:
        START_RELAY opcode (no parameters)
    """
    return bytes([RELAY_START])


def build_stop_relay_packet() -> bytes:
    """Build STOP_RELAY command packet.
    
    Returns:
        STOP_RELAY opcode (no parameters)
    """
    return bytes([RELAY_STOP])


def build_relay_add_child_packet(pipe_id: int, pipe_name: str) -> bytes:
    """Build RELAY_ADD_CHILD command packet.
    
    Args:
        pipe_id: Local pipe ID (4 bytes LE)
        pipe_name: Pipe name (UTF-16 encoded)
        
    Returns:
        RELAY_ADD_CHILD packet
    """
    # [opcode (1B)] [pipe_id (4B LE)] [name_len (1B)] [pipe_name (UTF-16)]
    pipe_name_bytes = pipe_name.encode('utf-16le')
    name_len = len(pipe_name_bytes)
    
    packet = bytes([RELAY_ADD_CHILD])
    packet += pipe_id.to_bytes(4, 'little')
    packet += bytes([name_len])
    packet += pipe_name_bytes
    
    return packet


def build_relay_remove_child_packet(pipe_id: int) -> bytes:
    """Build RELAY_REMOVE_CHILD command packet.
    
    Args:
        pipe_id: Local pipe ID (4 bytes LE)
        
    Returns:
        RELAY_REMOVE_CHILD packet
    """
    # [opcode (1B)] [pipe_id (4B LE)]
    packet = bytes([RELAY_REMOVE_CHILD])
    packet += pipe_id.to_bytes(4, 'little')
    
    return packet


def build_relay_down_packet_for_parent(pipe_id: int, encrypted_packet: bytes) -> bytes:
    """Build RELAY_DOWN packet to send to child via parent.
    
    Args:
        pipe_id: Local pipe ID (4 bytes LE)
        encrypted_packet: Encrypted packet to forward
        
    Returns:
        RELAY_DOWN packet
    """
    # [opcode (1B)] [pipe_id (4B LE)] [encrypted_packet]
    packet = bytes([RELAY_DOWN])
    packet += pipe_id.to_bytes(4, 'little')
    packet += encrypted_packet
    
    return packet


class RelayHandler:
    """High-level relay handler for processing relay packets."""
    
    def __init__(self):
        self.relay_mgr = get_relay_manager()
    
    async def handle_child_data(
        self,
        parent_beacon_id: bytes,
        pipe_id: int,
        encrypted_packet: bytes,
        registry,
        transport_handler,
    ) -> Optional[bytes]:
        """Handle incoming child data from parent beacon."""
        return await handle_relay_up(
            parent_beacon_id,
            pipe_id,
            encrypted_packet,
            registry,
            transport_handler,
        )
    
    def send_to_child(
        self,
        child_beacon_id: bytes,
        encrypted_response: bytes
    ) -> Tuple[Optional[bytes], Optional[bytes]]:
        """Prepare data to send to child via parent."""
        return build_relay_down_packet(
            child_beacon_id,
            encrypted_response,
        )