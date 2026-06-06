"""
Pandragon Protocol Package

Protocol parsing, serialization, and constants.
"""

from .constants import (
    PANDRAGON_MAGIC,
    HEADER_LEN,
    MAC_LEN,
    S2BOpcode,
    B2SOpcode,
    get_s2b_opcode_name,
    get_b2s_opcode_name,
)

from .parser import (
    ParsedPacket,
    parse_header,
    parse_packet,
    serialize_response,
    decrypt_payload,
    unwrap_payload,
    _macro_to_regex,
)

__all__ = [
    # Constants
    'PANDRAGON_MAGIC',
    'HEADER_LEN',
    'MAC_LEN',
    'S2BOpcode',
    'B2SOpcode',
    'get_s2b_opcode_name',
    'get_b2s_opcode_name',
    # Parser
    'ParsedPacket',
    'parse_header',
    'parse_packet',
    'serialize_response',
    'decrypt_payload',
    'unwrap_payload',
    '_macro_to_regex',
]
