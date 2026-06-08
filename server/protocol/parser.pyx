"""
Pandragon Protocol Parser (Cython Optimized)

Handles decryption and parsing of the encrypted binary protocol.
Packet structure (46-byte header + encrypted payload):
    - magic:           4 bytes (little-endian uint32, 0x50414E44 = "PAND")
    - version:         1 byte (uint8)
    - beacon_id:       8 bytes
    - opcode:          1 byte (uint8)
    - seq_num:         4 bytes (little-endian uint32)
    - nonce:           24 bytes (XChaCha20 nonce)
    - payload_len:     4 bytes (little-endian uint32, ciphertext length excluding MAC)
Padding is handled via PKCS#7 applied to plaintext before encryption.
"""

# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True

import re
from libc.string cimport memcpy
from libc.stdint cimport uint32_t, uint8_t
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, List, Any, Union

# C-level struct for the 46-byte header
cdef extern from *:
    """
    #include <stdint.h>
    #include <string.h>

    #pragma pack(push, 1)
    typedef struct {
        uint32_t magic;
        uint8_t  version;
        uint8_t  beacon_id[8];
        uint8_t  opcode;
        uint32_t seq_num;
        uint8_t  nonce[24];
        uint32_t payload_len;
    } PacketHeader;
    #pragma pack(pop)
    """
    ctypedef struct PacketHeader:
        uint32_t magic
        uint8_t  version
        uint8_t  beacon_id[8]
        uint8_t  opcode
        uint32_t seq_num
        uint8_t  nonce[24]
        uint32_t payload_len

try:
    from Crypto.Cipher import ChaCha20_Poly1305
except ImportError:
    ChaCha20_Poly1305 = None

from .constants import (
    PANDRAGON_MAGIC, HEADER_LEN, MAC_LEN, B2SOpcode, S2BOpcode,
    get_b2s_opcode_name, get_s2b_opcode_name,
    B2S_OPCODE_NAMES, S2B_OPCODE_NAMES
)

@dataclass
class ParsedPacket:
    """Parsed packet structure matching C++ parsed_packet"""
    magic: int
    version: int
    beacon_id: bytes
    opcode: int
    seq_num: int
    nonce: bytes
    payload_len: int
    payload: bytes

    @property
    def beacon_id_hex(self) -> str:
        return self.beacon_id.hex()

    @property
    def opcode_name(self) -> str:
        """Get human-readable opcode name"""
        if self.opcode in B2S_OPCODE_NAMES:
            return get_b2s_opcode_name(self.opcode)
        return get_s2b_opcode_name(self.opcode)


# =============================================================================
# Macro Expansion for Malleable C2
# =============================================================================

_MACRO_PATTERN = re.compile(r'\$\{(TIMESTAMP|RAND_B64:\d+|JUNK:\d+|PAD_BASE64)\}')
_MACRO_INDEXES = {
    'RAND_B64:': 11,
    'JUNK:': 7,
}


def _macro_to_regex(pattern: str) -> str:
    macros: List[str] = []

    def save_macro(match: re.Match) -> str:
        macros.append(match.group(0))
        return f'__MACRO_{len(macros) - 1}__'

    # Replace macros with placeholders
    temp = _MACRO_PATTERN.sub(save_macro, pattern)

    # Escape regex special chars in static parts
    temp = re.escape(temp)

    # Restore macros as regex patterns
    for i, macro in enumerate(macros):
        placeholder = f'__MACRO_{i}__'
        if macro == '${TIMESTAMP}':
            temp = temp.replace(placeholder, r'\d{10}')
        elif macro.startswith('${RAND_B64:'):
            n = int(macro[_MACRO_INDEXES['RAND_B64:']:-1])
            # URL-safe base64 (RFC 4648 §5): - instead of +, _ instead of /
            temp = temp.replace(placeholder, f'[A-Za-z0-9-_]{{{n}}}')
        elif macro.startswith('${JUNK:'):
            n = int(macro[_MACRO_INDEXES['JUNK:']:-1])
            temp = temp.replace(placeholder, f'[A-Za-z0-9]{{{n}}}')
        elif macro == '${PAD_BASE64}':
            temp = temp.replace(placeholder, r'=+[A-Za-z0-9]?')

    return temp


def unwrap_payload(raw_payload: str, prefix: str = "", suffix: str = "") -> str:
    result = raw_payload

    if prefix:
        prefix_pattern = '^' + _macro_to_regex(prefix)
        match = re.match(prefix_pattern, result)
        if match:
            result = result[match.end():]
        else:
            return raw_payload

    if suffix:
        suffix_pattern = _macro_to_regex(suffix) + '$'
        match = re.search(suffix_pattern, result)
        if match:
            result = result[:match.start()]

    return result


# =============================================================================
# Optimized Helpers
# =============================================================================

cdef bytes pkcs7_unpad_c(const unsigned char[:] data):
    """Remove PKCS#7 padding using memoryviews. Returns original data on invalid padding."""
    cdef size_t n = data.shape[0]
    if n == 0:
        return b""

    cdef unsigned char pad_len = data[n - 1]
    if pad_len < 1 or pad_len > 16 or pad_len > n:
        return bytes(data)

    cdef size_t i
    for i in range(n - pad_len, n):
        if data[i] != pad_len:
            return bytes(data)

    return bytes(data[:n - pad_len])

def decrypt_payload(
    const unsigned char[:] ciphertext_with_mac,
    const unsigned char[:] nonce,
    const unsigned char[:] key,
    const unsigned char[:] associated_data = None
) -> Tuple[bool, bytes]:
    if ChaCha20_Poly1305 is None:
        return False, b""

    if nonce.shape[0] != 24 or key.shape[0] != 32 or ciphertext_with_mac.shape[0] < MAC_LEN:
        return False, b""

    cdef size_t n = ciphertext_with_mac.shape[0]
    cdef const unsigned char[:] ciphertext = ciphertext_with_mac[:n - MAC_LEN]
    cdef const unsigned char[:] mac_tag = ciphertext_with_mac[n - MAC_LEN:]

    try:
        cipher = ChaCha20_Poly1305.new(key=bytes(key), nonce=bytes(nonce))
        if associated_data is not None:
            cipher.update(bytes(associated_data))
        plaintext = cipher.decrypt_and_verify(bytes(ciphertext), bytes(mac_tag))
        return True, plaintext
    except Exception as e:
        return False, b""

# =============================================================================
# Main Entry Points
# =============================================================================

def parse_header(
    data: Union[bytes, memoryview]
) -> Tuple[Optional[Dict[str, Any]], str]:
    cdef const unsigned char[:] view
    if isinstance(data, memoryview):
        view = data
    else:
        view = data  # Cython auto-converts bytes-like to memoryview
    
    if view.shape[0] < HEADER_LEN:
        return None, "Buffer too small"

    # Parse header via C-struct overlay
    cdef PacketHeader h
    memcpy(&h, &view[0], sizeof(PacketHeader))

    header = {
        'magic': h.magic,
        'version': h.version,
        'beacon_id': bytes(h.beacon_id[:8]),
        'opcode': h.opcode,
        'seq_num': h.seq_num,
        'nonce': bytes(h.nonce[:24]),
        'payload_len': h.payload_len,
    }

    # Protocol Validation (return error string but still return header)
    if h.magic != PANDRAGON_MAGIC:
        return header, f"Bad magic: 0x{h.magic:08x}"
    if h.version != 0:
        return header, f"Bad version: {h.version}"

    return header, ""


def parse_packet(
    data: Union[bytes, memoryview],
    key: Union[bytes, memoryview],
    direction_s2b: bool = False
) -> Tuple[Optional[ParsedPacket], str]:
    cdef const unsigned char[:] data_view
    cdef const unsigned char[:] key_view
    
    if isinstance(data, memoryview):
        data_view = data
    else:
        data_view = data
        
    if isinstance(key, memoryview):
        key_view = key
    else:
        key_view = key
    
    if data_view.shape[0] == 0:
        return None, "Empty data"
    if data_view.shape[0] < HEADER_LEN + MAC_LEN:
        return None, "Packet too small"

    # Fast header parse via C-struct overlay
    cdef PacketHeader h
    memcpy(&h, &data_view[0], sizeof(PacketHeader))

    # Protocol Validation
    if h.magic != PANDRAGON_MAGIC:
        return None, f"Bad magic: 0x{h.magic:08x}"
    if h.version != 0:
        return None, f"Bad version: {h.version}"

    # Opcode check logic
    cdef unsigned char opcode = h.opcode
    cdef set valid_opcodes
    if direction_s2b:
        valid_opcodes = {
            S2BOpcode.NO_TASKS, S2BOpcode.ECHO, S2BOpcode.SLEEP,
            S2BOpcode.FILE_READ, S2BOpcode.DIE, S2BOpcode.BOF_EXEC,
            S2BOpcode.BOF_FREE, S2BOpcode.ROTATE_KEY,
            S2BOpcode.FILE_DOWNLOAD_START, S2BOpcode.FILE_DOWNLOAD_CHUNK,
            S2BOpcode.FILE_UPLOAD_START, S2BOpcode.FILE_UPLOAD_CHUNK,
            S2BOpcode.ETW_ENABLE, S2BOpcode.ETW_DISABLE,
            S2BOpcode.START_RELAY, S2BOpcode.STOP_RELAY,
            S2BOpcode.RELAY_ADD_CHILD, S2BOpcode.RELAY_REMOVE_CHILD,
            S2BOpcode.RELAY_DOWN, S2BOpcode.INJECT_PROCESS,
        }
    else:
        valid_opcodes = {
            B2SOpcode.BEACON_CHECK_IN, B2SOpcode.BEACON_POLL,
            B2SOpcode.BEACON_TASK_RESULT, B2SOpcode.BEACON_ERROR,
            B2SOpcode.FILE_CONTENT, B2SOpcode.FILE_WRITE_RESULT,
            B2SOpcode.BOF_OUTPUT, B2SOpcode.LIST_FILES_RESULT,
            B2SOpcode.KEY_ROTATE_ACK,
            B2SOpcode.FILE_DOWNLOAD_ACK, B2SOpcode.FILE_CHUNK_DATA,
            B2SOpcode.FILE_UPLOAD_ACK,
            B2SOpcode.RELAY_CHILD_UP,
        }

    if opcode not in valid_opcodes:
        return None, f"Bad opcode: 0x{opcode:02x}"

    # Ciphertext extraction
    cdef uint32_t payload_len_incl_mac = h.payload_len
    if data_view.shape[0] < HEADER_LEN + payload_len_incl_mac:
        return None, "Payload overflow"

    cdef const unsigned char[:] header_bytes = data_view[:HEADER_LEN]
    cdef const unsigned char[:] ciphertext_with_mac = data_view[HEADER_LEN:HEADER_LEN + payload_len_incl_mac]
    cdef const unsigned char[:] nonce_view = h.nonce

    # Decrypt and Unpad
    success, result = decrypt_payload(ciphertext_with_mac, nonce_view, key, header_bytes)
    if not success:
        return None, "Decryption failed"

    plaintext = pkcs7_unpad_c(result)

    return ParsedPacket(
        magic=h.magic,
        version=h.version,
        beacon_id=bytes(h.beacon_id[:8]),
        opcode=opcode,
        seq_num=h.seq_num,
        nonce=bytes(h.nonce[:24]),
        payload_len=len(plaintext),
        payload=plaintext
    ), ""

def serialize_response(
    unsigned char opcode,
    const unsigned char[:] beacon_id,
    uint32_t seq_num,
    const unsigned char[:] payload,
    const unsigned char[:] key,
    bint pad = True,
    unsigned int pad_max = 0
) -> bytes:
    import os
    import random

    if len(key) != 32 or len(beacon_id) != 8:
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        else:
            raise ValueError("Beacon ID must be 8 bytes")

    # 1. PKCS#7 padding logic (applied to plaintext before encryption)
    cdef bytes plaintext_bytes = bytes(payload)
    cdef unsigned char pad_val
    cdef unsigned int extra
    if pad:
        pad_val = 16 - (len(plaintext_bytes) % 16)
        plaintext_bytes += bytes([pad_val] * pad_val)
    if pad_max > len(plaintext_bytes):
        extra = (pad_max - len(plaintext_bytes)) // 16
        if extra > 0:
            for _ in range(random.randint(0, extra)):
                plaintext_bytes += bytes([16] * 16)

    cdef bytes nonce = os.urandom(24)
    cdef uint32_t actual_payload_len = len(plaintext_bytes) + MAC_LEN

    # 2. Header Construction (C-style)
    cdef PacketHeader h
    h.magic = PANDRAGON_MAGIC
    h.version = 0
    memcpy(h.beacon_id, &beacon_id[0], 8)
    h.opcode = opcode
    h.seq_num = seq_num
    memcpy(h.nonce, <unsigned char*>nonce, 24)
    h.payload_len = actual_payload_len

    cdef unsigned char header_arr[46]
    memcpy(header_arr, &h, sizeof(PacketHeader))
    cdef bytes header_bytes = bytes(header_arr[:HEADER_LEN])

    # 3. Encryption
    cipher = ChaCha20_Poly1305.new(key=bytes(key), nonce=nonce)
    cipher.update(header_bytes)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)

    return header_bytes + ciphertext + tag
