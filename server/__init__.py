"""
Pandragon Teamserver Package

Modern C2 teamserver.
"""

__version__ = "1.0.0"
__author__ = "Serexp, Futuristic Gadgets Lab"

from .core.config import (
    load_config, get_config, setup_logging, get_logger,
    resolve_effective_listeners, get_primary_listener,
)

from .protocol import (
    PANDRAGON_MAGIC,
    HEADER_LEN,
    MAC_LEN,
    S2BOpcode,
    B2SOpcode,
    parse_packet,
    serialize_response,
    ParsedPacket,
)

from .security import (
    AuditLogger,
    LRUCache,
)

from .beacon import (
    BeaconSession,
    BeaconRegistry,
)

from .operators import (
    OperatorManager,
    OperatorSession,
)

from .transfers import (
    FileTransferManager,
    FileTransferSession,
)

from .persistence import (
    SessionManager,
)

from .transports import (
    TransportProtocol,
    TransportMessage,
    TransportResponse,
    TransportContext,
    TCPTransport,
    BeaconTransportHandler,
)


__all__ = [
    '__version__',
    '__author__',
    'load_config',
    'get_config',
    'setup_logging',
    'get_logger',
    'PANDRAGON_MAGIC',
    'HEADER_LEN',
    'MAC_LEN',
    'S2BOpcode',
    'B2SOpcode',
    'parse_packet',
    'serialize_response',
    'ParsedPacket',
    'AuditLogger',
    'LRUCache',
    'BeaconSession',
    'BeaconRegistry',
    'OperatorManager',
    'OperatorSession',
    'FileTransferManager',
    'FileTransferSession',
    'SessionManager',
    'TransportProtocol',
    'TransportMessage',
    'TransportResponse',
    'TransportContext',
    'TCPTransport',
    'BeaconTransportHandler',
]
