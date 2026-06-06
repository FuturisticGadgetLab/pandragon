"""
Transport Layer Base Classes

Abstract base classes defining the interface for all transport mechanisms.
This allows the teamserver to support multiple transport protocols (HTTP, TCP, DNS, etc.)
while maintaining a unified interface for beacon communication.

Architecture:
    ┌─────────────────────────────────────────┐
    │           Teamserver Core               │
    │  (Beacon Registry, Commands, etc.)      │
    └──────────────────┬──────────────────────┘
                       │
            ┌──────────▼──────────┐
            │  ITransportHandler  │  ← Callback interface
            └──────────┬──────────┘
                       │
    ┌──────────────────┼──────────────────────┐
    │                  │                      │
┌───▼──────┐   ┌──────▼──────┐      ┌────────▼────────┐
│  HTTP    │   │   TCP       │      │   DNS           │
│Transport │   │  Transport  │      │  Transport      │
└──────────┘   └─────────────┘      └─────────────────┘
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, Optional, Callable
import time


class TransportProtocol(Enum):
    """Supported transport protocols"""
    HTTP = auto()
    HTTPS = auto()
    WEBSOCKET = auto()
    TCP = auto()
    TLS_TCP = auto()
    DNS = auto()
    NAMED_PIPE = auto()
    CUSTOM = auto()


@dataclass
class TransportContext:
    """
    Context information about a transport connection.

    Provides metadata about the client connection that transports
    can provide to the handler.

    Attributes:
        client_id: Unique identifier for this connection/session
        remote_addr: Remote IP address or identifier
        protocol: Transport protocol being used
        metadata: Protocol-specific metadata (headers, DNS query info, etc.)
        created_at: When this context was created
    """
    client_id: str
    remote_addr: str
    protocol: TransportProtocol
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def get_meta(self, key: str, default: Any = None) -> Any:
        """Get metadata value safely"""
        return self.metadata.get(key, default)


@dataclass
class TransportMessage:
    """
    Normalized message format for all transports.

    All incoming beacon messages are converted to this format
    before being passed to the handler.

    Attributes:
        data: Raw message payload (bytes)
        context: Transport context with connection metadata
        message_id: Unique message identifier
        received_at: When message was received
    """
    data: bytes
    context: TransportContext
    message_id: str = ""
    received_at: float = field(default_factory=time.time)

    def __post_init__(self):
        if not self.message_id:
            import uuid
            self.message_id = str(uuid.uuid4())[:8]


@dataclass
class TransportResponse:
    """
    Response to send back via transport.

    Attributes:
        data: Response payload (bytes for query string, etc.)
        context: Transport context from request (for routing response)
        status_code: HTTP-like status code (200, 400, etc.)
        headers: Protocol-specific headers
        close_after: Whether to close connection after sending
    """
    data: bytes
    context: TransportContext
    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    close_after: bool = False


class ITransportHandler(ABC):
    """
    Abstract base class for transport handlers.

    The teamserver core implements this interface to receive
    messages from any transport mechanism.

    Transport implementations call these methods when messages arrive.
    """

    @abstractmethod
    async def on_message(self, message: TransportMessage) -> Optional[TransportResponse]:
        """
        Handle incoming message from transport.

        Called by transport when a complete message is received.

        Args:
            message: Normalized transport message

        Returns:
            Response to send back, or None for no response
        """
        pass

    @abstractmethod
    async def on_connect(self, context: TransportContext) -> None:
        """
        Handle new connection.

        Called when a new client connects (for connection-oriented transports).

        Args:
            context: Transport context for the new connection
        """
        pass

    @abstractmethod
    async def on_disconnect(self, context: TransportContext) -> None:
        """
        Handle client disconnect.

        Called when a client disconnects (for connection-oriented transports).

        Args:
            context: Transport context for the disconnected connection
        """
        pass

    @abstractmethod
    async def send_response(self, response: TransportResponse) -> bool:
        """
        Send response to client.

        Args:
            response: Response to send

        Returns:
            True if sent successfully, False otherwise
        """
        pass


class BaseTransport(ABC):
    """
    Abstract base class for transport implementations.

    Transport implementations inherit from this class and implement
    the protocol-specific logic for receiving and sending messages.

    Attributes:
        protocol: Transport protocol type
        handler: Callback handler for received messages
        running: Whether transport is actively listening
    """

    def __init__(self, protocol: TransportProtocol):
        """
        Initialize transport.

        Args:
            protocol: Transport protocol type
        """
        self.protocol = protocol
        self._handler: Optional[ITransportHandler] = None
        self._running = False

    @property
    def handler(self) -> Optional[ITransportHandler]:
        """Get registered handler"""
        return self._handler

    @property
    def is_running(self) -> bool:
        """Check if transport is running"""
        return self._running

    def set_handler(self, handler: ITransportHandler) -> None:
        """
        Set callback handler for received messages.

        Args:
            handler: Handler to call when messages arrive
        """
        self._handler = handler

    @abstractmethod
    async def start(self) -> None:
        """
        Start listening for incoming messages.

        Implementation should initialize protocol-specific listeners
        and set _running = True.
        """
        pass

    @abstractmethod
    async def stop(self) -> None:
        """
        Stop listening and cleanup resources.

        Implementation should close listeners and set _running = False.
        """
        pass

    @abstractmethod
    async def send(self, response: TransportResponse) -> bool:
        """
        Send response via this transport.

        Args:
            response: Response to send

        Returns:
            True if sent successfully, False otherwise
        """
        pass

    async def _notify_handler(
        self,
        data: bytes,
        context: TransportContext
    ) -> Optional[TransportResponse]:
        """
        Notify handler of received message.

        Internal method to call the registered handler.

        Args:
            data: Raw message data
            context: Transport context

        Returns:
            Response from handler, or None
        """
        if self._handler is None:
            return None

        message = TransportMessage(data=data, context=context)
        return await self._handler.on_message(message)
