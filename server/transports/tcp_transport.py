"""
TCP Transport Implementation

TCP transport for beacon communication.
Supports plain TCP with length-prefixed framing.

Wire format (matches beacon tcp_socket.cpp):
    Beacon -> Server: [4-byte BE length][request body bytes]
    Server -> Beacon: [4-byte BE length][response body bytes]

The body is the same encrypted packet format used over HTTP
(base64-decoded for HTTP GET/POST, raw bytes for TCP).

Example:
    transport = TCPTransport(host='0.0.0.0', port=9090)
    transport.set_handler(teamserver)
    await transport.start()
"""

import asyncio
import logging
import struct
import uuid
from typing import Optional, Dict, Any

from .base import (
    BaseTransport,
    TransportProtocol,
    TransportContext,
    TransportResponse,
    TransportMessage,
)


logger = logging.getLogger('pandragon.transports.tcp')

# 4-byte big-endian length prefix
_LENGTH_FORMAT = '>I'
_LENGTH_SIZE = struct.calcsize(_LENGTH_FORMAT)

# Max frame size: 64MB (same cap as beacon side)
_MAX_FRAME_SIZE = 64 * 1024 * 1024


class TCPTransport(BaseTransport):
    """
    TCP transport for beacon communication.

    Listens for incoming TCP connections and reads length-prefixed frames.
    Each complete frame is passed to the handler as a TransportMessage.
    Responses are sent back as length-prefixed frames.
    """

    def __init__(
        self,
        host: str = '0.0.0.0',
        port: int = 9090,
        max_connections: int = 100,
        read_timeout: float = 30.0,
    ):
        """
        Initialize TCP transport.

        Args:
            host: Host to bind to
            port: Port to listen on
            max_connections: Maximum concurrent connections
            read_timeout: Read timeout in seconds per frame
        """
        super().__init__(TransportProtocol.TCP)

        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.read_timeout = read_timeout

        self._server: Optional[asyncio.Server] = None
        # Map client_id -> (reader, writer, context)
        self._connections: Dict[str, Dict[str, Any]] = {}

    async def start(self) -> None:
        """Start TCP server and begin listening for connections."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
        )

        self._running = True
        addr = self._server.sockets[0].getsockname()
        logger.info(f"TCP transport started on {addr[0]}:{addr[1]}")

    async def stop(self) -> None:
        """Stop TCP server and close all connections."""
        self._running = False

        # Close all client connections
        for conn_id, conn_info in list(self._connections.items()):
            try:
                writer = conn_info['writer']
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.error(f"Error closing connection {conn_id}: {e}")

        self._connections.clear()

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        logger.info("TCP transport stopped")

    async def send(self, response: TransportResponse) -> bool:
        """
        Send response to a specific client via stored StreamWriter.

        Args:
            response: Response with context containing the client_id

        Returns:
            True if sent successfully
        """
        client_id = response.context.client_id
        conn_info = self._connections.get(client_id)

        if not conn_info:
            logger.warning(f"TCP send: no connection for client_id={client_id}")
            return False

        try:
            writer = conn_info['writer']

            # Frame: [4-byte BE length][response data]
            data = response.data
            length_prefix = struct.pack(_LENGTH_FORMAT, len(data))
            writer.write(length_prefix + data)
            await writer.drain()

            logger.debug(f"TCP sent {len(data)} bytes to {client_id}")
            return True

        except (ConnectionError, asyncio.IncompleteReadError, BrokenPipeError) as e:
            logger.error(f"TCP send failed for {client_id}: {e}")
            # Connection is dead; remove it
            await self._remove_connection(client_id)
            return False
        except Exception as e:
            logger.error(f"TCP send unexpected error for {client_id}: {e}")
            return False

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handle individual TCP client connection.

        Reads length-prefixed frames and passes each complete frame
        to the registered handler.

        Args:
            reader: Async stream reader
            writer: Async stream writer
        """
        peer = writer.get_extra_info('peername')
        peer_addr = f"{peer[0]}:{peer[1]}" if peer else 'unknown'
        client_id = str(uuid.uuid4())[:8]

        context = TransportContext(
            client_id=client_id,
            remote_addr=peer_addr,
            protocol=TransportProtocol.TCP,
            metadata={
                'peer': peer,
                'local_port': self.port,
            },
        )

        # Store connection
        self._connections[client_id] = {
            'reader': reader,
            'writer': writer,
            'context': context,
        }

        logger.info(f"TCP connection from {peer_addr} (id={client_id})")

        # Notify handler of new connection
        if self._handler:
            try:
                await self._handler.on_connect(context)
            except Exception as e:
                logger.error(f"Handler on_connect error: {e}")

        try:
            # Read frames until connection closes
            while self._running:
                # Read 4-byte length prefix
                length_data = await asyncio.wait_for(
                    reader.readexactly(_LENGTH_SIZE),
                    timeout=self.read_timeout,
                )
                frame_length = struct.unpack(_LENGTH_FORMAT, length_data)[0]

                # Sanity check
                if frame_length == 0:
                    logger.debug(f"Zero-length frame from {client_id}, sending empty response")
                    # Send zero-length response frame
                    writer.write(struct.pack(_LENGTH_FORMAT, 0))
                    await writer.drain()
                    continue

                if frame_length > _MAX_FRAME_SIZE:
                    logger.warning(
                        f"Frame too large ({frame_length} bytes) from {client_id}, closing connection"
                    )
                    break

                # Read frame body
                body = await asyncio.wait_for(
                    reader.readexactly(frame_length),
                    timeout=self.read_timeout,
                )

                logger.debug(f"Received {frame_length} bytes from {client_id}")

                # Pass to handler
                if self._handler:
                    try:
                        response = await self._notify_handler(body, context)
                        if response:
                            # Send response as length-prefixed frame
                            resp_data = response.data
                            resp_len = struct.pack(_LENGTH_FORMAT, len(resp_data))
                            writer.write(resp_len + resp_data)
                            await writer.drain()
                    except Exception as e:
                        logger.error(f"Handler error for {client_id}: {e}")
                        # Send error response
                        error_data = struct.pack(_LENGTH_FORMAT, 0)
                        writer.write(error_data)
                        await writer.drain()

        except asyncio.IncompleteReadError:
            logger.info(f"Connection closed by {client_id} ({peer_addr})")
        except asyncio.TimeoutError:
            logger.info(f"Read timeout for {client_id} ({peer_addr})")
        except ConnectionResetError:
            logger.info(f"Connection reset by {client_id} ({peer_addr})")
        except Exception as e:
            logger.error(f"Unexpected error handling {client_id}: {e}")
        finally:
            await self._remove_connection(client_id)

    async def _remove_connection(self, client_id: str) -> None:
        """Remove connection from tracking and notify handler."""
        conn_info = self._connections.pop(client_id, None)
        if conn_info:
            try:
                writer = conn_info['writer']
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.warning(f"Error closing connection {client_id}: {e}")

            if self._handler:
                try:
                    await self._handler.on_disconnect(conn_info['context'])
                except Exception as e:
                    logger.error(f"Handler on_disconnect error: {e}")
