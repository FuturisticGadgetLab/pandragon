#!/usr/bin/env python3
"""
Pandragon Teamserver Entry Point (aiohttp)
"""

import sys
import os
import time
import asyncio
import logging
import argparse
import signal

sys.path.insert(0, os.path.dirname(__file__))

from aiohttp import web

from core.config import (
    load_config, setup_logging, get_logger,
    resolve_effective_listeners, get_primary_listener,
)
from core.context import ApplicationContext
from handlers.operator_ws import handle_operator_ws


logger = None
_show_beacon_content = False
_start_time = 0.0


async def _start_extra_http_listener(listener, beacon_app):
    """Start a single non-primary HTTP/S listener."""
    name = listener['name']
    host = listener['host']
    port = listener['port']
    protocol = listener['protocol']

    ssl_context = None
    if protocol == 'https':
        import ssl
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(listener['ssl_cert'], listener['ssl_key'])

    runner = web.AppRunner(beacon_app)
    await runner.setup()
    site = web.TCPSite(runner, host, port, ssl_context=ssl_context)
    await site.start()
    logger.info(f"Extra listener '{name}' ready on {protocol.upper()} {host}:{port}")
    return runner


async def _start_tcp_listeners(tcp_listener_configs, ctx):
    """Start TCP listeners."""
    from transports import TCPTransport
    if not tcp_listener_configs:
        return []
    tcp_servers = []
    for listener in tcp_listener_configs:
        name = listener['name']
        host = listener['host']
        port = listener['port']
        transport = TCPTransport(host=host, port=port)
        transport.set_handler(ctx.beacon_handler)
        task = asyncio.create_task(transport.start())
        tcp_servers.append((transport, name, task))
        logger.info(f"TCP listener '{name}' ready on {host}:{port}")
    return tcp_servers


def _create_operator(args):
    """Create a new operator and save to credentials file."""
    from operators.manager import OperatorManager
    cred_file = os.path.join(args.data_dir or '.', args.cred_file or 'operators.json')
    mgr = OperatorManager(cred_file=cred_file)
    token = args.token or None
    op = mgr.create_operator(args.username, token=token)
    print(f"Operator created:")
    print(f"  Username: {op.username}")
    print(f"  Token:    {op.token}")
    print(f"  File:     {cred_file}")


def main():
    """Main entry point."""
    global logger, _show_beacon_content, _start_time

    parser = argparse.ArgumentParser(
        description="Pandragon Teamserver v2.0 (aiohttp)",
        add_help=True
    )
    sub = parser.add_subparsers(dest='command')

    create_parser = sub.add_parser('create', help='Create a new operator')
    create_parser.add_argument('username', type=str, help='Operator username')
    create_parser.add_argument('--token', type=str, default=None,
                               help='Token (64 hex chars; auto-generated if omitted)')
    create_parser.add_argument('--cred-file', type=str, default='operators.json',
                               help='Credentials file (default: operators.json)')

    parser.add_argument('--config', type=str, default=None,
                        help='Path to config file')
    parser.add_argument('--data-dir', type=str, default=None,
                        help='Data directory (default: current directory)')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Enable verbose debug logging')
    parser.add_argument('--debug-content', action='store_true', default=False,
                        help='Print decoded beacon content to console')
    args = parser.parse_args()

    if args.command == 'create':
        _create_operator(args)
        return

    if args.debug:
        os.environ['PANDRAGON_DEBUG'] = '1'
    _show_beacon_content = args.debug_content
    if args.data_dir:
        os.chdir(args.data_dir)

    config = load_config(config_path=args.config)
    logger = setup_logging()
    _start_time = time.time()

    logger.info("=" * 60)
    logger.info("Pandragon Teamserver v2.0 (aiohttp)")
    logger.info("=" * 60)
    if _show_beacon_content:
        logger.info("  - Beacon content debugging: ENABLED")
    logger.info("=" * 60)

    ctx = ApplicationContext(config)

    # Build the operator app (always has the WebSocket endpoint)
    operator_app = web.Application()
    operator_app['ctx'] = ctx
    operator_app['_start_time'] = _start_time

    operator_ws_path = config.get('operator_routes', {}).get('websocket', {}).get('path', '/ws')
    operator_app.router.add_get(operator_ws_path, handle_operator_ws)
    logger.info(f"Operator WebSocket endpoint: {operator_ws_path}")

    # Build the beacon-only app (HTTP route handlers)
    beacon_app = web.Application()
    beacon_app['ctx'] = ctx
    ctx.beacon_app = beacon_app

    for beacon_path in ctx.beacon_registry.get_http_paths():
        if beacon_path:
            beacon_app.router.add_route('GET', f"/{beacon_path}", ctx.http_transport.handle_request)
            beacon_app.router.add_route('POST', f"/{beacon_path}", ctx.http_transport.handle_request)

    if not ctx.beacon_registry.get_http_paths():
        logger.error("No beacon routes registered, no known beacons loaded or all lack HTTP routes")
        exit(1) # we don't support this scenario since the teamserver is designed around listeners

    listeners = resolve_effective_listeners()
    primary = get_primary_listener()
    tcp_listeners = [l for l in listeners if l['protocol'] == 'tcp']
    http_listeners = [l for l in listeners if l['protocol'] in ('http', 'https')]

    logger.info(f"Starting {len(listeners)} listener(s)")
    for l in listeners:
        proto_label = l['protocol'].upper()
        primary_label = " [PRIMARY]" if l['primary'] else ""
        beacon_label = " beacon" if l['beacon_enabled'] else ""
        logger.info(f"  [{l['name']}] {proto_label} {l['host']}:{l['port']}{primary_label}{beacon_label}")
        if l['protocol'] == 'https':
            logger.info(f"    SSL: cert={l['ssl_cert']}, key={l['ssl_key']}")

    async def start_all():
        nonlocal primary

        await ctx.task_queue.start(
            task_callback=ctx._on_task,
            completion_callback=ctx._on_complete
        )
        logger.info("Task queue scheduler started")

        # ── Decide which app the primary uses ────────────────────────
        primary_beacon_enabled = primary.get('beacon_enabled', True)
        if primary_beacon_enabled:
            # Add beacon routes to the operator app
            for beacon_path in ctx.beacon_registry.get_http_paths():
                if beacon_path:
                    operator_app.router.add_route(
                        'GET', f"/{beacon_path}", ctx.http_transport.handle_request,
                    )
                    operator_app.router.add_route(
                        'POST', f"/{beacon_path}", ctx.http_transport.handle_request,
                    )

        # ── Start extra HTTP/S listeners ────────────────────────────
        extra_runners = []
        for listener in http_listeners:
            if listener['primary']:
                continue
            if not listener.get('beacon_enabled', True):
                logger.info(f"  Skipping '{listener['name']}': beacon_enabled=false")
                continue
            runner = await _start_extra_http_listener(listener, beacon_app)
            extra_runners.append(runner)

        # ── Start TCP listeners ─────────────────────────────────────
        tcp_transports = await _start_tcp_listeners(tcp_listeners, ctx)

        # ── Start primary listener ──────────────────────────────────
        ssl_context = None
        if primary['protocol'] == 'https':
            import ssl
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(primary['ssl_cert'], primary['ssl_key'])
            logger.info(f"Primary listener: HTTPS {primary['host']}:{primary['port']} "
                        f"(WebSocket{' + beacon' if primary_beacon_enabled else ''})")
        else:
            logger.info(f"Primary listener: HTTP {primary['host']}:{primary['port']} "
                        f"(WebSocket{' + beacon' if primary_beacon_enabled else ''}, NO TLS)")

        primary_runner = web.AppRunner(operator_app)
        await primary_runner.setup()
        site = web.TCPSite(primary_runner, primary['host'], primary['port'], ssl_context=ssl_context)
        await site.start()
        logger.info(f"Pandragon teamserver running on {primary['protocol'].upper()} {primary['host']}:{primary['port']}")

        # ── Wait for shutdown ────────────────────────────────────────
        shutdown_event = asyncio.Event()

        def _signal_handler():
            logger.info("Received signal, shutting down...")
            shutdown_event.set()

        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, _signal_handler)
            except NotImplementedError:
                pass

        try:
            await shutdown_event.wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            logger.info("Shutting down...")

        # ── Drain operator WebSockets ───────────────────────────────
        if ctx.operator_sockets:
            logger.info(f"Draining {len(ctx.operator_sockets)} operator connection(s)...")
            dead = []
            for ws in ctx.operator_sockets:
                try:
                    await ws.send_json({'type': 'shutdown'})
                    await ws.close(code=1001, message=b'server shutdown')
                except Exception:
                    dead.append(ws)
            for ws in dead:
                ctx.operator_sockets.discard(ws)

        # ── Cleanup all runners, TCP transports ─────────────────────
        await primary_runner.cleanup()
        for runner in extra_runners:
            await runner.cleanup()
        for transport, name, task in tcp_transports:
            await transport.stop()
        await ctx.task_queue.stop()
        logger.info("Shutdown complete")

    try:
        asyncio.run(start_all())
    except KeyboardInterrupt:
        logger.info("Shutdown complete")


if __name__ == "__main__":
    main()
