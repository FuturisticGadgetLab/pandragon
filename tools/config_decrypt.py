#!/usr/bin/env python3
"""
Pandragon Config Decrypt/Inspect Tool

Decrypts and inspects config blobs or generated C++ headers.
Supports XChaCha20-Poly1305 encrypted configs (v2) and legacy XOR (v1).

Usage:
    python config_decrypt.py include/generated_config.h
    python config_decrypt.py Beacon/config/default.bin
"""

import json
import struct
import sys
import os
import re
from datetime import datetime

# Import crypto from pycryptodome
# ChaCha20_Poly1305 supports XChaCha20 with 24-byte nonce
try:
    from Crypto.Cipher import ChaCha20_Poly1305
except ImportError:
    print("[!] Missing required dependency: pycryptodome")
    print("    pip install pycryptodome")
    sys.exit(1)

# Constants
PCFG_MAGIC = 0x50434647  # "PCFG"
PCFG_VERSION_XOR = 0x0001  # Legacy XOR obfuscation
PCFG_VERSION_XCHACHA = 0x0002  # XChaCha20-Poly1305 encryption
LEGACY_XOR_KEY = 0x5A  # Only for very old configs


def parse_cpp_header(filepath: str) -> tuple:
    """
    Extract config blob and decryption key from C++ header file.
    Returns: (blob, config_key, nonce)
    """
    with open(filepath, 'r') as f:
        content = f.read()

    # Find CONFIG_BLOB array
    blob_match = re.search(r'constexpr uint8_t CONFIG_BLOB\[\] = \{([^}]+)\}', content, re.DOTALL)
    if not blob_match:
        raise ValueError("Could not find CONFIG_BLOB in header")

    hex_str = blob_match.group(1)
    hex_values = re.findall(r'0x([0-9A-Fa-f]{2})', hex_str)
    blob = bytes(int(v, 16) for v in hex_values)

    # Try to find XChaCha20 key and nonce (v2 format)
    config_key = None
    nonce = None

    key_match = re.search(r'constexpr uint8_t CONFIG_DECRYPT_KEY\[\d*\] = \{([^}]+)\}', content, re.DOTALL)
    if key_match:
        hex_values = re.findall(r'0x([0-9A-Fa-f]{2})', key_match.group(1))
        config_key = bytes(int(v, 16) for v in hex_values)

    nonce_match = re.search(r'constexpr uint8_t CONFIG_NONCE\[\d*\] = \{([^}]+)\}', content, re.DOTALL)
    if nonce_match:
        hex_values = re.findall(r'0x([0-9A-Fa-f]{2})', nonce_match.group(1))
        nonce = bytes(int(v, 16) for v in hex_values)

    return blob, config_key, nonce


def load_binary_blob(filepath: str) -> bytes:
    """Load raw binary blob"""
    with open(filepath, 'rb') as f:
        return f.read()


def decrypt_blob(blob: bytes, config_key: bytes = None, nonce: bytes = None) -> dict:
    """
    Decrypt config blob.
    Supports both XChaCha20-Poly1305 (v2) and legacy XOR (v1).
    
    For v2: config_key and nonce must be provided
    For v1: uses legacy XOR key
    """
    if len(blob) < 20:
        raise ValueError("Blob too small")

    # Parse header
    # v1: magic(4) + version(2) + reserved(2) + length(4) + crc32(4) = 16 bytes
    # v2: magic(4) + version(2) + reserved(2) + nonce(24) + ciphertext_len(4) = 36 bytes
    
    magic, version = struct.unpack('<IH', blob[:6])

    if magic != PCFG_MAGIC:
        raise ValueError(f"Invalid magic: 0x{magic:08X} (expected 0x{PCFG_MAGIC:08X})")

    result = {
        'magic': magic,
        'version': version,
    }

    if version == PCFG_VERSION_XCHACHA:
        # XChaCha20-Poly1305 encrypted format (v2)
        if config_key is None or nonce is None:
            raise ValueError("XChaCha20 config requires CONFIG_DECRYPT_KEY and CONFIG_NONCE")

        # Header: magic(4) + version(2) + reserved(2) + nonce(24) + ciphertext_len(4) = 36 bytes
        if len(blob) < 36:
            raise ValueError("Blob too small for v2 header")

        header = blob[:36]
        _, _, _, nonce_from_header, ciphertext_len = struct.unpack('<IHH24sI', header)

        # Verify nonce matches
        if nonce != nonce_from_header:
            print(f"[!] Warning: Nonce mismatch - using provided nonce")

        # Extract ciphertext and MAC
        ciphertext = blob[36:36 + ciphertext_len]
        mac = blob[36 + ciphertext_len:36 + ciphertext_len + 16]

        if len(ciphertext) < ciphertext_len:
            raise ValueError(f"Ciphertext truncated: expected {ciphertext_len}, got {len(ciphertext)}")

        # Decrypt with XChaCha20-Poly1305
        try:
            cipher = ChaCha20_Poly1305.new(key=config_key, nonce=nonce)
            cipher.update(b'')  # No associated data
            plaintext = cipher.decrypt_and_verify(ciphertext, mac)
            result['payload'] = plaintext
            result['encrypted'] = True
            result['encryption_method'] = 'XChaCha20-Poly1305'
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

    elif version == PCFG_VERSION_XOR:
        # Legacy XOR obfuscated format (v1)
        if len(blob) < 16:
            raise ValueError("Blob too small for v1 header")

        header = blob[:16]
        _, _, _, length, crc32_val = struct.unpack('<IHHII', header)

        # Decrypt payload (XOR)
        payload_encrypted = blob[16:]
        payload = bytearray(payload_encrypted)
        for i in range(len(payload)):
            payload[i] ^= LEGACY_XOR_KEY

        # Verify CRC
        import zlib
        computed_crc = zlib.crc32(payload) & 0xFFFFFFFF
        result['crc32'] = crc32_val
        result['crc_computed'] = computed_crc
        result['crc_valid'] = (computed_crc == crc32_val)
        result['payload'] = bytes(payload)
        result['encrypted'] = False
        result['encryption_method'] = 'XOR (legacy)'

    else:
        raise ValueError(f"Unknown config version: 0x{version:04X}")

    return result


def _parse_malleable_block(payload: bytes, offset: int, payload_len: int):
    """Parse a malleable config block from payload at given offset.
    Returns (malleable_dict, bytes_consumed) or None on failure.
    """
    start = offset
    if offset + 2 > payload_len:
        return None

    prefix_len = payload[offset]
    offset += 1
    prefix = payload[offset:offset+prefix_len].decode('utf-8', errors='replace') if prefix_len else ''
    offset += prefix_len

    suffix_len = payload[offset]
    offset += 1
    suffix = payload[offset:offset+suffix_len].decode('utf-8', errors='replace') if suffix_len else ''
    offset += suffix_len

    # HTTP headers
    if offset >= payload_len:
        return None
    header_count = payload[offset]
    offset += 1

    headers = []
    for _ in range(header_count):
        if offset + 2 > payload_len:
            break
        name_len = payload[offset]
        offset += 1
        value_len = payload[offset]
        offset += 1
        name = payload[offset:offset+name_len].decode('utf-8', errors='replace')
        offset += name_len
        value = payload[offset:offset+value_len].decode('utf-8', errors='replace')
        offset += value_len
        headers.append({'name': name, 'value': value})

    # Payload location
    if offset >= payload_len:
        return None
    loc_type = payload[offset]
    offset += 1
    loc_types = ['query_param', 'path', 'body']
    loc_type_str = loc_types[loc_type] if loc_type < 3 else 'unknown'

    param_name_len = payload[offset] if offset < payload_len else 0
    offset += 1
    param_name = payload[offset:offset+param_name_len].decode('utf-8', errors='replace') if param_name_len else ''
    offset += param_name_len

    path_prefix_len = payload[offset] if offset < payload_len else 0
    offset += 1
    path_prefix = payload[offset:offset+path_prefix_len].decode('utf-8', errors='replace') if path_prefix_len else ''
    offset += path_prefix_len

    path_suffix_len = payload[offset] if offset < payload_len else 0
    offset += 1
    path_suffix = payload[offset:offset+path_suffix_len].decode('utf-8', errors='replace') if path_suffix_len else ''
    offset += path_suffix_len

    body_ct = payload[offset] if offset < payload_len else 0
    offset += 1
    body_cts = ['text/plain', 'application/octet-stream']
    body_ct_str = body_cts[body_ct] if body_ct < 2 else 'unknown'

    malleable = {
        'wrapper': {'prefix': prefix, 'suffix': suffix},
        'http_headers': headers,
        'payload_location': {
            'type': loc_type_str,
            'param_name': param_name,
            'path_prefix': path_prefix,
            'path_suffix': path_suffix,
            'body_content_type': body_ct_str,
        }
    }
    return (malleable, offset - start)


def parse_payload(payload: bytes) -> dict:
    """Parse decrypted v2 config payload"""
    if len(payload) < 45:
        raise ValueError("Payload too small")
    
    offset = 0
    
    # === Beacon ID (8 bytes) ===
    beacon_id = payload[offset:offset+8].hex()
    offset += 8
    
    # === Crypto key (32 bytes) ===
    crypto_key = payload[offset:offset+32].hex()
    offset += 32
    
    # === Channel count (1 byte) ===
    channel_count = payload[offset]
    offset += 1
    
    # === Parse C2 channels ===
    channels = []
    for ch_idx in range(channel_count):
        if offset + 14 > len(payload):
            break

        ch_type = payload[offset]
        http_method = payload[offset + 1]
        host_len = payload[offset + 2]
        path_len = payload[offset + 3]
        ua_len = payload[offset + 4]
        # reserved = payload[offset + 5]
        port = payload[offset + 6] | (payload[offset + 7] << 8)
        max_failures = payload[offset + 8]
        backoff_ms = (payload[offset + 9] | (payload[offset + 10] << 8) |
                      (payload[offset + 11] << 16) | (payload[offset + 12] << 24))
        offset += 13

        # Read strings
        host = payload[offset:offset+host_len].decode('utf-8', errors='replace')
        offset += host_len

        path = payload[offset:offset+path_len].decode('utf-8', errors='replace')
        offset += path_len

        ua = payload[offset:offset+ua_len].decode('utf-8', errors='replace')
        offset += ua_len

        # Read malleable_mode byte
        if offset >= len(payload):
            break
        malleable_mode = payload[offset]
        offset += 1

        type_str = "HTTP" if ch_type == 1 else "HTTPS" if ch_type == 2 else "TCP" if ch_type == 3 else "PIPE" if ch_type == 4 else "UNKNOWN"
        mode_str = "GLOBAL" if malleable_mode == 0x00 else "INLINE" if malleable_mode == 0x01 else "NONE"
        method_str = "POST" if http_method == 1 else "GET"

        channel_info = {
            'type': type_str,
            'host': host,
            'port': port,
            'path': path,
            'user_agent': ua,
            'http_method': method_str,
            'max_consecutive_failures': max_failures,
            'backoff_sleep_ms': backoff_ms,
            'malleable_mode': f"0x{malleable_mode:02x} ({mode_str})"
        }

        # Parse inline malleable if present
        if malleable_mode == 0x01:
            ch_malleable = _parse_malleable_block(payload, offset, len(payload))
            if ch_malleable:
                channel_info['malleable_config'] = ch_malleable[0]
                offset += ch_malleable[1]

        channels.append(channel_info)

    # === Sleep ms (4 bytes) ===
    sleep_ms = payload[offset] | (payload[offset + 1] << 8) | \
               (payload[offset + 2] << 16) | (payload[offset + 3] << 24)
    offset += 4

    # === Jitter pct (1 byte) ===
    jitter_pct = payload[offset]
    offset += 1

    # === Kill date (4 bytes) ===
    kill_date = payload[offset] | (payload[offset + 1] << 8) | \
                (payload[offset + 2] << 16) | (payload[offset + 3] << 24)
    offset += 4

    # === Options (2 bytes) ===
    options_val = payload[offset] | (payload[offset + 1] << 8)
    offset += 2

    options = {
        'sandbox_evasion': bool(options_val & 0x0001),
        'debug_mode': bool(options_val & 0x0002),
        'kill_date_set': bool(options_val & 0x0004),
        'validate_ssl': bool(options_val & 0x0008),
        'bypass_etw': bool(options_val & 0x0010),
        'use_indirect_syscalls': bool(options_val & 0x0020),
        'lazy_checkin': bool(options_val & 0x0040),
        'lazy_unhook': bool(options_val & 0x0080),
        'sleep_obfuscation': ['none', 'ekko', 'foliage', 'reserved'][(options_val >> 8) & 3],
        'sleep_wipe_pe_headers': bool(options_val & 0x0400),
        'sleep_stack_spoof': bool(options_val & 0x0800),
        'pad': bool(options_val & 0x1000),
        'indirect_pivot_set': False,
    }

    # === Lazy check-in max (1 byte) ===
    lazy_checkin_max = payload[offset] if offset < len(payload) else 0
    offset += 1

    # === Indirect pivot len (1 byte) ===
    indirect_pivot_len = payload[offset] if offset < len(payload) else 0
    offset += 1

    # === Indirect pivot (variable) ===
    indirect_pivot = None
    if indirect_pivot_len > 0 and offset + indirect_pivot_len <= len(payload):
        indirect_pivot = payload[offset:offset+indirect_pivot_len].decode('utf-8', errors='replace')
        offset += indirect_pivot_len
        options['indirect_pivot_set'] = True

    # === Pad max (2 bytes) ===
    pad_max = 0
    if offset + 2 <= len(payload):
        pad_max = payload[offset] | (payload[offset + 1] << 8)
        offset += 2

    # === Num spoof frames (2 bytes) ===
    num_spoof_frames = 0
    if offset + 2 <= len(payload):
        num_spoof_frames = payload[offset] | (payload[offset + 1] << 8)
        offset += 2

    # === SpawnTo x64 (len + string) ===
    spawnto_x64 = None
    spawnto_x64_len = 0
    if offset < len(payload):
        spawnto_x64_len = payload[offset]
        offset += 1
        if spawnto_x64_len > 0 and offset + spawnto_x64_len <= len(payload):
            spawnto_x64 = payload[offset:offset+spawnto_x64_len].decode('utf-8', errors='replace')
            offset += spawnto_x64_len

    # === SpawnTo x86 (len + string) ===
    spawnto_x86 = None
    spawnto_x86_len = 0
    if offset < len(payload):
        spawnto_x86_len = payload[offset]
        offset += 1
        if spawnto_x86_len > 0 and offset + spawnto_x86_len <= len(payload):
            spawnto_x86 = payload[offset:offset+spawnto_x86_len].decode('utf-8', errors='replace')
            offset += spawnto_x86_len

    # === Has global malleable (1 byte) ===
    global_malleable = None
    has_malleable_config = False
    if offset < len(payload):
        has_global = payload[offset]
        offset += 1
        if has_global == 0x01:
            has_malleable_config = True
            result = _parse_malleable_block(payload, offset, len(payload))
            if result:
                global_malleable = result[0]
                offset += result[1]

    # === Work Hours (6 bytes) ===
    work_hours = {
        'enabled': False,
        'start_hour': 9,
        'start_minute': 0,
        'end_hour': 17,
        'end_minute': 0,
        'insomnia': False
    }
    if offset + 6 <= len(payload):
        work_hours['enabled'] = bool(payload[offset])
        work_hours['start_hour'] = payload[offset + 1]
        work_hours['start_minute'] = payload[offset + 2]
        work_hours['end_hour'] = payload[offset + 3]
        work_hours['end_minute'] = payload[offset + 4]
        work_hours['insomnia'] = bool(payload[offset + 5])
        offset += 6

    # === Stack spoof chain (2 byte count + per-entry module/func pairs) ===
    stack_chain = []
    if offset + 2 <= len(payload):
        chain_count = payload[offset] | (payload[offset + 1] << 8)
        offset += 2
        for _ in range(chain_count):
            if offset + 6 > len(payload):
                break
            off = payload[offset] | (payload[offset + 1] << 8) | \
                  (payload[offset + 2] << 16) | (payload[offset + 3] << 24)
            offset += 4
            mod_len = payload[offset]
            offset += 1
            module = payload[offset:offset + mod_len].decode('utf-8', errors='replace') if mod_len else ''
            offset += mod_len
            fn_len = payload[offset]
            offset += 1
            function = payload[offset:offset + fn_len].decode('utf-8', errors='replace') if fn_len else ''
            offset += fn_len
            stack_chain.append({'module': module, 'function': function, 'offset': off})

    # Convert kill date
    kill_date_str = None
    if kill_date and options['kill_date_set']:
        try:
            kill_date_str = datetime.fromtimestamp(kill_date).isoformat()
        except (OSError, ValueError):
            kill_date_str = str(kill_date)

    return {
        'beacon_id': beacon_id,
        'crypto_key': crypto_key,
        'c2_channels': channels,
        'sleep_ms': sleep_ms,
        'jitter_pct': jitter_pct,
        'kill_date': kill_date_str,
        'lazy_checkin_max': lazy_checkin_max,
        'indirect_pivot': indirect_pivot,
        'pad_max': pad_max,
        'num_spoof_frames': num_spoof_frames,
        'spawnto_x64': spawnto_x64,
        'spawnto_x86': spawnto_x86,
        'stack_spoof_chain': stack_chain,
        'options': options,
        'has_malleable_config': has_malleable_config,
        'global_malleable': global_malleable,
        'work_hours': work_hours
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python config_decrypt.py <config.h|config.bin>")
        sys.exit(1)

    filepath = sys.argv[1]

    # Load blob
    print(f"[*] Loading: {filepath}")
    try:
        if filepath.endswith('.h'):
            blob, config_key, nonce = parse_cpp_header(filepath)
        else:
            blob = load_binary_blob(filepath)
            config_key = None
            nonce = None
    except Exception as e:
        print(f"[!] Failed to load: {e}")
        sys.exit(1)

    print(f"[+] Loaded {len(blob)} bytes")

    # Decrypt and parse
    try:
        result = decrypt_blob(blob, config_key, nonce)
        config = parse_payload(result['payload'])
    except Exception as e:
        print(f"[!] Failed to parse: {e}")
        sys.exit(1)

    # Print results
    print("\n" + "=" * 60)
    print("CONFIG BLOB INFO")
    print("=" * 60)
    print(f"Magic:         0x{result['magic']:08X} ({'VALID' if result['magic'] == PCFG_MAGIC else 'INVALID'})")
    print(f"Version:       {result['version']}")
    print(f"Encryption:    {result.get('encryption_method', 'Unknown')}")
    
    if result['version'] == PCFG_VERSION_XCHACHA:
        print(f"Encrypted:     Yes (XChaCha20-Poly1305)")
    elif result['version'] == PCFG_VERSION_XOR:
        print(f"Encrypted:     No (XOR obfuscation only)")
        print(f"CRC32:         0x{result.get('crc32', 0):08X} ({'VALID' if result.get('crc_valid', False) else 'INVALID'})")

    print("\n" + "=" * 60)
    print("BEACON CONFIG")
    print("=" * 60)
    print(f"Beacon ID:     {config['beacon_id']}")
    print(f"Crypto Key:    {config['crypto_key']}")
    print(f"Sleep:         {config['sleep_ms']}ms (+{config['jitter_pct']}% jitter)")

    if config['kill_date']:
        print(f"Kill Date:     {config['kill_date']}")

    if config.get('indirect_pivot'):
        print(f"Indirect Pivot: {config['indirect_pivot']}")

    if config.get('pad_max', 0) > 0:
        print(f"Pad Max:       {config['pad_max']} bytes")

    nsf = config.get('num_spoof_frames', 0)
    if nsf > 0:
        print(f"Spoof Frames:  {nsf} frames")

    if config.get('spawnto_x64'):
        print(f"SpawnTo x64:   {config['spawnto_x64']}")
    if config.get('spawnto_x86'):
        print(f"SpawnTo x86:   {config['spawnto_x86']}")

    if config.get('lazy_checkin_max', 0) > 0:
        print(f"Lazy Checkin:  max={config['lazy_checkin_max']}")

    chain = config.get('stack_spoof_chain', [])
    if chain:
        print(f"\nStack Spoof Chain ({len(chain)} entries):")
        for entry in chain:
            off = entry.get('offset', 0)
            if off:
                print(f"  {entry['module']}!{entry['function']}+0x{off:X}")
            else:
                print(f"  {entry['module']}!{entry['function']} (scan)")

    print(f"\nOptions:")
    opts = config['options']
    for k, v in opts.items():
        print(f"  - {k}: {v}")

    wh = config.get('work_hours', {})
    if wh.get('enabled'):
        print(f"\nWork Hours:")
        print(f"  - Time:      {wh['start_hour']:02d}:{wh['start_minute']:02d} - {wh['end_hour']:02d}:{wh['end_minute']:02d}")
        print(f"  - Insomnia: {wh['insomnia']}")

    print(f"\nC2 Channels ({len(config['c2_channels'])}):")
    for i, ch in enumerate(config['c2_channels']):
        print(f"  [{i}] {ch['type']} {ch['host']}:{ch['port']}{ch['path']} (HTTP: {ch['http_method']})")
        print(f"      UA: {ch['user_agent']}")
        print(f"      Failures: {ch['max_consecutive_failures']}, Backoff: {ch['backoff_sleep_ms']}ms")
        print(f"      Malleable: {ch['malleable_mode']}")
        if 'malleable_config' in ch:
            mcfg = ch['malleable_config']
            w = mcfg.get('wrapper', {})
            if w.get('prefix') or w.get('suffix'):
                print(f"      Wrapper: prefix='{w.get('prefix','')}' suffix='{w.get('suffix','')}'")
            hdrs = mcfg.get('http_headers', [])
            if hdrs:
                print(f"      Headers: {len(hdrs)}")
                for h in hdrs:
                    print(f"        {h['name']}: {h['value']}")

    # Global malleable
    gm = config.get('global_malleable')
    if gm:
        print(f"\nGlobal Malleable Config:")
        w = gm.get('wrapper', {})
        if w.get('prefix') or w.get('suffix'):
            print(f"  Wrapper: prefix='{w.get('prefix','')}' suffix='{w.get('suffix','')}'")
        hdrs = gm.get('http_headers', [])
        if hdrs:
            print(f"  Headers: {len(hdrs)}")
            for h in hdrs:
                print(f"    {h['name']}: {h['value']}")
        loc = gm.get('payload_location', {})
        print(f"  Location: {loc.get('type', 'unknown')}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
