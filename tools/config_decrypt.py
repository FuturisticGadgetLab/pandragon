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

    # Magic is per-build randomized; just record it
    # No validation against a constant since it's unique per build

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
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        if crc != crc32_val:
            raise ValueError(f"CRC mismatch: expected 0x{crc32_val:08X}, got 0x{crc:08X}")

        result['payload'] = bytes(payload)
        result['encrypted'] = False
        result['encryption_method'] = 'XOR (legacy)'

    else:
        raise ValueError(f"Unknown config version: {version}")

    return result


def _parse_malleable_block(payload: bytes, offset: int) -> tuple:
    """Parse a malleable config block from payload at given offset.
    Returns (malleable_dict, bytes_consumed)
    """
    if offset + 6 > len(payload):
        raise ValueError("Payload too small for malleable header")

    start = offset

    # Wrapper prefix (uint16_t LE)
    prefix_len = payload[offset] | (payload[offset + 1] << 8)
    offset += 2
    wrapper_prefix = payload[offset:offset + prefix_len].decode('utf-8') if prefix_len > 0 else ""
    offset += prefix_len

    # Wrapper suffix (uint16_t LE)
    suffix_len = payload[offset] | (payload[offset + 1] << 8)
    offset += 2
    wrapper_suffix = payload[offset:offset + suffix_len].decode('utf-8') if suffix_len > 0 else ""
    offset += suffix_len

    # HTTP headers (count)
    num_headers = payload[offset]
    offset += 1
    headers = []
    for _ in range(num_headers):
        if offset + 2 > len(payload):
            raise ValueError("Payload too small for header count")
        name_len = payload[offset]
        value_len = payload[offset + 1]
        offset += 2

        if offset + name_len + value_len > len(payload):
            raise ValueError("Payload too small for header data")
        header_name = payload[offset:offset + name_len].decode('utf-8')
        offset += name_len
        header_value = payload[offset:offset + value_len].decode('utf-8')
        offset += value_len
        headers.append({'name': header_name, 'value': header_value})

    # Payload location
    if offset >= len(payload):
        raise ValueError("Payload too small for payload location")
    loc_type = payload[offset]
    offset += 1

    loc_type_str = {0: 'query_param', 1: 'path', 2: 'body'}.get(loc_type, 'unknown')

    # Param name
    pn_len = payload[offset]
    offset += 1
    param_name = payload[offset:offset + pn_len].decode('utf-8') if pn_len > 0 else ""
    offset += pn_len

    # Path prefix
    pp_len = payload[offset]
    offset += 1
    path_prefix = payload[offset:offset + pp_len].decode('utf-8') if pp_len > 0 else ""
    offset += pp_len

    # Path suffix
    ps_len = payload[offset]
    offset += 1
    path_suffix = payload[offset:offset + ps_len].decode('utf-8') if ps_len > 0 else ""
    offset += ps_len

    # Body content type
    if offset >= len(payload):
        raise ValueError("Payload too small for body content type")
    body_ct = payload[offset]
    offset += 1
    body_ct_str = {0: 'text/plain', 1: 'application/octet-stream'}.get(body_ct, 'text/plain')

    # Cookie name (optional)
    cookie_name = ""
    if offset < len(payload):
        cn_len = payload[offset]
        offset += 1
        if cn_len > 0:
            if offset + cn_len > len(payload):
                raise ValueError("Payload too small for cookie_name data")
            cookie_name = payload[offset:offset + cn_len].decode('utf-8')
            offset += cn_len

    malleable = {
        'wrapper': {'prefix': wrapper_prefix, 'suffix': wrapper_suffix},
        'http_headers': headers,
        'payload_location': {
            'type': loc_type_str,
            'param_name': param_name,
            'path_prefix': path_prefix,
            'path_suffix': path_suffix,
            'body_content_type': body_ct_str,
            'cookie_name': cookie_name,
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
            raise ValueError("Payload too small for channel header")

        # Channel header: type(1) + http_method(1) + host_len(1) + path_len(1) + ua_len(1) + reserved(1) + port(2) + max_failures(1) + backoff_ms(4)
        ch_type = payload[offset]
        http_method = payload[offset + 1]
        host_len = payload[offset + 2]
        path_len = payload[offset + 3]
        ua_len = payload[offset + 4]
        # reserved = offset + 5
        port = payload[offset + 6] | (payload[offset + 7] << 8)
        max_failures = payload[offset + 8]
        backoff_ms = payload[offset + 9] | (payload[offset + 10] << 8) | (payload[offset + 11] << 16) | (payload[offset + 12] << 24)
        offset += 13

        # Read strings
        if offset + host_len + path_len + ua_len > len(payload):
            raise ValueError("Payload too small for channel strings")

        host = payload[offset:offset + host_len].decode('utf-8')
        offset += host_len
        path = payload[offset:offset + path_len].decode('utf-8')
        offset += path_len
        user_agent = payload[offset:offset + ua_len].decode('utf-8')
        offset += ua_len

        # Malleable mode
        malleable_mode = payload[offset]
        offset += 1

        channel = {
            'type': {1: 'HTTP', 2: 'HTTPS', 3: 'TCP', 4: 'PIPE'}.get(ch_type, 'UNKNOWN'),
            'http_method': 'POST' if http_method else 'GET',
            'host': host,
            'port': port,
            'path': path,
            'user_agent': user_agent,
            'max_consecutive_failures': max_failures,
            'backoff_sleep_ms': backoff_ms,
            'malleable_mode': {0: 'global', 1: 'inline', 255: 'none'}.get(malleable_mode, 'unknown'),
        }

        if malleable_mode == 1 and offset + 2 <= len(payload):
            malleable, consumed = _parse_malleable_block(payload, offset)
            channel['malleable_config'] = malleable
            offset += consumed

        # Response malleable mode
        if offset >= len(payload):
            raise ValueError("Payload too small for response malleable mode")
        response_malleable_mode = payload[offset]
        offset += 1
        channel['response_malleable_mode'] = {0: 'global', 1: 'inline', 255: 'none'}.get(response_malleable_mode, 'unknown')

        if response_malleable_mode == 1 and offset + 2 <= len(payload):
            resp_malleable, consumed = _parse_malleable_block(payload, offset)
            channel['response_malleable_config'] = resp_malleable
            offset += consumed

        channels.append(channel)

    # --- Global malleable config ---
    if offset >= len(payload):
        raise ValueError("Payload too small for global malleable flag")
    has_global_malleable = payload[offset]
    offset += 1

    global_malleable = None
    if has_global_malleable == 1:
        global_malleable, consumed = _parse_malleable_block(payload, offset)
        offset += consumed

    # --- Global response malleable config ---
    if offset >= len(payload):
        raise ValueError("Payload too small for global response malleable flag")
    has_global_response_malleable = payload[offset]
    offset += 1

    global_response_malleable = None
    if has_global_response_malleable == 1:
        global_response_malleable, consumed = _parse_malleable_block(payload, offset)
        offset += consumed

    # --- Work hours ---
    if offset + 6 > len(payload):
        raise ValueError("Payload too small for work hours")
    work_hours = {
        'enabled': bool(payload[offset]),
        'start_hour': payload[offset + 1],
        'start_minute': payload[offset + 2],
        'end_hour': payload[offset + 3],
        'end_minute': payload[offset + 4],
        'insomnia': bool(payload[offset + 5]),
    }
    offset += 6

    # --- Stack chain ---
    if offset + 2 > len(payload):
        stack_chain = []
    else:
        stack_chain_count = payload[offset] | (payload[offset + 1] << 8)
        offset += 2
        stack_chain = []
        for _ in range(stack_chain_count):
            if offset + 2 > len(payload):
                break
            mod_len = payload[offset]
            offset += 1
            module = payload[offset:offset + mod_len].decode('utf-8') if mod_len > 0 else ""
            offset += mod_len
            if offset >= len(payload):
                func_len = 0
            else:
                func_len = payload[offset]
                offset += 1
            function = payload[offset:offset + func_len].decode('utf-8') if func_len > 0 else ""
            offset += func_len
            stack_chain.append({'module': module, 'function': function})

    # --- Return parsed config ---
    config = {
        'beacon_id': beacon_id,
        'crypto_key': crypto_key,
        'channels': channels,
        'global_malleable': global_malleable,
        'global_response_malleable': global_response_malleable,
        'work_hours': work_hours,
        'stack_chain': stack_chain,
    }
    return config


def main():
    if len(sys.argv) < 2:
        print("Usage: python config_decrypt.py <generated_config.h|blob.bin>")
        print("  For .h files: extracts blob, key, nonce from header and decrypts")
        print("  For .bin files: requires key and nonce (not implemented for binary)")
        sys.exit(1)

    filepath = sys.argv[1]

    if filepath.endswith('.h') or filepath.endswith('.hpp'):
        # Parse C++ header
        try:
            blob, config_key, nonce = parse_cpp_header(filepath)
        except Exception as e:
            print(f"[!] Failed to parse header: {e}")
            sys.exit(1)
    else:
        # Load binary blob
        blob = load_binary_blob(filepath)
        config_key = None
        nonce = None
        if len(sys.argv) >= 4:
            # Assume next two args are key and nonce hex strings
            if len(sys.argv) >= 3:
                config_key = bytes.fromhex(sys.argv[2])
            if len(sys.argv) >= 4:
                nonce = bytes.fromhex(sys.argv[3])
        if config_key is None or nonce is None:
            print("[!] Binary blob requires config_key and nonce as hex strings")
            print("Usage: python config_decrypt.py blob.bin <config_key_hex> <nonce_hex>")
            sys.exit(1)

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
    print(f"Magic:         0x{result['magic']:08X} (per-build randomized)")
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
    config = config
    print(f"Beacon ID:    {config['beacon_id']}")
    print(f"Crypto Key:   {config['crypto_key']}")
    print(f"Channels:     {len(config['channels'])}")
    for i, ch in enumerate(config['channels']):
        print(f"  [{i}] {ch['type']} -> {ch['host']}:{ch['port']}{ch['path']} ({ch['http_method']})")
        print(f"      Max Fails: {ch['max_consecutive_failures']}, Backoff: {ch['backoff_sleep_ms']}ms")
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
            loc = mcfg.get('payload_location', {})
            print(f"      Location: {loc.get('type', 'unknown')}")
        print(f"      Response Malleable: {ch.get('response_malleable_mode', 'unknown')}")
        if 'response_malleable_config' in ch:
            rmcfg = ch['response_malleable_config']
            rw = rmcfg.get('wrapper', {})
            if rw.get('prefix') or rw.get('suffix'):
                print(f"      Response Wrapper: prefix='{rw.get('prefix','')}' suffix='{rw.get('suffix','')}'")

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

    # Global response malleable
    grm = config.get('global_response_malleable')
    if grm:
        print(f"\nGlobal Response Malleable Config:")
        rw = grm.get('wrapper', {})
        if rw.get('prefix') or rw.get('suffix'):
            print(f"  Wrapper: prefix='{rw.get('prefix','')}' suffix='{rw.get('suffix','')}'")

    print("\nWork Hours:")
    wh = config.get('work_hours', {})
    print(f"  Enabled: {wh.get('enabled', False)}")
    print(f"  {wh.get('start_hour', 0):02d}:{wh.get('start_minute', 0):02d} - {wh.get('end_hour', 0):02d}:{wh.get('end_minute', 0):02d}")
    print(f"  Insomnia: {wh.get('insomnia', False)}")

    print("\nStack Chain:")
    for entry in config.get('stack_chain', []):
        print(f"  {entry['module']}!{entry['function']}")


if __name__ == '__main__':
    main()