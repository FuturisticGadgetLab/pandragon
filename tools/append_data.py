#!/usr/bin/env python3
"""
Pandragon Post-Build Append Tool

Appends data to the beacon executable with a build-specific magic header.
Format: [MAGIC:4][LEN:4 LE][DATA:N]

Usage:
    python append_data.py beacon.exe --data "marker_string"
    python append_data.py beacon.exe --file payload.bin
    python append_data.py beacon.exe --hex "deadbeefcafe"
    python append_data.py beacon.exe --data "str1" --data "str2"  # chain multiple
"""

import sys
import os
import struct
import argparse
import re

# Path to generated config header (relative to script location)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_CONFIG_HEADER = os.path.join(PROJECT_ROOT, "Beacon", "config", "include", "generated_config.h")

# Default magic if header not found (PDRA = 0x41524450 little-endian)
DEFAULT_MAGIC = b"PDRA"


def extract_magic_from_header(header_path):
    """Extract APPEND_MAGIC from generated_config.h"""
    if not os.path.exists(header_path):
        return None

    with open(header_path, 'r') as f:
        content = f.read()

    # Match: constexpr uint8_t APPEND_MAGIC[4] = { 0xXX, 0xXX, 0xXX, 0xXX };
    match = re.search(
        r'constexpr\s+uint8_t\s+APPEND_MAGIC\s*\[\s*4\s*\]\s*=\s*\{\s*([^}]+)\}',
        content
    )
    if not match:
        return None

    # Parse hex values
    hex_str = match.group(1)
    hex_vals = re.findall(r'0x([0-9a-fA-F]{2})', hex_str)
    if len(hex_vals) != 4:
        return None

    return bytes(int(v, 16) for v in hex_vals)


def build_append_block(magic, data):
    """Build append block: magic(4) + len(4 LE) + data"""
    if len(magic) != 4:
        raise ValueError("Magic must be exactly 4 bytes")
    if len(data) > 0xFFFFFFFF:
        raise ValueError("Data too large (max 4GB)")
    return magic + struct.pack('<I', len(data)) + data


def read_data(args):
    """Read data from various input sources"""
    data_chunks = []

    if args.data:
        for d in args.data:
            data_chunks.append(d.encode('utf-8'))

    if args.file:
        for f in args.file:
            with open(f, 'rb') as fp:
                data_chunks.append(fp.read())

    if args.hex:
        for h in args.hex:
            # Remove whitespace and 0x prefixes
            clean = re.sub(r'[\s0x]+', '', h, flags=re.IGNORECASE)
            if len(clean) % 2 != 0:
                raise ValueError(f"Invalid hex string (odd length): {h}")
            data_chunks.append(bytes.fromhex(clean))

    if not data_chunks:
        raise ValueError("No data provided. Use --data, --file, or --hex")

    return b''.join(data_chunks)


def main():
    parser = argparse.ArgumentParser(
        description="Append data to Pandragon beacon executable",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s build/beacon/pandragon.exe --data "DECOY_STRING"
  %(prog)s build/beacon/pandragon.exe --file shellcode.bin
  %(prog)s build/beacon/pandragon.exe --hex "deadbeefcafe" --data "marker"
  %(prog)s build/beacon/pandragon.exe --data "str1" --data "str2"  # chains both
        """
    )

    parser.add_argument('exe', help='Path to beacon executable')
    parser.add_argument('--data', action='append', help='String data to append (can repeat)')
    parser.add_argument('--file', action='append', help='Binary file to append (can repeat)')
    parser.add_argument('--hex', action='append', help='Hex-encoded data to append (can repeat)')
    parser.add_argument('--magic', help='Override magic as 8 hex chars (e.g. 817b11e7)')
    parser.add_argument('--header', default=DEFAULT_CONFIG_HEADER,
                        help=f'Path to generated_config.h (default: {DEFAULT_CONFIG_HEADER})')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be appended without writing')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    # Validate exe exists
    if not os.path.exists(args.exe):
        print(f"[!] Executable not found: {args.exe}", file=sys.stderr)
        return 1

    # Determine magic
    if args.magic:
        if len(args.magic) != 8:
            print(f"[!] Magic must be 8 hex chars (4 bytes), got: {args.magic}", file=sys.stderr)
            return 1
        try:
            magic = bytes.fromhex(args.magic)
        except ValueError:
            print(f"[!] Invalid hex magic: {args.magic}", file=sys.stderr)
            return 1
    else:
        magic = extract_magic_from_header(args.header)
        if magic is None:
            print(f"[!] Could not extract APPEND_MAGIC from {args.header}", file=sys.stderr)
            print(f"    Falling back to default magic: {DEFAULT_MAGIC.hex()}", file=sys.stderr)
            magic = DEFAULT_MAGIC

    if args.verbose:
        print(f"[*] Using append magic: {magic.hex()}")

    # Read data
    try:
        data = read_data(args)
    except (ValueError, OSError) as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1

    # Build append block
    append_block = build_append_block(magic, data)

    if args.dry_run:
        print(f"[*] Would append {len(append_block)} bytes to {args.exe}")
        print(f"    Magic: {magic.hex()}")
        print(f"    Data length: {len(data)} bytes")
        print(f"    Data (first 64 bytes): {data[:64].hex()}")
        return 0

    # Append to exe
    try:
        with open(args.exe, 'ab') as f:
            f.write(append_block)
    except OSError as e:
        print(f"[!] Failed to write to {args.exe}: {e}", file=sys.stderr)
        return 1

    print(f"[+] Appended {len(append_block)} bytes to {args.exe}")
    print(f"    Magic: {magic.hex()}")
    print(f"    Data length: {len(data)} bytes")

    return 0


if __name__ == "__main__":
    sys.exit(main())