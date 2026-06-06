#!/usr/bin/env python3
"""
Pandragon Config Linter / Validator

Detects config type (beacon, server, known_beacons, operators) from
file content and validates structure, types, and required fields.

Usage:
    python tools/config_check.py server/config.json
    python tools/config_check.py Beacon/config/default.json
    python tools/config_check.py server/known_beacons.json
    python tools/config_check.py server/operators.json

Exit code: 0 = valid, 1 = invalid
"""

import json
import os
import sys
import re
from pathlib import Path


# ── Helpers ──────────────────────────────────────────────────────

def e(msg: str):
    print(f"  [ERROR] {msg}")

def w(msg: str):
    print(f"  [WARNING] {msg}")

def ok(msg: str):
    print(f"  [OK] {msg}")


def detect_type(config: dict) -> str:
    """Detect config type from top-level keys."""
    if isinstance(config.get("c2_channels"), list):
        return "beacon"
    if isinstance(config.get("beacons"), dict):
        return "known_beacons"
    if isinstance(config.get("operators"), dict):
        return "operators"
    if isinstance(config.get("listeners"), list):
        return "server"
    if isinstance(config.get("server"), dict):
        return "server"
    return "unknown"


# ── Beacon Config Validator ──────────────────────────────────────

def check_beacon(config: dict, path: str) -> int:
    errors = 0
    schema_dir = Path(__file__).resolve().parent.parent / "config"

    # JSON schema validation
    schema_file = schema_dir / "schema.json"
    if schema_file.exists():
        try:
            import jsonschema
        except ImportError:
            w("jsonschema not available, skipping schema validation")
        else:
            with open(schema_file) as f:
                schema = json.load(f)
            try:
                jsonschema.validate(instance=config, schema=schema)
                ok("JSON schema validation passed")
            except jsonschema.ValidationError as ex:
                e(f"Schema validation: {ex.message}")
                errors += 1
    else:
        w(f"Schema file not found at {schema_file}")

    # crypto_key consistency
    ck = config.get("crypto_key", "")
    if ck:
        if not re.fullmatch(r'^[0-9a-fA-F]{64}$', ck):
            e("crypto_key must be 64 hex characters (32 bytes)")
            errors += 1
        bid = config.get("beacon_id", "")
        if bid:
            expected = hashlib.sha256(bytes.fromhex(ck)).hexdigest()[:16]
            if bid.lower() != expected:
                e(f"beacon_id {bid} does not match SHA256(crypto_key)[:16] = {expected}")
                errors += 1
            else:
                ok("beacon_id matches crypto_key")
        else:
            ok(f"beacon_id auto-derived (add beacon_id to pin it)")
    else:
        w("No crypto_key (will be auto-generated)")

    # c2_channels
    channels = config.get("c2_channels", [])
    if not channels:
        e("c2_channels must have at least 1 entry")
        errors += 1
    else:
        ok(f"{len(channels)} C2 channel(s)")
        for i, ch in enumerate(channels):
            transport = ch.get("type", "?")
            if transport in ("HTTP", "HTTPS"):
                if not ch.get("path", ""):
                    e(f"c2_channels[{i}]: path required for {transport}")
                    errors += 1
                if not ch.get("user_agent", ""):
                    e(f"c2_channels[{i}]: user_agent required for {transport}")
                    errors += 1
                if not (1 <= ch.get("port", 0) <= 65535):
                    e(f"c2_channels[{i}]: port out of range")
                    errors += 1

    # lazy_checkin consistency
    if config.get("lazy_checkin"):
        lcm = config.get("lazy_checkin_max")
        if not isinstance(lcm, int) or lcm < 1 or lcm > 255:
            e("lazy_checkin_max must be an int 1-255 when lazy_checkin=true")
            errors += 1

    # indirect_syscall_pivot
    pivot = config.get("indirect_syscall_pivot", "")
    if pivot:
        if not pivot.startswith("Zw"):
            e("indirect_syscall_pivot must start with 'Zw'")
            errors += 1

    # work_hours
    wh = config.get("work_hours", {})
    if wh:
        for field in ("enabled", "start_hour", "start_minute", "end_hour", "end_minute", "insomnia"):
            if field not in wh:
                e(f"work_hours.{field} is required")
                errors += 1

    return errors


# ── Server Config Validator ──────────────────────────────────────

def check_server(config: dict, path: str) -> int:
    errors = 0
    base = Path(path).resolve().parent

    # ── server section ──
    sv = config.get("server", {})
    if sv:
        if not isinstance(sv, dict):
            e("server must be an object")
            errors += 1
        else:
            port = sv.get("port", 6767)
            if not isinstance(port, int) or port < 1 or port > 65535:
                e("server.port out of range (1-65535)")
                errors += 1
            for ssl_key in ("ssl_cert", "ssl_key"):
                val = sv.get(ssl_key)
                if val:
                    ssl_path = base / val
                    if not ssl_path.exists():
                        w(f"server.{ssl_key} -> {val} not found (expected at {ssl_path})")
            timeout = sv.get("session_timeout_minutes", 30)
            if not isinstance(timeout, int) or timeout < 1:
                e("server.session_timeout_minutes must be a positive int")
                errors += 1

    # ── listeners ──
    listeners = config.get("listeners", [])
    if not isinstance(listeners, list):
        e("listeners must be an array")
        errors += 1
    elif listeners:
        seen_ports = {}
        valid_protocols = {"http", "https", "tcp", "pipe"}
        for i, ln in enumerate(listeners):
            proto = ln.get("protocol", "").lower()
            if proto not in valid_protocols:
                e(f"listeners[{i}].protocol '{ln.get('protocol')}' invalid (http/https/tcp/pipe)")
                errors += 1
            port = ln.get("port", 443 if proto == "https" else 80)
            if not isinstance(port, int) or port < 1 or port > 65535:
                e(f"listeners[{i}].port out of range")
                errors += 1
            if port in seen_ports:
                w(f"Duplicate port {port} on listeners {seen_ports[port]} and {i}")
            seen_ports[port] = i
            if proto in ("https",):
                for ssl_key in ("ssl_cert", "ssl_key"):
                    val = ln.get(ssl_key)
                    if val:
                        ssl_path = base / val
                        if not ssl_path.exists():
                            w(f"listeners[{i}].{ssl_key} -> {val} not found")

        primary_count = sum(1 for ln in listeners if ln.get("primary"))
        if primary_count > 1:
            e(f"{primary_count} listeners marked primary; at most 1 allowed")
            errors += 1

    # ── operator_routes ──
    op_routes = config.get("operator_routes", {})
    if op_routes:
        ws_path = op_routes.get("websocket", {}).get("path", "")
        if ws_path and not ws_path.startswith("/"):
            e(f"operator_routes.websocket.path must start with '/'")
            errors += 1

    # ── logging ──
    log = config.get("logging", {})
    if log:
        level = log.get("level", "INFO").upper()
        if level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            e(f"logging.level '{log.get('level')}' invalid (use DEBUG/INFO/WARNING/ERROR/CRITICAL)")
            errors += 1

    # ── audit ──
    audit = config.get("audit", {})
    if audit:
        if "enabled" in audit and not isinstance(audit["enabled"], bool):
            e("audit.enabled must be a boolean")
            errors += 1

    # ── beacon section ──
    bc = config.get("beacon", {})
    if bc:
        bof_dir = bc.get("bof_directory", "")
        if bof_dir:
            bof_path = base / bof_dir
            if not bof_path.exists():
                w(f"beacon.bof_directory -> {bof_dir} not found")
        dl_dir = bc.get("download_directory", "")
        if dl_dir and not (base / dl_dir).exists():
            w(f"beacon.download_directory -> {dl_dir} not found (will be created)")

    # ── security ──
    sec = config.get("security", {})
    if sec:
        max_ps = sec.get("max_payload_size", 10485760)
        if not isinstance(max_ps, int) or max_ps < 1:
            e("security.max_payload_size must be a positive int")
            errors += 1

    return errors


# ── Known Beacons Validator ──────────────────────────────────────

def check_known_beacons(config: dict, path: str) -> int:
    errors = 0

    version = config.get("version")
    if not isinstance(version, int):
        e("version must be an integer")
        errors += 1

    beacons = config.get("beacons", {})
    if not isinstance(beacons, dict):
        e("beacons must be an object")
        errors += 1
        return errors

    ok(f"{len(beacons)} beacon(s) registered")
    for bid, info in beacons.items():
        if not re.fullmatch(r'^[0-9a-fA-F]{16}$', bid):
            e(f"beacon key '{bid}' must be 16 hex characters")
            errors += 1
        ck = info.get("crypto_key", "")
        if ck and not re.fullmatch(r'^[0-9a-fA-F]{64}$', ck):
            e(f"beacon '{bid}': crypto_key must be 64 hex characters")
            errors += 1
        routes = info.get("allowed_routes", [])
        if not isinstance(routes, list):
            e(f"beacon '{bid}': allowed_routes must be an array")
            errors += 1
        else:
            for ri, rt in enumerate(routes):
                tt = rt.get("transport_type", "")
                if tt not in ("HTTP", "HTTPS", "TCP", "PIPE"):
                    e(f"beacon '{bid}' allowed_routes[{ri}]: invalid transport_type")
                    errors += 1
                if tt in ("HTTP", "HTTPS"):
                    if not rt.get("path", ""):
                        e(f"beacon '{bid}' allowed_routes[{ri}]: path required for {tt}")
                        errors += 1
                    if not rt.get("user_agent", ""):
                        e(f"beacon '{bid}' allowed_routes[{ri}]: user_agent required for {tt}")
                        errors += 1

    return errors


# ── Operators Validator ──────────────────────────────────────────

def check_operators(config: dict, path: str) -> int:
    errors = 0

    ops = config.get("operators", {})
    if not isinstance(ops, dict):
        e("operators must be an object")
        errors += 1
        return errors

    ok(f"{len(ops)} operator(s)")
    for username, token_hash in ops.items():
        if not isinstance(token_hash, str) or not re.fullmatch(r'^[0-9a-fA-F]{64}$', token_hash):
            e(f"operator '{username}': token hash must be 64 hex characters (SHA-256)")
            errors += 1

    return errors


# ── Main ─────────────────────────────────────────────────────────

def main():
    if len(sys.argv) != 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(1)

    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    with open(filepath) as f:
        try:
            config = json.load(f)
        except json.JSONDecodeError as ex:
            print(f"[!] Invalid JSON: {ex}")
            sys.exit(1)

    ctype = detect_type(config)
    if ctype == "unknown":
        print(f"[!] Could not detect config type for {filepath}")
        print(f"    Top-level keys: {list(config.keys())}")
        sys.exit(1)

    type_labels = {
        "beacon": "Beacon Config",
        "server": "Server Config",
        "known_beacons": "Known Beacons",
        "operators": "Operators",
    }
    print(f"File: {filepath}")
    print(f"Type: {type_labels[ctype]}")
    print()

    validators = {
        "beacon": check_beacon,
        "server": check_server,
        "known_beacons": check_known_beacons,
        "operators": check_operators,
    }

    errors = validators[ctype](config, filepath)

    print()
    if errors == 0:
        print("[OK] Config is valid. CONGRATS!")
        sys.exit(0)
    else:
        print(f"[ERROR] {errors} error(s) found")
        sys.exit(1)


if __name__ == "__main__":
    import hashlib
    main()
