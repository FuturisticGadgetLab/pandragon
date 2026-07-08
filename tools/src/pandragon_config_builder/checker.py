#!/usr/bin/env python3
"""
Pandragon Config Linter / Validator

Detects config type (beacon, server, known_beacons, operators) from
file content and validates structure, types, and required fields.

Usage:
    pandragon-config-check server/config.json
    pandragon-config-check Beacon/config/default.json
    pandragon-config-check server/known_beacons.json
    pandragon-config-check --check-all
    pandragon-config-check --check-all --server-dir ../server
    pandragon-config-check --check-consistency
    pandragon-config-check --graph

Exit code: 0 = valid, 1 = invalid
"""

import json
import os
import sys
import re
from pathlib import Path


CONFIG_GRAPH = r"""
╔══════════════════════════════════════════════════════════════════════╗
║                     PANDRAGON CONFIGURATION FLOW                     ║
╚══════════════════════════════════════════════════════════════════════╝

  ┌──────────────────────┐     config_builder.py      ┌──────────────────────────┐
  │ Beacon/config/       │ ─────────────────────────▶ │ Beacon/include/          │
  │ default.json         │  (encrypts + generates)    │ generated_config.h       │
  │ (HAND-EDIT THIS)     │                             │ (compiled into beacon)   │
  └─────────┬────────────┘                             └───────────┬──────────────┘
            │                                                      │
            │ syncs beacon_id + crypto_key + routes                │
            ▼                                                      ▼
  ┌──────────────────────┐                             ┌──────────────────────────┐
  │ server/              │                             │ pandragon.exe            │
  │ known_beacons.json   │◀──(auto-generated,          │ (encrypted config        │
  │ (DO NOT HAND-EDIT)   │     DO NOT HAND-EDIT)       │  embedded in .rdata)     │
  └─────────┬────────────┘                             └──────────────────────────┘
            │
            │ loaded at startup
            ▼
  ┌──────────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
  │ server/config.json   │────▶│    TEAMSERVER        │     │ server/ssl/          │
  │ (HAND-EDIT THIS)     │     │                      │     │ cert.pem + key.pem   │
  │                       │     │ 1. Loads config.json │     │ (make ssl-cert)      │
  │ Can include operators │     │ 2. Loads known_      │     └──────────────────────┘
  │ inline: "operators": {│     │    beacons.json      │
  │   "admin": "64hex"    │     │ 3. Registers HTTP    │
  │ }                     │     │    routes from       │
  │                       │     │    known_beacons     │
  │ run.py create appends │     │ 4. Reads operators   │
  │ operators to this file│     │    from config.json  │
  └──────────────────────┘     └──────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────────────┐
  │ QUICK-START                                                                │
  │                                                                            │
  │   1. Edit Beacon/config/default.json  (C2 domains, sleep, options...)      │
  │   2. Edit server/config.json          (listeners, SSL, operators...)       │
  │   3. make ssl-cert                    (self-signed TLS cert)               │
  │   4. make                             (builds beacon + syncs known_beacons)│
  │   5. make run-server-args ARGS="create admin"   (create operator)          │
  │   6. make run-server                  (start teamserver)                   │
  └─────────────────────────────────────────────────────────────────────────────┘
"""


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
    if isinstance(config.get("listeners"), list):
        return "server"
    if isinstance(config.get("server"), dict):
        return "server"
    if isinstance(config.get("operators"), dict):
        return "operators"
    return "unknown"


def check_beacon(config: dict, path: str, schema_dir: str = None) -> int:
    errors = 0

    if schema_dir is None:
        schema_dir = os.path.join(os.getcwd(), "Beacon", "config")
    schema_file = os.path.join(schema_dir, "schema.json")

    if os.path.exists(schema_file):
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

    import hashlib
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

    channels = config.get("c2_channels", [])
    if not channels:
        e("c2_channels must have at least 1 entry")
        errors += 1
    else:
        ok(f"{len(channels)} C2 channel(s)")
        for i, ch in enumerate(channels):
            transport = ch.get("type", "?")
            if transport in ("HTTP", "HTTPS"):
                if not ch.get("poll_path", "") or not ch.get("submit_path", ""):
                    e(f"c2_channels[{i}]: poll_path and submit_path required for {transport}")
                    errors += 1
                if not ch.get("user_agent", ""):
                    e(f"c2_channels[{i}]: user_agent required for {transport}")
                    errors += 1
                if not (1 <= ch.get("port", 0) <= 65535):
                    e(f"c2_channels[{i}]: port out of range")
                    errors += 1

    if config.get("lazy_checkin"):
        lcm = config.get("lazy_checkin_max")
        if not isinstance(lcm, int) or lcm < 1 or lcm > 255:
            e("lazy_checkin_max must be an int 1-255 when lazy_checkin=true")
            errors += 1

    pivot = config.get("indirect_syscall_pivot", "")
    if pivot:
        if not pivot.startswith("Zw"):
            e("indirect_syscall_pivot must start with 'Zw'")
            errors += 1

    wh = config.get("work_hours", {})
    if wh:
        for field in ("enabled", "start_hour", "start_minute", "end_hour", "end_minute", "insomnia"):
            if field not in wh:
                e(f"work_hours.{field} is required")
                errors += 1

    return errors


def check_server(config: dict, path: str) -> int:
    errors = 0
    base = Path(path).resolve().parent

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

    op_routes = config.get("operator_routes", {})
    if op_routes:
        ws_path = op_routes.get("websocket", {}).get("path", "")
        if ws_path and not ws_path.startswith("/"):
            e(f"operator_routes.websocket.path must start with '/'")
            errors += 1

    log = config.get("logging", {})
    if log:
        level = log.get("level", "INFO").upper()
        if level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            e(f"logging.level '{log.get('level')}' invalid (use DEBUG/INFO/WARNING/ERROR/CRITICAL)")
            errors += 1

    audit = config.get("audit", {})
    if audit:
        if "enabled" in audit and not isinstance(audit["enabled"], bool):
            e("audit.enabled must be a boolean")
            errors += 1

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

    sec = config.get("security", {})
    if sec:
        max_ps = sec.get("max_payload_size", 10485760)
        if not isinstance(max_ps, int) or max_ps < 1:
            e("security.max_payload_size must be a positive int")
            errors += 1

    ops = config.get("operators", {})
    if ops:
        if not isinstance(ops, dict):
            e("operators must be an object")
            errors += 1
        else:
            good = 0
            bad = 0
            for username, token in ops.items():
                if isinstance(token, str) and re.fullmatch(r'^[0-9a-fA-F]{64}$', token):
                    good += 1
                else:
                    e(f"operators.{username}: token must be 64 hex characters")
                    bad += 1
            if good:
                ok(f"{good} inline operator(s) with valid tokens")
            if bad:
                errors += bad

    return errors


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
                    if not rt.get("poll_path", "") or not rt.get("submit_path", ""):
                        e(f"beacon '{bid}' allowed_routes[{ri}]: poll_path and submit_path required for {tt}")
                        errors += 1
                    if not rt.get("user_agent", ""):
                        e(f"beacon '{bid}' allowed_routes[{ri}]: user_agent required for {tt}")
                        errors += 1

    return errors


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


def check_consistency(root: str = ".", server_dir: str = "server") -> int:
    """Cross-file consistency checks across all config files."""
    import hashlib
    errors = 0
    proj = Path(root).resolve()

    print("=" * 55)
    print("CROSS-FILE CONSISTENCY CHECKS")
    print("=" * 55)

    beacon_cfg = proj / "Beacon" / "config" / "default.json"
    known_file = proj / server_dir / "known_beacons.json"

    beacon_has_key = False
    if beacon_cfg.exists():
        with open(beacon_cfg) as f:
            bc = json.load(f)
        b_ck = bc.get("crypto_key", "")
        if b_ck:
            beacon_has_key = True
            expected_bid = hashlib.sha256(bytes.fromhex(b_ck)).hexdigest()[:16]
            if known_file.exists():
                with open(known_file) as f:
                    kn = json.load(f)
                known_bid = None
                for bid in kn.get("beacons", {}):
                    if bid == expected_bid:
                        known_bid = bid
                        break
                if known_bid:
                    ok(f"beacon_id {expected_bid} matches between default.json and known_beacons.json")
                else:
                    e(f"beacon_id {expected_bid} from default.json NOT FOUND in known_beacons.json")
                    e(f"    Run 'make config' to sync")
                    errors += 1
            else:
                w("known_beacons.json not found — sync check skipped")
        else:
            w("Beacon/config/default.json has no crypto_key — sync irrelevant")
    else:
        w("Beacon/config/default.json not found — sync check skipped")

    server_cfg = proj / server_dir / "config.json"
    if server_cfg.exists():
        with open(server_cfg) as f:
            sc = json.load(f)

        bf = sc.get("beacons_file", "known_beacons.json")
        bf_path = proj / server_dir / bf
        if bf_path.exists():
            ok(f"beacons_file '{bf}' exists")
        else:
            w(f"beacons_file '{bf}' not found at {bf_path}")

        for key in ("ssl_cert", "ssl_key"):
            val = sc.get("server", {}).get(key, "")
            if val:
                ref = proj / server_dir / val
                if not ref.exists():
                    w(f"server.{key} -> {val} not found (run 'make ssl-cert')")

    if errors == 0:
        print("\n[OK] All cross-file checks passed")
    else:
        print(f"\n[ERROR] {errors} cross-file consistency error(s)")

    return errors


def check_all(root: str = ".", server_dir: str = "server") -> int:
    """Validate every config file in the project."""
    import hashlib
    proj = Path(root).resolve()
    total_errors = 0

    configs = [
        ("Beacon",           f"Beacon/config/default.json"),
        ("Server",           f"{server_dir}/config.json"),
        ("Known Beacons",    f"{server_dir}/known_beacons.json"),
    ]

    for label, rel_path in configs:
        path = proj / rel_path
        print(f"\n{'─' * 50}")
        print(f"[{label}] {rel_path}")
        print(f"{'─' * 50}")
        if not path.exists():
            w("File not found — skipping")
            continue
        try:
            with open(path) as f:
                config = json.load(f)
        except json.JSONDecodeError as ex:
            e(f"Invalid JSON: {ex}")
            total_errors += 1
            continue

        ctype = detect_type(config)
        validators = {
            "beacon": check_beacon,
            "server": check_server,
            "known_beacons": check_known_beacons,
            "operators": check_operators,
        }
        if ctype in validators:
            kwargs = {}
            if ctype == "beacon":
                kwargs["schema_dir"] = str(proj / "Beacon" / "config")
            total_errors += validators[ctype](config, str(path), **kwargs)
        else:
            w(f"Unrecognized config type — skipping")

    print()
    total_errors += check_consistency(root, server_dir)

    print(f"\n{'=' * 50}")
    if total_errors == 0:
        print("[OK] All config files are valid")
        return 0
    else:
        print(f"[ERROR] {total_errors} total error(s) across all configs")
        return 1


def main():
    server_dir = "server"
    parsed_argv = []
    i = 0
    while i < len(sys.argv):
        if sys.argv[i] == "--server-dir" and i + 1 < len(sys.argv):
            server_dir = sys.argv[i + 1]
            i += 2
        elif sys.argv[i].startswith("--server-dir="):
            server_dir = sys.argv[i].split("=", 1)[1]
            i += 1
        else:
            parsed_argv.append(sys.argv[i])
            i += 1

    sys.argv = parsed_argv

    if "--graph" in sys.argv:
        print(CONFIG_GRAPH)
        sys.exit(0)
    if "--check-all" in sys.argv:
        rc = check_all(server_dir=server_dir)
        sys.exit(rc)
    if "--check-consistency" in sys.argv:
        rc = check_consistency(server_dir=server_dir)
        sys.exit(rc)

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

    kwargs = {}
    if ctype == "beacon":
        beacon_dir = os.path.dirname(os.path.abspath(filepath))
        schema_candidate = os.path.join(beacon_dir, "schema.json")
        if os.path.exists(schema_candidate):
            kwargs["schema_dir"] = os.path.dirname(schema_candidate)
        else:
            kwargs["schema_dir"] = os.path.join(os.getcwd(), "Beacon", "config")

    errors = validators[ctype](config, filepath, **kwargs)

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
