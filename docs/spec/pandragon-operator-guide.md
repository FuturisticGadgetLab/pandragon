# Pandragon Operator Reference Manual
**Author**: Serexp (Futuristic Gadgets Laboratory)

## 1. Overview
Pandragon is a modular, high-stealth Command and Control (C2) framework built for elite red team operations. The system is designed around a transport-agnostic architecture, ensuring that the core protocol remains decoupled from the physical medium (HTTP, TCP, SMB, etc.). This allows operators to wrap Pandragon traffic in opaque binary blobs that blend perfectly into unique target environments.

### Architecture
- **Beacon**: A lightweight C++ implant featuring direct/indirect syscall redirection via Hardware Breakpoints (HWBP) and Vectored Exception Handling (VEH).
- **Teamserver**: A secure coordination hub implementing XChaCha20-Poly1305 session encryption and LRU-based replay protection.
- **Transport Abstraction**: The beacon utilizes a function-pointer-based transport layer. Protocol logic (serialization, encryption) is separated from the wire transport, supporting standard HTTP/S, raw TCP, and Named Pipe (SMB) relays, while remaining extensible for custom out-of-band channels.
- **BOF Model**: Supports Cobalt Strike BOFs using a contiguous, page-aligned memory allocation strategy to ensure stealthy relocations and proper memory protection promotion.

## 2. Beacon Configuration Reference

| Field Name | Type | Default | What it does |
|------------|------|---------|--------------|
| `beacon_id` | 8-byte Hex | Random | **Beacon ID**: Unique session identifier. Present in every packet header to allow the teamserver to route tasks and track replay state. |
| `lazy_checkin` | Boolean | true | **Lazy Checkin**: Defer system information announcement to a random poll within the `lazy_checkin_max` window. |
| `lazy_checkin_max` | uint8_t | 2 | The upper bound for the random poll deferral window. |
| `lazy_unhook` | Boolean | false | **Lazy Unhook**: Defer ntdll unhooking (phantom mapping) until the first BOF execution or process migration. |
| `sleep_ms` | uint32_t | 5000 | Baseline sleep interval. |
| `jitter_pct` | uint8_t | 20 | Sleep variance (timing entropy). |
| `use_indirect_syscalls`| Boolean | false | Use HWBP+VEH to redirect syscalls through ntdll stubs. |
| `bypass_etw` | Boolean | true | Hardware-breakpoint based silencing of `NtTraceEvent`. |
| `sleep_obfuscation` | String | "ekko" | Memory encryption strategy during idle periods. |
| `sleep_stack_spoof` | Boolean | false | Stack pivoting to a helper region during sleep. |

### `beacon_id`
**Type**: uint8_t[8]
**Default**: Generated at build
**Valid range**: Any 8-byte value

**What it does**: Identifies the beacon session. The Teamserver uses this to match incoming packets to a specific crypto context and command queue.

**Effectiveness impact**: Vital for session management. In a multi-relay environment, the Beacon ID is the only way to route traffic through parent/child nodes.

**Evasion impact**: While the ID is unique per session, it is never sent in cleartext. It is part of the encrypted payload, preventing static network signatures from identifying specific implants across different transports.

### `lazy_checkin` & `lazy_checkin_max`
**Type**: Boolean / uint8_t
**Default**: true / 2

**What it does**: Defer the "First Check-in" (system info metadata) to a random poll number between 1 and `lazy_checkin_max`.

**Effectiveness impact**: Prevents the deterministic signature where the very first packet after a beacon's startup is significantly larger than subsequent poll packets.

**Evasion impact**: Extremely effective against behavioral NDR rules that look for high-entropy large blobs immediately following a new network connection.

### `lazy_unhook`
**Type**: Boolean
**Default**: false

**What it does**: Delays the unhooking of `ntdll.dll` until it is strictly required by a feature (e.g., loading a BOF or migrating).

**Effectiveness impact**: Unhooking via "Phantom Mapping" involves spawning a suspended process (default `cmd.exe`) and reading its memory. This generates high-risk telemetry.

**Evasion impact**: By delaying this action, the beacon remains "dormant" and clean for a longer period, reducing the chance of initial detection during the discovery phase.

---

## 3. Command & Feature Reference

### `bof_exec` [BOF]
**Syntax**: `bof_exec <path_to_bof> <args>`
**Description**: Executes a Cobalt Strike compatible BOF using the Pandragon custom loader.

#### Execution Profile
| Property | Value |
|---------------------------------|-------|
| Allocates RX memory | Yes (Page-aligned) |
| Allocates RW memory | Yes (Temporary) |
| Allocates RWX memory | No |
| Creates process | No |
| Creates thread | Yes (Inline/Fiber) |
| Process spawn type | None |
| Thread execution type | Main thread or Fiber |
| Touches disk | No |
| Opens network connection | No |
| Modifies another process | No |
| Loads additional DLLs | Yes (via `BeaconUseToken`/`LoadLibrary`) |
| Uses hardware breakpoints (HWBPs) | No |
| Elevates privileges | Optional (via tokens) |
| Modifies token | Optional |

#### Telemetry Generated
**User-mode telemetry**
- [x] Yes
  • `Microsoft-Windows-Threat-Intelligence\ExecutableMemory`: Fires when promoting BOF memory to `RX`.

**Kernel-mode telemetry**
- [ ] No

**NDR / network telemetry**
- [x] Yes
  • Encrypted task results (BOF output).

**Memory forensics exposure**
- [x] Yes
  • `PE-Sieve` detects `RX` regions not backed by files. Pandragon mitigates this by using **Page-Aligned Contiguous Sections**, allowing for clean page boundaries and reducing "Executable" entropy.

#### OPSEC Risk Rating
**Overall risk**: 🟡 Medium

**Risk summary**: BOF execution is generally safer than process injection but leaves identifiable memory artifacts (`RX` private pages). Detection is usually triggered by the *content* of the BOF (e.g., using `BeaconUseToken` to touch `lsass.exe`).

**Mitigations**: Enable `lazy_unhook` so the environment is cleaned immediately before execution. Use the planned caching mechanism to reuse memory regions for common BOFs.

---

## 4. Transport OPSEC & Agnosticism

Pandragon's communication model is built on **Transport Agnosticism**. The beacon does not "know" if it's talking over HTTP or a raw TCP socket.

### 4.1 Opaque Binary Blobs
The protocol serializes all communications into a standard binary packet:
`[Magic] [Version] [BeaconID] [Nonce] [Opcode] [PayloadLen] [EncryptedPayload] [MAC]`

This packet is then handed to the transport layer. Operators can:
- **HTTP/S**: Wrap the blob in Base64URL and place it in query params, headers, or the body.
- **TCP**: Send the raw blob with a custom static prefix/suffix to match legitimate protocol headers (e.g., mimicking a database handshake).
- **Custom**: Provide a custom `TransportFn` to send the blob over proprietary protocols or covert channels.

### 4.2 Replay Protection
Every packet sent or received includes:
1.  **24-byte Nonce**: Generated using a cryptographically secure pseudo-random number generator (CSPRNG).
2.  **Sequence Number**: Incremented on every send/receive to prevent out-of-order or duplicate packets.

**Teamserver Defense**: The server maintains an **LRU (Least Recently Used) Cache** of all recently seen nonces. If a packet arrives with a nonce already in the cache, it is dropped immediately as a replay attempt.

---

## 5. Operational Stealth Configuration Optimization

Recommended settings for high-value targets:

1.  **`lazy_checkin`**: `true` (Defeats "Large First Packet" detection).
2.  **`lazy_checkin_max`**: `10-15` (Increases the window of behavioral ambiguity).
3.  **`lazy_unhook`**: `true` (Avoids spawning child processes during initial discovery).
4.  **`bypass_etw`**: `true` (Uses HWBP to avoid memory patching detection).
5.  **`sleep_ms`**: `300000` (5 minutes) for long-haul persistence.
6.  **`jitter_pct`**: `35` (High entropy in callback timing).
7.  **`sleep_obfuscation`**: `"ekko"` (Ensures code is encrypted while idle).
8.  **`sleep_stack_spoof`**: `true` (Hides the beacon's call stack from memory scanners).
9.  **`use_indirect_syscalls`**: `true` (Bypasses all user-mode EDR hooks).
10. **`validate_ssl`**: `true` (Always use valid certificates to avoid TLS interception alerts).

---

## 6. Known Detection Signatures

| ID | Signature type | Description | Detected by | Severity | Mitigated? |
|----|----------------|-------------|-------------|----------|------------|
| S-001 | Static-String | Symbol names/literals | Static Scan | Medium | ✅ (lcg_encrypt) |
| B-001 | Behavioral | `cmd.exe` child spawn | EDR Process Tree | High | ✅ (lazy_unhook) |
| B-002 | Behavioral | HWBP on `NtTraceEvent` | EDR/Anti-Debug | Medium | ✅ (VEH Hidden) |
| M-001 | Memory | Ekko timer chain | Memory Scanners | High | ❌ (Partially) |
| P-001 | Protocol | Replay attempt | Teamserver | N/A | ✅ (LRU Nonce Cache) |

---

## 7. Appendix: Command Quick Reference

| Command | OPSEC Profile | Mitigations |
|---------|---------------|-------------|
| `ls` | 🟢 Low | Limit scope to non-sensitive paths. |
| `download` | 🟡 Medium | Use small chunk sizes to blend traffic. |
| `bof_exec`| 🟡 Medium | Verify BOF logic before running. |
| `inject` | 🔴 High | Target stable system processes only. |
