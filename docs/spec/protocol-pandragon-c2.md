---
title: Pandragon C2 Protocol Specification
version: 1.2
date_created: 2026-04-02
last_updated: 2026-05-08
owner: Futuristic Gadgets Laboratory (FGL)
tags: [protocol, c2, encryption, malleable-c2, xchacha20-poly1305, beacon]
---

# Introduction

This document specifies the Pandragon C2 (Command and Control) protocol, an encrypted binary protocol designed for stealthy beacon communication. The protocol provides authenticated encryption, traffic obfuscation, and malleable C2 capabilities for operational security.

The protocol operates over transports with optional traffic disguise through malleable network configurations.
Officially, Pandragon is designed to be transport-agnostic. As of now, we have implemented a partial API for this.
Ideally, operators will be able to change transports dynamically over live beacons. For now, we support HTTP(S), TCP, and SMB pipes.

## 1. Purpose & Scope

This specification defines:

- **Wire Protocol**: Packet structure, header format, and framing
- **Cryptographic Layer**: XChaCha20-Poly1305 AEAD encryption and authentication
- **Opcode Definitions**: Server-to-Beacon and Beacon-to-Server command set
- **Payload Formats**: Structured data for each opcode
- **Malleable C2**: Traffic obfuscation through wrappers, macros, and payload location
- **Key Management**: Key derivation, rotation, and replay protection

**Intended Audience**:
- FGL developers implementing beacon or server components
- Security researchers analyzing protocol traffic patterns
- Red team operators configuring beacon deployments

**Assumptions**:
- Transport layer provides TLS encryption. If it does not, we still have Pandragon's encryption.
- Beacon and server share a pre-distributed 32-byte symmetric key
- Beacon possesses a unique 8-byte identifier derived from key material

## 2. Definitions

| Term | Definition |
|------|------------|
| **AEAD** | Authenticated Encryption with Associated Data |
| **Beacon** | Windows x64 agent deployed on target systems |
| **C2** | Command and Control |
| **FGL** | Futuristic Gadgets Laboratory |
| **HWBP** | Hardware Breakpoint (used for ETW bypass) |
| **IAT** | Import Address Table |
| **MAC** | Message Authentication Code (Poly1305 in this protocol) |
| **Nonce** | Number used once (24-byte for XChaCha20) |
| **PCFG** | Pandragon Config Format (binary configuration) |
| **PEB** | Process Environment Block |
| **S2B** | Server-to-Beacon direction |
| **B2S** | Beacon-to-Server direction |
| **XChaCha20** | Extended-nonce ChaCha20 stream cipher |

**Opcode Direction Notation**:
- **S2B**: Server -> Beacon (commands)
- **B2S**: Beacon -> Server (responses/check-ins)

## 3. Requirements, Constraints & Guidelines

### Protocol Requirements

- **REQ-001**: All packets MUST use the 47-byte fixed header format defined in Section 4
- **REQ-002**: All payloads MUST be encrypted using XChaCha20-Poly1305
- **REQ-003**: Each packet MUST use a unique 24-byte nonce generated via CSPRNG
- **REQ-004**: The Poly1305 MAC MUST be computed over ciphertext with header as AAD
- **REQ-006**: Beacon MUST validate server packets using shared crypto key and beacon ID
- **REQ-007**: Server MUST track sequence numbers per beacon for replay protection
- **REQ-008**: Padding size (0-15 bytes) MUST be encoded in lower 4 bits of `padding_flags`

### Cryptographic Requirements

- **SEC-001**: Encryption key MUST be exactly 32 bytes (256 bits)
- **SEC-002**: Nonce MUST be exactly 24 bytes (192 bits) generated via CSPRNG
- **SEC-003**: Nonce MUST NEVER be reused with the same key
- **SEC-004**: MAC tag MUST be 16 bytes (128 bits) appended to ciphertext
- **SEC-005**: Failed MAC verification MUST result in packet rejection without processing
- **SEC-006**: Key rotation MUST use the ROTATE_KEY opcode with acknowledgment

### Malleable C2 Requirements

- **MAL-001**: Wrapper prefix/suffix MUST NOT be encrypted (applied post-encryption)
- **MAL-002**: Macros MUST be expanded server-side before transmission
- **MAL-003**: Payload location (query/path/body) MUST be configurable per beacon
- **MAL-004**: Custom HTTP headers MUST be added to all beacon requests

### Constraints

- **CON-001**: Maximum packet size SHOULD NOT exceed 64KB (beacon memory constraints)
- **CON-002**: Plaintext padding MUST use PKCS#7 (1-16 bytes, aligned to 16-byte boundary)
- **CON-003**: Beacon ID MUST be exactly 8 bytes
- **CON-004**: Protocol version MUST be 0 (epoch) for all current implementations
- **CON-005**: Magic bytes MUST be `0x50414E44` ("PAND" in ASCII, little-endian)

### Guidelines

- **GUD-001**: Sequence numbers SHOULD increment monotonically per session
- **GUD-002**: Sleep jitter SHOULD be applied client-side to avoid timing analysis
- **GUD-003**: File transfers SHOULD use chunked opcodes (0x20-0x23); legacy 0x12-0x13 for small files only
- **GUD-004**: Error responses SHOULD include descriptive error messages printed ONLY in debug builds.
- **GUD-005**: Beacon SHOULD validate kill_date before processing commands. Perhaps periodically.

## 4. Interfaces & Data Contracts

### 4.1 Packet Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                        HEADER (46 bytes)                        │
├──────────────┬─────────┬────────────┬──────────┬───────────────┤
│ magic        │ version │ beacon_id  │ opcode   │ seq_num       │
│ 4 bytes      │ 1 byte  │ 8 bytes    │ 1 byte   │ 4 bytes       │
│ 0x50414E44   │ 0x00    │ SHA256(k)[:8] │ command  │ little-endian │
├──────────────┴─────────┴────────────┴──────────┴───────────────┤
│ nonce (24 bytes)            │ payload_len (4 bytes)             │
│ CSPRNG per packet          │ ciphertext + MAC length           │
└─────────────────────────────┴───────────────────────────────────┘
│ CIPHERTEXT │ MAC (16 bytes)                                     │
│ XChaCha20  │ Poly1305 tag                                       │
└─────────────────────────────────────────────────────────────────┘
```
Note: Padding is handled via PKCS#7 applied to plaintext before encryption (not shown).
This provides variable-length obfuscation per message type without leaking padding size in plaintext.

### 4.2 Header Field Definitions

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| `magic` | 0 | 4 | Protocol magic: `0x50414E44` ("PAND") |
| `version` | 4 | 1 | Protocol version: `0x00` |
| `beacon_id` | 5 | 8 | First 8 bytes of SHA256(crypto_key) |
| `opcode` | 13 | 1 | Command or response code |
| `seq_num` | 14 | 4 | Sequence number (little-endian uint32) |
| `nonce` | 18 | 24 | XChaCha20 nonce (CSPRNG) |
| `payload_len` | 42 | 4 | Length of (ciphertext + MAC) in bytes |

### 4.3 Server-to-Beacon Opcodes

| Opcode | Name | Description | Payload Structure |
|--------|------|-------------|-------------------|
| `0x00` | `NO_TASKS` | Poll response with no pending tasks | Empty |
| `0x01` | `ECHO` | Echo request for connectivity test | `uint16_t len + char data[len]` |
| `0x02` | `SLEEP` | Change sleep interval and jitter | `payload_sleep` |
| `0x04` | `FILE_READ` | Read file (legacy, small files <4KB) | `uint16_t path_len + wchar_t path[]` |
| `0xFF` | `DIE` | Terminate beacon | Empty |
| `0x10` | `BOF_EXEC` | Execute Cobalt Strike BOF | `payload_bof_exec` |
| `0x11` | `BOF_FREE` | Free cached BOF by ID | `uint32_t bof_id` |
| `0x12` | `FILE_DOWNLOAD` | Read entire file in one packet (legacy) | `payload_file_download` |
| `0x13` | `FILE_UPLOAD` | Write entire file in one packet (legacy) | `payload_file_upload` |
| `0x14` | `LONG_RUNNING_BOF` | Async BOF with subcommands | `uint32_t task_id + uint8_t subcmd + [args]` |
| `0x1E` | `ROTATE_KEY` | Rotate crypto key | `payload_rotate_key` |
| `0x20` | `FILE_DOWNLOAD_START` | Initiate chunked download | `payload_file_download_start` |
| `0x21` | `FILE_DOWNLOAD_CHUNK` | Request file chunk | `payload_file_download_chunk` |
| `0x22` | `FILE_UPLOAD_START` | Initiate chunked upload | `payload_file_upload_start` |
| `0x23` | `FILE_UPLOAD_CHUNK` | Send file chunk | `payload_file_upload_chunk` |
| `0x25` | `ETW_ENABLE` | Enable ETW bypass via HWBP | Empty |
| `0x26` | `ETW_DISABLE` | Disable ETW bypass (remove HWBP) | Empty |
| `0x40` | `START_RELAY` | Enable relay mode (P2P beacon) | Empty |
| `0x41` | `STOP_RELAY` | Disable relay mode, drain children | Empty |
| `0x42` | `RELAY_ADD_CHILD` | Add child to relay list | `[pipe_id:4][name_len:1][pipe_name]` |
| `0x43` | `RELAY_REMOVE_CHILD` | Remove child from relay list | `[pipe_id:4]` |
| `0x44` | `RELAY_DOWN` | Server -> Parent: downstream child data | `[pipe_id:4][len:4][encrypted_packet]` |

### 4.4 Beacon-to-Server Opcodes

| Opcode | Name | Description | Payload Structure |
|--------|------|-------------|-------------------|
| `0x01` | `BEACON_CHECK_IN` | Initial beacon registration | JSON sysinfo blob |
| `0x02` | `BEACON_POLL` | Request pending tasks | Empty |
| `0x03` | `BEACON_TASK_RESULT` | Command execution result | `uint8_t status + uint16_t len + char output[]` |
| `0x04` | `BEACON_ERROR` | Error notification | `uint16_t code + uint16_t len + char msg[]` |
| `0x10` | `FILE_CONTENT` | File read result (legacy, small files) | `payload_file_content` |
| `0x11` | `FILE_WRITE_RESULT` | File write confirmation (legacy) | `payload_file_write_result` |
| `0x12` | `BOF_OUTPUT` | BOF execution output | `uint16_t len + char output[]` |
| `0x13` | `LIST_FILES_RESULT` | Directory listing result | `payload_list_files_result` |
| `0x1F` | `KEY_ROTATE_ACK` | Key rotation acknowledgment | `payload_key_rotate_ack` |
| `0x20` | `FILE_DOWNLOAD_ACK` | Download initiation response | `payload_file_download_ack` |
| `0x21` | `FILE_CHUNK_DATA` | File chunk data | `payload_file_chunk_data` |
| `0x22` | `FILE_UPLOAD_ACK` | Upload chunk acknowledgment | `payload_file_upload_ack` |
| `0x40` | `RELAY_CHILD_UP` | Parent -> Server: upstream child data | `[pipe_id:4][len:4][encrypted_packet]` |

### 4.5 Payload Structures

```cpp

// S2B: SLEEP payload
struct payload_sleep {
    uint32_t sleep_ms;     // Sleep interval in milliseconds
    uint8_t  jitter_pct;   // Jitter percentage (0-100)
};

// S2B: BOF_EXEC payload
struct payload_bof_exec {
    uint16_t bof_len;      // Length of BOF binary
    uint16_t arg_len;      // Length of arguments
    // char bof_data[bof_len] + char args[arg_len] follow
};

// S2B: FILE_DOWNLOAD payload (legacy)
struct payload_file_download {
    uint16_t path_len;     // Length in wchar_t
    // wchar_t path[path_len] follows
};

// S2B: FILE_UPLOAD payload (legacy)
struct payload_file_upload {
    uint16_t path_len;     // Length in wchar_t
    uint32_t file_size;    // Expected file size
    // wchar_t path[path_len] + char data[file_size] follow
};

// S2B: ROTATE_KEY payload
// The beacon_id field is used for VERIFICATION ONLY - the beacon MUST reject
// this command if beacon_id does not match its own ID. The beacon's identifier
// remains unchanged after key rotation; only the crypto key is updated.
// This preserves malleable config associations keyed by beacon_id.
struct payload_rotate_key {
    uint8_t new_crypto_key[32];  // New 32-byte XChaCha20 key
    uint8_t beacon_id[8];        // Target beacon ID (verify against self)
};

// S2B: FILE_DOWNLOAD_START payload
struct payload_file_download_start {
    uint16_t path_len;     // Length in wchar_t
    uint32_t chunk_size;   // Requested chunk size (default: 4096)
    // wchar_t path[path_len] follows
};

// S2B: FILE_DOWNLOAD_CHUNK payload
struct payload_file_download_chunk {
    uint32_t chunk_index;  // Chunk number (0, 1, 2, ...)
    uint32_t offset;       // Byte offset in file
    uint32_t chunk_size;   // Bytes to read
};

// S2B: FILE_UPLOAD_START payload
struct payload_file_upload_start {
    uint16_t path_len;     // Length in wchar_t
    uint32_t file_size;    // Total file size
    uint32_t chunk_size;   // Chunk size for transfer
    // wchar_t path[path_len] follows
};

// S2B: FILE_UPLOAD_CHUNK payload
struct payload_file_upload_chunk {
    uint32_t chunk_index;  // Chunk number
    uint32_t offset;       // Byte offset
    uint32_t chunk_size;   // Bytes in this chunk
    uint8_t  is_last;      // 1=final chunk, 0=more coming
    // char data[chunk_size] follows
};


// B2S: FILE_CONTENT payload (legacy)
struct payload_file_content {
    uint16_t path_len;     // Length in wchar_t
    uint32_t file_size;    // File size in bytes
    uint8_t  status;       // 0=success, 1=error
    // wchar_t path[path_len] + char data[file_size] follow
};

// B2S: FILE_WRITE_RESULT payload
struct payload_file_write_result {
    uint8_t status;  // 0=success, 1=error
};

// B2S: KEY_ROTATE_ACK payload
struct payload_key_rotate_ack {
    uint8_t status;      // 0=OK (key accepted), 1=ERROR
    uint8_t reserved[3]; // Padding
};

// B2S: FILE_DOWNLOAD_ACK payload
struct payload_file_download_ack {
    uint32_t file_size;  // Actual file size (0 if error)
    uint8_t  status;     // 0=OK (file exists), 1=ERROR
};

// B2S: FILE_CHUNK_DATA payload
struct payload_file_chunk_data {
    uint32_t chunk_index;  // Chunk number
    uint32_t offset;       // Byte offset
    uint32_t chunk_size;   // Actual bytes sent
    uint8_t  status;       // 0=OK, 1=EOF (final), 2=ERROR
    // char data[chunk_size] follows (only if status != ERROR)
};

// B2S: FILE_UPLOAD_ACK payload
struct payload_file_upload_ack {
    uint32_t chunk_index;  // Which chunk this acknowledges
    uint8_t  status;       // 0=OK, 1=ERROR, 2=RETRY
};

// B2S: LIST_FILES_RESULT payload
struct file_entry {
    uint32_t attributes;   // FILE_ATTR_* bitfield
    uint64_t size;         // File size (0 for directories)
    uint64_t created;      // FILETIME
    uint64_t accessed;     // FILETIME
    uint64_t modified;     // FILETIME
    uint16_t name_len;     // Filename length in wchar_t
    uint16_t owner_len;    // Owner string length in wchar_t
    // wchar_t name[name_len] + wchar_t owner[owner_len] follow
};

struct payload_list_files_result {
    uint32_t total_entries;     // Total entries in result
    uint32_t entries_in_packet; // Entries in this packet
    uint8_t  status;            // 0=OK, 1=ERROR
    uint16_t error_len;         // Error message length (if status=1)
    // file_entry[entries_in_packet] follows (if status=0)
    // wchar_t error_msg[error_len] follows (if status=1)
};
```

### 4.6 File Entry Attributes

| Flag | Value | Description |
|------|-------|-------------|
| `FILE_ATTR_READONLY` | `0x0001` | Read-only file |
| `FILE_ATTR_HIDDEN` | `0x0002` | Hidden file |
| `FILE_ATTR_SYSTEM` | `0x0004` | System file |
| `FILE_ATTR_DIRECTORY` | `0x0010` | Directory entry |
| `FILE_ATTR_ARCHIVE` | `0x0020` | Archive file |
| `FILE_ATTR_NORMAL` | `0x0080` | Normal file (no other flags) |

### 4.7 Chunked Transfer Constants

```cpp
constexpr uint32_t DEFAULT_CHUNK_SIZE = 4096;   // 4KB default
constexpr uint32_t MAX_CHUNK_SIZE = 60000;      // ~60KB max (64KB packet limit)
```

## 5. Cryptographic Operations

### 5.1 Key Derivation

The beacon ID is derived from the initial (pre-shared) crypto key:

```
beacon_id = SHA256(crypto_key)[0:8]
```

This 8-byte identifier is used for:
- Packet header identification
- Server-side beacon routing
- Key rotation verification

**Note**: After key rotation, the beacon_id does NOT change. The beacon continues using its original
identifier to maintain malleable config associations and UI continuity. The new key is used only for
encryption/decryption of subsequent packets.


### 5.4 MAC Computation Detail

**Associated Data (AAD) Layout**:
```
┌─────────────────────────────────────────────────────────┐
│ AAD for MAC computation (47 bytes)                      │
├──────────┬────────┬──────────┬──────────┬───────────────┤
│ magic    │version │beacon_id │ opcode   │ seq_num       │
│ 4 bytes  │ 1 byte │ 8 bytes  │ 1 byte   │ 4 bytes       │
├──────────┴────────┴──────────┴──────────┴───────────────┤
│ padding_flags │ nonce (24 bytes)    │ payload_len      │
│ 1 byte        │ from header         │ 4 bytes          │
└─────────────────────────────────────────────────────────┘
```

**Critical**: The MAC is computed with the complete header including `payload_len`:

```
header_for_mac = complete_header_data  // payload_len included in AAD
```

This allows the receiver to verify the header before knowing the actual payload length.

### 5.5 Replay Protection

Sequence numbers provide replay protection:

- **Server**: Tracks last seen `seq_num` per beacon, rejects duplicates
- **Beacon**: Validates `seq_num` increments (optional, configurable)
- **Wraparound**: Sequence numbers wrap at `UINT32_MAX`

### 5.6 Key Rotation Protocol

```
Server                              Beacon
  │                                   │
  │── ROTATE_KEY (new_key, beacon_id)─▶│  (encrypted with OLD key)
  │                                   │
  │◀─ KEY_ROTATE_ACK (status)─────────│  (encrypted with OLD key)
  │                                   │
  │── subsequent packets ─────────────▶│  (encrypted with NEW key)
  │◀─ subsequent packets ──────────────│  (encrypted with NEW key)
```

**Key Rotation Steps**:
1. Server generates new 32-byte key
2. Server sends `ROTATE_KEY` (opcode 0x1E) with new key + beacon ID (encrypted with old key)
3. Beacon verifies `payload.beacon_id` matches its own `beacon_id`; rejects if mismatch
4. Beacon updates to new crypto_key, sends `KEY_ROTATE_ACK` (opcode 0x1F) using OLD key
5. Server receives ACK, switches to new key for subsequent packets
6. **Beacon ID remains unchanged**; only the crypto key is rotated

**Important**: The beacon identifier (`beacon_id` in packet header) does NOT change after rotation. This ensures:
- Malleable C2 config associations remain valid (server indexes by `beacon_id`)
- UI continuity: beacon appears as the same session
- No transition period needed where both keys are accepted

The beacon should derive its identifier from the original config's `crypto_key`, not from the rotated key.

## 6. Malleable C2 Configuration

### 6.1 Wrapper Macros

Wrappers are applied to base64url-encoded ciphertext for traffic disguise:

```
raw_request = prefix + base64url(ciphertext) + suffix
```

**Supported Macros**:

| Macro | Expansion | Example |
|-------|-----------|---------|
| `${TIMESTAMP}` | 10-digit Unix timestamp | `1712044800` |
| `${RAND_B64:N}` | N random base64 characters | `${RAND_B64:4}` -> `aB3x` |
| `${JUNK:N}` | N random alphanumeric chars | `${JUNK:8}` -> `kL9mN2pQ` |
| `${PAD_BASE64}` | Base64 padding pattern | `==a` or `=` |

**Example Configuration**:
```json
{
    "wrapper": {
        "prefix": "REQ_${RAND_B64:4}_",
        "suffix": "_${JUNK:8}"
    }
}
```

**Result**: `REQ_aB3x_<base64url_payload>_kL9mN2pQ`

### 6.2 Payload Location

Payload can be embedded in different HTTP request locations:

| Type | Value | Description | Example |
|------|-------|-------------|---------|
| `query_param` | 0 | URL query parameter | `?q=<payload>` |
| `path` | 1 | URL path segment | `/cdn/<payload>.png` |
| `body` | 2 | Request body | `POST /api data=<payload>` |

**Configuration**:
```json
{
    "payload_location": {
        "type": 0,  // query_param
        "param_name": "q"
    }
}
```

Or for path mode:
```json
{
    "payload_location": {
        "type": 1,  // path
        "path_prefix": "/cdn/",
        "path_suffix": ".png"
    }
}
```

### 6.3 Custom HTTP Headers

Additional headers injected into all beacon requests:

```json
{
    "http_headers": [
        {"name": "X-Request-ID", "value": "${RAND_B64:16}"},
        {"name": "X-Session-Token", "value": "static_value"}
    ]
}
```

**Limits**:
- Maximum 16 custom headers
- Header name: max 64 bytes
- Header value: max 1024 bytes

### 6.4 User-Agent Rotation

Pre-configured User-Agent strings for traffic disguise:

| Name | User-Agent | Description |
|------|------------|-------------|
| `default` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...` | Chrome on Windows 10 |
| `alt1` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0` | Firefox on Windows |
| `alt2` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Edg/120.0.0.0` | Edge on Windows |
| `alt3` | `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ... Safari/605.1.15` | Safari on macOS |
| `alt4` | `Mozilla/5.0 (X11; Linux x86_64) ... Chrome/120.0.0.0` | Chrome on Linux |
| `alt5` | `Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) ... Mobile/15E148` | Mobile Safari |

## 7. Acceptance Criteria

### Packet Parsing

- **AC-001**: Given a valid 47-byte header with correct magic, when parsed, then all fields are extracted correctly
- **AC-002**: Given a packet with invalid magic, when parsed, then the packet is rejected with error code `BAD_MAGIC`
- **AC-003**: Given a packet with wrong version, when parsed, then the packet is rejected with error code `BAD_VERSION`
- **AC-004**: Given a packet with truncated payload, when parsed, then the packet is rejected with error code `PAYLOAD_OVERFLOW`

### Cryptographic Operations

- **AC-005**: Given valid ciphertext and key, when decrypted, then plaintext matches original
- **AC-006**: Given tampered ciphertext, when decrypted, then MAC verification fails and packet is rejected
- **AC-007**: Given reused nonce, when encrypting, then the implementation SHOULD detect and prevent (implementation-specific)
- **AC-008**: Given wrong key, when decrypting, then MAC verification fails

### Malleable C2

- **AC-009**: Given wrapper prefix with macros, when expanded, then macros are replaced with valid random data
- **AC-010**: Given query_param payload location, when constructing request, then payload is base64url-encoded in query string
- **AC-011**: Given custom headers, when sending request, then all headers are included

### Key Rotation

- **AC-012**: Given ROTATE_KEY command, when beacon validates beacon_id, then key is accepted only if beacon_id matches
- **AC-013**: Given key rotation, when acknowledged, then subsequent packets use new key

## 8. Dependencies & External Integrations

### Cryptographic Libraries

- **LIB-001**: Server: XChaCha20-Poly1305 implementation (libsodium or pycryptodome). Beacon: Bastia library.
- **LIB-002**: SHA256 for beacon ID derivation
- **LIB-003**: CSPRNG for nonce generation (os.urandom or arc4random)

### Transport Layer

- **EXT-001**: HTTPS server (Flask + Gunicorn or similar)
- **EXT-002**: WebSocket support (Flask-SocketIO)
- **EXT-003**: TLS termination (nginx, Caddy, or cloud provider)

### Beacon Runtime

- **PLT-001**: Windows x64
- **PLT-002**: Clang++ 19+ with MinGW toolchain
- **PLT-003**: Freestanding C++20 (no standard library dependencies)

### Compliance

- **COM-001**: Operational use requires explicit authorization
- **COM-002**: Subject to export controls.

## 9. Examples & Edge Cases

### 9.1 Complete Packet Example

**Check-in Packet (Beacon -> Server)**:

The beacon sends a binary payload containing system information:

```
Header (hex):
44 4e 41 50    magic = 0x50414E44 ("PAND")
00             version = 0
a1 b2 c3 d4    beacon_id (8 bytes)
e5 f6 a7 b8
01             opcode = 0x01 (BEACON_CHECK_IN)
01 00 00 00    seq_num = 1
00             padding_flags = 0 (no padding)
[24-byte nonce]
00 00 00 00    payload_len (actual value, not zeroed)
```

Payload (binary system info):
[4] os_major        (PEB->OSMajorVersion)
[4] os_minor        (PEB->OSMinorVersion)  
[4] os_build        (PEB->OSBuildNumber)
[2] arch            (IMAGE_FILE_MACHINE_*)
[1] is_wow64
[1] is_elevated     (TokenElevation)
[1] is_domain_joined (ComputerNameDnsDomain)
[4] pid
[2] process_name_len
[..] process_name
[2] username_len
[..] username
[2] computer_name_len
[..] computer_name
[2] domain_len
[..] domain
[4] ram_mb
[1] cpu_cores
[1] ip_count
[..] ip_count * { [1] len, [len] addr }  (dotted-decimal UTF-8)

After encryption (PKCS#7 padding applied to inner plaintext):
[padding: 0-15 bytes] [ciphertext: N bytes] [MAC: 16 bytes]

### 9.3 B2S: Task Result

```python
# Beacon responds with output
opcode = 0x03  # BEACON_TASK_RESULT
status = 0     # Success
output = b"WORKSTATION01\\admin\n"

payload = struct.pack('<BH', status, len(output)) + output
```

### 9.4 Chunked File Download Flow

```
Server                              Beacon
  │                                   │
  │── FILE_DOWNLOAD_START ───────────▶│  path=C:\secret.txt, chunk_size=4096
  │◀─ FILE_DOWNLOAD_ACK (size=10KB)───│  File exists, 10240 bytes
  │                                   │
  │── FILE_DOWNLOAD_CHUNK (idx=0) ───▶│  Request bytes 0-4095
  │◀─ FILE_CHUNK_DATA (idx=0, OK) ────│  First 4096 bytes
  │                                   │
  │── FILE_DOWNLOAD_CHUNK (idx=1) ───▶│  Request bytes 4096-8191
  │◀─ FILE_CHUNK_DATA (idx=1, OK) ────│  Next 4096 bytes
  │                                   │
  │── FILE_DOWNLOAD_CHUNK (idx=2) ───▶│  Request bytes 8192-10239
  │◀─ FILE_CHUNK_DATA (idx=2, EOF) ───│  Final 2048 bytes + EOF flag
  │                                   │
```

### 9.5 Edge Cases

**Empty Payload**:
- Valid for `NO_TASKS`, `DIE`, `BEACON_POLL`
- Ciphertext = MAC only (16 bytes)
- `payload_len = 16`

**Maximum Padding**:
- `padding_flags = 0x0F` (15 bytes)
- Random bytes between header and ciphertext
- Receiver skips padding based on flags

**Large File Upload**:
- Files MUST use chunked upload (opcodes 0x22, 0x23)
- Legacy non-chunked file upload (0x13) supported only for small files <4KB

**Sequence Number Wraparound**:
- After `seq_num = 4294967295`, next packet uses `seq_num = 0`
- Server MUST handle wraparound correctly

## 10. Validation Criteria

### Protocol Conformance

1. **Header Validation**: All packets MUST have valid magic, version, and opcode
2. **Length Validation**: `payload_len` MUST match actual ciphertext + MAC length
3. **Padding Validation**: Padding size MUST be 0-15 bytes
4. **Nonce Uniqueness**: Nonce MUST NOT repeat within same key session

### Cryptographic Validation

1. **Key Length**: Encryption key MUST be exactly 32 bytes
2. **Nonce Length**: Nonce MUST be exactly 24 bytes
3. **MAC Verification**: All packets MUST verify Poly1305 tag before processing
4. **Beacon ID Match**: Beacon MUST verify beacon_id in S2B packets matches self

### Malleable C2 Validation

1. **Macro Expansion**: All macros MUST be expanded before transmission
2. **Wrapper Application**: Prefix/suffix MUST be applied to base64url payload
3. **Payload Location**: Payload MUST be placed in configured location (query/path/body)
4. **Header Injection**: Custom headers MUST be added to all requests

## 11. Related Specifications / Further Reading

- **XChaCha20-Poly1305**: Bernstein, D.J. "ChaCha, a variant of Salsa20" (2008)
- **Poly1305**: Bernstein, D.J. "The Poly1305-AES message-authentication code" (2005)
- **Cobalt Strike BOF**: Cobalt Strike Beacon Object Files specification
- **PCFG Format**: Internal FGL configuration format (separate document)
- **TEAMSERVER**: Server implementation details (server/TEAMSERVER.md)

---

**Document Control**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-04-02 | FGL | Initial specification |
| 1.2 | 2026-05-08 | FGL | Fixed opcode values to match implementation; added ROTATE_KEY clarification (beacon_id verification only, not ID change); added LONG_RUNNING_BOF, relay opcodes, ETW opcodes; updated chunked file transfer opcodes to 0x20-0x23 |
| 1.3 | 2026-05-08 | FGL | Removed padding_flags from header (47->46 bytes); padding now handled via PKCS#7 only (plaintext layer) |

**Classification**: FGL Internal Use Only
