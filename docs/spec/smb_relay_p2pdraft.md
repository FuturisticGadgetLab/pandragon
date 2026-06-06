# SMB Relay + P2P Beacon Chaining

Created: 2026-04-14

## Notes
- Parent is dumb relay: never sees child's plaintext
- Random pipe names, no beacon_id in cleartext
- Server maintains routing graph
- Multi-hop: A -> B -> C chains work
- Pipe name = credential

## Routing Graph (Server-Side)

```python
class BeaconRoute:
    beacon_id: bytes           # 8 bytes
    transport: str             # "direct" | "relay"
    # Direct fields:
    listener_name: str         # e.g., "operator_https"
    # Relay fields:
    via_beacon_id: bytes       # parent's beacon_id (or None if direct)
    parent_pipe_id: int        # parent's local pipe_id (or None if direct)
    depth: int                 # 0 = direct, 1 = relayed once, 2 = twice, etc.
    last_seen: float
    is_alive: bool
```

Server maintains:
```python
routes: Dict[bytes, BeaconRoute]     # beacon_id -> route
relay_children: Dict[bytes, List[bytes]]  # parent_beacon_id -> [child_beacon_id, ...]
```

When parent disconnects:
1. Mark parent offline
2. For each child in relay_children[parent_id]: mark offline too
3. Optionally: attempt re-parenting if other parents available

---

## Relay Opcodes (Extends existing Pandragon protocol)

```python
RELAY_REGISTER   = 0x10  # Parent -> Server: "I created pipe_id=X, ready for children"
RELAY_CHILD_UP   = 0x11  # Parent -> Server: "pipe_id=X has data (from child)"
RELAY_DOWN       = 0x12  # Server -> Parent: "forward to pipe_id=X (to child)"
RELAY_DISCONNECT = 0x13  # Parent -> Server: "pipe_id=X disconnected (child gone)"
RELAY_UNREGISTER = 0x14  # Parent -> Server: "destroyed pipe_id=X (listener down)"
RELAY_MULTI      = 0x15  # Server -> Parent: "forward to pipe_id=X, which is ALSO a relay parent"
```

---

## Wire Format

RELAY_REGISTER (0x10):  [pipe_id:4][name_len:1][pipe_name]
RELAY_CHILD_UP (0x11):   [pipe_id:4][len:4][encrypted_child_packet]
RELAY_DOWN (0x12):       [pipe_id:4][len:4][encrypted_child_packet]
RELAY_MULTI (0x15):      nested relay: [pipe_id:4] -> [inner:0x12][pipe_id:4][len:4][packet]
RELAY_DISCONNECT (0x13): [pipe_id:4]
RELAY_UNREGISTER (0x14):  [pipe_id:4]

---

## Pipe Authentication Problem

**Question**: How does parent know a pipe connection is from a legitimate child vs random noise/attacker?

**Answer**: Pipe name is **operator-defined** (via server redirect command). This allows threat emulation; use names like `\.\pipe\WindowsUpdate`, `\.\pipe\svcctl`, etc. The server config supports macros (`${RAND_B64:N}`, `${JUNK:N}`, `${HOST}`) for randomized names when needed.

Flow:
1. Operator specifies pipe name in redirect command: `redirect target_host pipe_name \\.\pipe\msagent_XYZ`
   Or with macros: `redirect target_host pipe_name \\.\pipe\${RAND_B64:16}`
2. Server expands macros -> concrete pipe name
3. Server sends `RELAY_CREATE_PIPE` to parent with the expanded pipe name
4. Parent creates `\\.\pipe\<expanded_name>` via CreateNamedPipe
5. Child connects via `CreateFile(\\.\pipe\<expanded_name>)`
6. Parent accepts the connection

**Why this works**:
- Pipe name is operator-chosen. Matches legitimate Windows pipe names for emulation.
- Server only tells parent to create pipes for active redirect commands.
- If attacker connects to wrong pipe name: connection rejected (pipe doesn't exist).
- If attacker somehow learns pipe name: connects, sends encrypted garbage. Server tries to decrypt -> MAC fail -> drops it. No data leak.
- Server can limit: "expect max N children per pipe"; parent drops extras.

**Additional guard**: Parent sends RELAY_CHILD_UP with the encrypted packet. Server attempts decryption. If MAC fails repeatedly from same pipe_id, server sends `RELAY_KILL_PIPE` to parent.

---

## Child Spawn Flow (redirect command)

```
Server -> Parent: [redirect command]
    pipe_name: "\\\\.\pipe\\<32_hex>"
    child_config: (encrypted beacon config for pipe channel)
    spawn_method: "smbexec" | "wmi" | "psexec" | "manual"

Parent:
    1. CreateNamedPipe(\\.\pipe\<32_hex>)
    2. Send RELAY_REGISTER(pipe_id=NEW) to server
    3. Spawn child process (inject the child_config + pipe_name)
    4. Wait for child to connect
    5. AcceptNamedPipe()
    6. Read [4B BE length][encrypted packet] from pipe
    7. Send RELAY_CHILD_UP(pipe_id, encrypted_packet) to server

Child:
    1. Connect to \\.\pipe\<32_hex>
    2. Send encrypted check-in packet
    3. Receive encrypted response
    4. Normal beacon loop over pipe transport
```

---

## Beacon-Side: Pipe Transport

Channel type: PCFG_CHANNEL_PIPE = 4 (config_parser.h)

C2 channel format:
[type=4][pipe_name_len:1][pipe_name][port=0][max_failures:1][backoff_ms:4]

Client (child):
- WaitNamedPipe, CreateFile, WriteFile/ReadFile with 4B length prefix

Parent:
- CreateNamedPipe, ConnectNamedPipe, accept loop
- Read [len:4][packet] -> RELAY_CHILD_UP
- RELAY_DOWN -> write [len:4][packet]

Buffer: static g_pipe_buf[65536] like TCP

---

## Server-Side: Relay Handler

handle_relay_up: parent_beacon_id + pipe_id -> find child -> handle_beacon_packet(child_id, encrypted)

handle_relay_down: if depth==1 send RELAY_DOWN to parent, else wrap in RELAY_MULTI

---

## Implementation

Phase 1 (Beacon pipe transport): DONE
- config_parser.h: PCFG_CHANNEL_PIPE = 4
- pipe_transport.cpp: client + listener mode
- net_abstract: transport type = "pipe"
- main.cpp: initNetworkFromConfig + failover

### Phase 2: Relay Engine (Parent Mode)

Non-blocking, integrated into main loop before pollForCommands(). Not a separate thread.

Commands:
- START_RELAY (0x10): enable relay mode
- RELAY_ADD_CHILD (0x15): [pipe_id:4][name_len:1][pipe_name]
- RELAY_REMOVE_CHILD (0x16): [pipe_id:4]
- STOP_RELAY (0x14): disable, drain children

Files: managers.h/cpp, pipe_transport.cpp, bastia.h, main.cpp, handlers.cpp

Phase 3 (Server routing): TODO - handle_relay_up/down, pipe-to-child mapping
Phase 4 (Multi-hop): Future - RELAY_MULTI nested frames, route graph traversal

---

## Open Questions

1. **Should pipe transport use the same bastia crypto as HTTP/TCP?**
   YES. Child encrypts with its key -> parent receives encrypted blob -> parent wraps in RELAY -> server decrypts with child's key.

2. **What if parent needs to send its OWN traffic AND relay child traffic?**
   Parent's own channel is independent. RELAY_CHILD_UP is a separate opcode. Server processes both. No conflict.

3. **How does server distinguish parent's packet from relayed child's packet?**
   Same Pandragon header: beacon_id in the header identifies WHOSE packet it is. Server looks up route by beacon_id. If route.transport == "relay", server knows to forward to parent. If route.transport == "direct", server processes normally.

   Child's packet arrives ENCAPSULATED in RELAY_CHILD_UP from parent. Server receives parent's packet, sees opcode=0x11, extracts child's encrypted blob, processes it as child's packet. Parent's own packets use normal opcodes (0x00 checkin, 0x01 data, etc.).

4. **Pipe name length?**
   32 hex chars (128-bit random). Max named pipe name on Windows is 256 chars, so 32 is fine.

5. **Should child send beacon_id in plaintext on first connect?**
   No; see design goal #2. Server learns child identity from the encrypted check-in packet (which contains beacon_id in the Pandragon header). The pipe name is the only "credential" and it's server-generated random.

---

## Notes
- This draft is the LIVING document. Update it as architecture evolves.
- Key principle: parent is a DUMB relay. It reads pipe_id from RELAY frames and forwards encrypted blobs verbatim. It never decrypts child traffic.
- PFS: each beacon has its own crypto_key. Parent key ≠ child key.
- The relay graph on the server is a simple directed graph. DFS/BFS finds routes to any beacon.
