================================================================================
                  PANDRAGON - C2 Beacon Framework v1.0
================================================================================

Mama look, I finally reached a major version after 1.5 months of development!
                                        ,   ,
  P                                     $,  $,     ,
                                        "ss.$ss. .s'
    A                           ,     .ss$$$$$$$$$$s,
                                $. s$$$$$$$$$$$$$$`$$Ss
      N                         "$$$$$$$$$$$$$$$$$$o$$$       ,
                               s$$$$$$$$$$$$$$$$$$$$$$$$s,  ,s
         D                    s$$$$$$$$$"$$$$$$""""$$$$$$"$$$$$,
                              s$$$$$$$$$$s""$$$$ssssss"$$$$$$$$"
           R                 s$$$$$$$$$$'         `"""ss"$"$s""
                             s$$$$$$$$$$,              `"""""$  .s$$s
             A               s$$$$$$$$$$$$s,...               `s$$'  `
                         `ssss$$$$$$$$$$$$$$$$$$$$####s.     .$$"$.   , s
               G           `""""$$$$$$$$$$$$$$$$$$$$#####$$$$$$"     $.$'
                                 "$$$$$$$$$$$$$$$$$$$$$####s""     .$$$|
                 O                "$$$$$$$$$$$$$$$$$$$$$$$$##s    .$$" $
                                   $$""$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"
                    N             $$"  "$"$$$$$$$$$$$$$$$$$$$$S""""'
                             ,   ,"     '  $$$$$$$$$$$$$$$$####s
                             $.          .s$$$$$$$$$$$$$$$$$####"
                 ,           "$s.   ..ssS$$$$$$$$$$$$$$$$$$$####"
                 $           .$$$S$$$$$$$$$$$$$$$$$$$$$$$$#####"
                 Ss     ..sS$$$$$$$$$$$$$$$$$$$$$$$$$$$######""
                  "$$sS$$$$$$$$$$$$$$$$$$$$$$$$$$$########"
           ,      s$$$$$$$$$$$$$$$$$$$$$$$$#########""'
           $    s$$$$$$$$$$$$$$$$$$$$$#######""'      s'         ,
           $$..$$$$$$$$$$$$$$$$$$######"'       ....,$$....    ,$
            "$$$$$$$$$$$$$$$######"' ,     .sS$$$$$$$$$$$$$$$$s$$
              $$$$$$$$$$$$#####"     $, .s$$$$$$$$$$$$$$$$$$$$$$$$s.
   )          $$$$$$$$$$$#####'      `$$$$$$$$$###########$$$$$$$$$$$.
  ((          $$$$$$$$$$$#####       $$$$$$$$###"       "####$$$$$$$$$$
  ) \         $$$$$$$$$$$$####.     $$$$$$###"             "###$$$$$$$$$
 (   )        $$$$$$$$$$$$$####.   $$$$$###"                ####$$$$$$$$$
 )  ( (       $$"$$$$$$$$$$$#####.$$$$$###' PANDRAGON       .###$$$$$$$$$$
 (  )  )   _,$"   $$$$$$$$$$$$######.$$##'                .###$$$$$$$$$$
 ) (  ( \.         "$$$$$$$$$$$$$#######,,,.          ..####$$$$$$$$$$$"
(   )$ )  )        ,$$$$$$$$$$$$$$$$$$####################$$$$$$$$$$$"
(   ($$  ( \     _sS"  `"$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$S$$,
 )  )$$$s ) )  .      .   `$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$"'  `$$
  (   $$$Ss/  .$,    .$,,s$$$$$$##S$$$$$$$$$$$$$$$$$$$$$$$$S""        '
    \)_$$$$$$$$$$$$$$$$$$$$$$$##"  $$        `$$.        `$$.
        `"S$$$$$$$$$$$$$$$$$#"      $          `$          `$
            `"""""""""""""'         '

================================================================================
                     LICENSE & TERMS OF USE
===============================================================================

  Pandragon is released under the Polyform Noncommercial License 1.0.0.
See the LICENSE file in the repository root for the full terms.

  In short: you may use, modify, and share this software for any
noncommercial purpose, including personal research, education, public
security testing, and hobby projects. Commercial use requires a separate
license from the authors.

                         AUTHORIZED USE ONLY
------------------------------------------------------------------------------

  This framework is intended exclusively for:
  - Authorized penetration testing with written permission from the target
    system owner(s)
  - Personal security research on systems you own or have explicit permission
    to test
  - Academic research and cybersecurity education strictly within dedicated, isolated
laboratory networks (air-gapped or VLAN-segmented) where the user owns all target
systems or has explicit, written authorization from the sole network owner.
  Use in production environments, public networks, or live targets without written
authorization is strictly forbidden.
  The authors disclaim all liability for misuse.
  This software is provided solely for use within jurisdictions where penetration
    testing without prior authorization is strictly illegal without a license.
    The authors explicitly prohibit the use of this software in any jurisdiction where
    the user does not hold a valid, government-issued penetration testing license or
    explicit court-authorization. By using this software, you accept full criminal
    and civil liability.

  Do no evil.

================================================================================
                                OVERVIEW
================================================================================

Pandragon is a freestanding C2 framework targeting Windows x86_64.
Built without CRT, IAT, or SEH. Uses secure XChaCha20-Poly1305 AEAD
encryption for all communications. API resolution via PEB walking with
lazy module loading. Syscalls execute indirectly via HWBP + VEH to bypass
user-mode hooks.

Authors: Serexp (Lead), Sakocc, Maddie

================================================================================
                                FEATURES
================================================================================

- Sleep Obfuscation: Ekko-style timer-based encryption of code sections
- Indirect Syscalls: HWBP + VEH 3-phase system bypasses user-mode hooks
- Randomized RET Gadgets: PEB-LDR walk, up to 32 random gadgets per syscall
- ETW Bypass: HWBP on NtTraceEvent via separate DR registers
- Lazy Unhook: Unhooks all DLLs only before BOF execution through novel techniques
- PEB Walking: No Import Address Table, direct PEB resolution
- XChaCha20-Poly1305: AEAD encryption, 32-byte keys, 24-byte nonces
- Multi-Channel Failover: Unlimited C2 channels with automatic failover
- COFF/BOF Loader: Cobalt Strike-compatible BOF execution
- Async BOF + Sleep Mask Integration: Async BOFs run while beacon is Ekko-masked via IPC.
- Long-Running Async BOFs: Threaded execution with shared memory IPC
- Custom Heap: No reliance on Windows heap APIs
- Server-side Donut: PE/.NET execution via Donut -> shellcode_loader BOF (execute_pe / execute_assembly)

================================================================================
                                QUICK START
================================================================================

Prerequisites:
  - Clang++ with MinGW target: apt install clang mingw-w64 lld
  - Python 3.x for teamserver and GUI
  - openssl (for SSL cert generation): apt install openssl
  - python3-venv (for isolated Python env): apt install python3-venv
  - Initialize submodules: git submodule update --init --recursive
  - Server setup: make setup      # One-shot: venv, deps, Cython parser build

All commands below assume the project root as working directory
(where this README.txt lives) unless otherwise noted.

Build Commands:
  make keys              - Generate crypto keys
  make                   - Release beacon build (~82KB)
  make DEBUG=1           - Debug beacon build with console output
  make clean && make     - Full rebuild
  make CONFIG_FILE=...   - Custom config file (default: Beacon/config/default.json)
  make force-config      - Regenerate config even if inputs haven't changed

Server (Production — standalone binary for deployment):
  make setup              # Create venv, install deps, build Cython parser
  make server             # Builds build/PandragonServer (PyInstaller binary)
  build/PandragonServer   # Run the binary directly (no venv needed)

Server (Development — hot-reload, tests, debug):
  make setup                      # Recommended first run
  make run-server                 # Builds parser if needed, starts teamserver
  make run-server-args ARGS="..." # Pass custom args, e.g. --debug or "create admin"
  make server-test                # Build parser + run tests (64 tests)
  make build-parser               # Build Cython parser only
  make venv                       # Create venv + install deps only
  make clean-venv                 # Remove venv and parser artifacts

Server commands:
  cd server && server/venv/bin/python run.py create admin      - Create operator account
  make run-server                                              - Start server (from project root)
  # Server must be started from server/ directory (or use --data-dir server/)
  # because config paths (SSL certs, known_beacons.json) are relative.

  Rebuild parser + test on every change:
    ls server/protocol/parser.pyx | entr -c make server-test

Configuration:
  server/config.json           - Main server config (listeners, routes, logging)
  server/known_beacons.json    - Beacon PSK database (generated by make keys)
  server/config.json           - Also contains inline operators (run.py create)
  Tools:
    tools/config_builder.py    - Encrypts beacon config into the binary
    Beacon/config/default.json - Default beacon config (edit before building)

Operator GUI:
  make setup              # One-time environment setup
  make run-server         # Starts teamserver; GUI connects via WebSocket
  make run-gui            # Launch GUI (from project root, uses venv)

============================================================================
                              DOCKER (TEAMSERVER)
============================================================================

  The teamserver can be deployed via Docker. The beacon and GUI are not
  containerised — the beacon is a Windows PE and the GUI is a desktop app.

  Prerequisites:
    - Docker Engine 24+ with Compose V2 plugin

  Usage:

    # 1. Initial setup (if not already done)
    make keys              # generate known_beacons.json
    make ssl-cert          # generate SSL cert (already done if you ran make setup)

    # 2. Edit server/config.json to suit your deployment
    #    (listener addresses, ports, operators, logging, etc.)

    # 3. Build and start the container
    make docker-build      # docker compose build
    make docker-run        # docker compose up -d

    # 4. Create an operator account
    docker compose exec teamserver python run.py create <username>

    # 5. View logs
    make docker-logs       # docker compose logs -f

    # Stop the container
    make docker-stop       # docker compose down

  How it works:
    - The image is built from server/Dockerfile on python:3.11-slim
    - The server/ directory is bind-mounted to /app inside the container
    - Config, SSL certs, and known_beacons.json are edited on the host
      and reflected in the container immediately (no rebuild needed)
    - Cython extensions are recompiled automatically on first start if
      the mounted directory does not contain the compiled .so files
    - Runtime data (sessions, downloads, logs) persists in server/ on
      the host

  Ports (default config):
    6767/tcp  — Operator HTTPS (WebSocket + beacon routes)
    8080/tcp  — Beacon HTTP
    6868/tcp  — Beacon TCP (localhost only by default)

  Docker Compose config: docker-compose.yml

Quick-start cheat sheet (copy-paste from project root):
  # 1. Install system deps (Debian/Ubuntu)
  sudo apt install clang mingw-w64 lld openssl python3-venv

  # 2. Build beacon
  make keys       # only needed if known_beacons.json absent
  make            # runs config_builder.py + compiles pandragon.exe

  # 3. Server setup + start (one command each)
  make setup      # Creates venv, installs deps, builds Cython parser, SSL certs
  make run-server # Starts teamserver

  # 4. Create operator (one-time)
  make run-server-args ARGS="create admin"   # from project root
  # Or: cd server && ../server/venv/bin/python run.py create admin

  # 5. Connect GUI (separate terminal)
  make run-gui    # from project root (uses venv)

================================================================================
                    INDIRECT SYSCALL SYSTEM (VEH + HWBP)
================================================================================

Architecture:
  1. Dr0 breakpoint set on PrepareSyscall() wrapper function
  2. VEH handler catches single-step exception
  3. Phase1: Cache NT function address + syscall number (SSN)
  4. Phase2: Detect hooks via Halos Gate - scan neighboring SSNs
  5. Phase3: Spoof return address using randomized RET gadgets

Gadget Collection:
  - PEB-LDR walk enumerates all loaded modules (excluding self)
  - Scans RX sections for 'add rsp, imm8; ret' patterns
  - Up to 32 unique gadgets cached
  - Random selection per syscall via TSC-derived index

ETW Bypass:
  - Same VEH handles ETW bypass (different DR registers)
  - HWBP on NtTraceEvent uses DR1-3 (DR0 reserved for syscalls)
  - Returns immediately without executing ETW logging

Thread Safety:
  - Uses dedicated syscall thread captured at init
  - Thread handle stored in syscalls_ctx->myThread
  - All indirect syscalls route through this single thread

================================================================================
                          BOF EXECUTION ENGINE
================================================================================

COFF Loader:
  - Parses COFF header, optional header, section headers
  - Applies relocations for absolute addresses
  - Resolves imports: MODULE$Function syntax (e.g., NTDLL$NtAllocateVirtualMemory)
  - Allocates executable memory, copies code, applies permissions

API Compatibility:
  - Full beacon.h implementation: BeaconDataParse, BeaconFormat*, BeaconPrintf
  - Token functions: BeaconUseToken, BeaconRevertToken, BeaconIsAdmin
  - Spawn+Inject: BeaconInjectProcess, BeaconInjectTemporaryProcess
  - Utility: toWideChar, BeaconCleanupProcess

Caching:
  - BOFs cached by 32-bit ID in LRU-style cache
  - Cache hit: instant execution, no re-parsing
  - Cache miss: full COFF parsing and import resolution
  - Explicit eviction via BOF_FREE command
  - Max cache size prevents memory exhaustion

The BOF engine is very loosely based on TrustedSec's implementation.

================================================================================
                    ASYNC LONG-RUNNING BOFS
================================================================================

Architecture:
  - BOF spawned in helper thread with isolated 64KB stack
  - Does NOT block main beacon sleep/poll loop
  - Uses shared memory region + event for IPC
  - Task ID (uint32_t) tracks async jobs server-side

Channel Types:
  - Shared Memory (default): Lower latency, single process only
  - Named Pipe: For P2P beacon chaining via SMB

Signal Handling:
  - ABORT (subcmd=1): Signal BOF to terminate cleanly
  - UPDATE_ARGS (subcmd=2): Inject new arguments into running BOF
  - REMOVE (subcmd=3): Force remove from async queue
  - FORCE_SLEEP (3): Request beacon enter sleep mask for N seconds
  - WAKEUP_SEND (4): Request beacon wake, flush output, re-enter mask
  - WAKEUP_EXIT (5): Request beacon wake and restore main loop (REQUIRED)

Output Handling:
  - BOF writes to shared memory channel
  - Beacon polls channel, sends output to server
  - Supports large output via chunked transmission

================================================================================
            ASYNC BOF + SLEEP MASK INTEGRATION (EKKO)
================================================================================

Problem: When Ekko encrypts .text (including beacon functions), an async BOF
cannot call beacon functions directly - it would crash. The solution: BOFs
signal the main beacon thread via the shared bof_channel, which reads and acts
on signals before/after sleep cycles.

BOF SDK Macros (beacon_compatibility.h):
  BADGER_FORCE_SLEEP(sec)   - Request beacon to enter Ekko sleep mask for 'sec' seconds
  BADGER_WAKEUP_SEND()      - Request beacon to wake, flush output, re-enter mask
  BADGER_WAKEUP_EXIT()      - Request beacon to wake and restore main loop (MUST CALL)
  BADGER_STOP_TASK()        - Check if operator sent stop_task (returns true/false)

Flow:
  1. Async BOF starts -> writes FORCE_SLEEP + duration to channel
  2. Main loop (before ExecuteSleep) checks channel, overrides sleep_ms
  3. Ekko encrypts .text, beacon sleeps masked
  4. BOF does work -> writes WAKEUP_SEND to channel
  5. Main loop (after wake) flushes all async BOF output, re-enters sleep
  6. BOF finishes -> writes WAKEUP_EXIT to channel
  7. Main loop wakes, restores normal sleep, cleans up BOF state

CRITICAL: Every async BOF MUST call BADGER_WAKEUP_EXIT before returning.
          Failure to do so leaves the beacon asleep indefinitely.

Example BOF (BofDev/async_bof_test.c):
  void go(char* args, int len) {
      datap parser; BeaconDataParse(&parser, args, len);
      int sleep_sec = BeaconDataInt(&parser);  // e.g., 30
      if (sleep_sec <= 0) sleep_sec = 30;

      BADGER_FORCE_SLEEP(sleep_sec);  // Beacon enters Ekko mask

      for (int i = 0; i < 3; i++) {
          if (BADGER_STOP_TASK()) { BADGER_WAKEUP_EXIT(); return; }
          BeaconPrintf(CALLBACK_OUTPUT, "[*] Working... %d/3", i+1);
          BADGER_WAKEUP_SEND();  // Beacon wakes, flushes output, re-masks
      }
      BADGER_WAKEUP_EXIT();  // Beacon wakes, restores main loop
  }

Server sees: async BOF output streamed while beacon is masked.

================================================================================
                    SERVER-SIDE DONUT INTEGRATION
================================================================================

Architecture: Operator uploads PE (.exe/.dll) -> Server uses Donut to generate
PIC shellcode -> Server sends shellcode_loader BOF with raw shellcode as argument.
Zero beacon bloat - the ~500-byte shellcode_loader BOF is the universal PE runner.

Commands (via Operator WebSocket):

  execute_pe - Execute native PE (EXE or DLL)
    {
      "type": "execute_pe",
      "beacon_id": "b-123...",
      "pe_data": "<base64-encoded PE>",
      "pe_filename": "mimikatz.exe",
      "cls": null,           // optional: .NET class name
      "method": null,        // optional: .NET method name
      "params": "sekurlsa::logonpasswords",  // optional: args
      "runtime": "v4.0.30319",  // optional: .NET runtime
      "arch": 2,             // optional: 1=x86, 2=x64, 3=both (default: 2)
      "bypass": 3            // optional: 1=Amsi, 2=Wldp, 3=both (default: 3)
    }

  execute_assembly - Execute .NET assembly (convenience alias for execute_pe with cls/method)
    {
      "type": "execute_assembly",
      "beacon_id": "b-123...",
      "assembly_data": "<base64-encoded .NET assembly>",
      "assembly_name": "SharpHound.exe",
      "cls": "SharpHound.Program",  // REQUIRED
      "method": "Main",             // optional: default "Main"
      "params": "",                 // optional
      "runtime": "v4.0.30319"       // optional
    }

Server processing:
  1. Decode base64 PE data
  2. Call donut.create() with params -> raw PIC shellcode
  3. Build BOF args: [encoding=2 (raw)][shellcode_len:u32][shellcode]
  4. Queue BOF_EXEC task with shellcode_loader.o + args
  5. Beacon executes shellcode_loader -> allocates RWX -> copies & runs shellcode

BOF (BofDev/shellcode_loader.c):
  - Allocates RWX via BeaconVirtualAlloc
  - Copies shellcode
  - Executes via function pointer
  - Frees memory on completion

Advantages:
  - No beacon bloat (PE execution is BOF-side)
  - Update Donut on server -> all beacons benefit
  - Supports any PE: native EXE/DLL, .NET assemblies
  - Configurable AMSI/WLDP bypass, compression, entropy

Requirements:
  pip install donut-shellcode  # in server venv

================================================================================
                    SLEEP OBFUSCATION (EKKO)
================================================================================

Ekko Flow:
  1. Capture current thread context (RIP, RSP, etc.)
  2. Allocate helper stack (16KB, heap-allocated)
  3. Encrypt .text sections (XOR with derived key)
  4. Optional: zero PE headers
  5. NtContinue to waiting loop on helper stack
  6. RtlCreateTimer schedules wakeup
  7. Timer callback signals event
  8. WaitingLoop decrypts .text, restores headers
  9. NtContinue back to original context

.obf Section:
  - Custom PE section that stays RX while .text is RW
  - Contains waiting loop, timer callback, encryption helpers
  - Never encrypted during sleep cycles

Stack Spoofing:
  - Modifies TEB->NtTib.StackBase/Limit to point to helper stack
  - Restores original TEB values before wake
  - Config-driven stack spoof chain: operator supplies module!function pairs
    in the config whose last ret addresses populate the fake sleep stack
    (see How2Config.txt §4i)
  - EAT boundary scanning locates each function's epilogue (last 0xC3)
  - Optional explicit offset: set "offset": 0x14 in the entry to use
    funcRVA + N directly instead of scanning (trusted operator override)
  - Forwarded exports are skipped; unresolved entries fall back silently

Dedicated function table:
  - Prevents crash when .text is non-executable

================================================================================
                            NETWORK PROTOCOL
================================================================================

Encryption:
  - XChaCha20-Poly1305-IETF (XChaCha20-Poly1305 with 12-byte nonce)
  - 32-byte beacon key derived from config_key XOR beacon_id
  - Per-packet 24-byte random nonce
  - 32-bit sequence number prevents replay attacks

Packet Format:
  [magic:4][version:1][beacon_id:8][opcode:1][seq:4][nonce:24][len:4][ciphertext+mac:16]

Malleable C2:
  - Prefix/suffix wrapper with macro expansion
  - Custom HTTP headers with macro support
  - Payload location: query param, path, or body
  - Path prefix/suffix for path-based encoding

================================================================================
                          BEACON IDENTIFICATION (PSK)
================================================================================

Pandragon uses a pre-shared key (PSK) model for beacon authentication.
Each beacon is registered in server/known_beacons.json with a unique
32-byte crypto_key (64 hex chars).

How it works:
  - beacon_id is derived as SHA256(crypto_key)[:8]
  - The server matches beacon_id from incoming packets against registered entries
  - Unknown beacon IDs are rejected immediately, no fallback or legacy keys
  - crypto_key is used for XChaCha20-Poly1305 AEAD decryption
  - Sequence numbers prevent replay attacks

Route-Based Identification (HTTP):
  - Incoming requests are matched against each beacon's allowed_routes
  - Matches on poll_path (GET) or submit_path (POST), User-Agent, and malleable C2 headers
  - Macros (${TIMESTAMP}, ${RAND_B64:N}, ${JUNK:N}) are expanded as regex
  - Only requests matching a known route are forwarded for decryption

Port-Based Identification (TCP/PIPE):
  - Non-HTTP transports identify beacons by listener port + remote IP
  - The server brute-forces key unwrap across candidates on that port
  - Route validation is skipped (no paths or headers in TCP/PIPE)

Key Management:
  - make keys generates a new beacon entry in known_beacons.json
  - tools/config_builder.py encrypts the config into the beacon binary
  - The crypto_key in the beacon's compiled config must match the server entry

================================================================================
                                CONFIGURATION
================================================================================

Beacon config is compiled to encrypted binary blob via tools/config_builder.py.
JSON schema available in Beacon/config/schema.json.

Key options:
  - c2_channels: Array of {type, host, port, poll_path, submit_path, user_agent}
  - sleep_ms: Base check-in interval
  - jitter_pct: Random variation (0-100)
  - use_indirect_syscalls: Enable HWBP syscall system
  - sleep_obfuscation: none, ekko, ekko_runtime, morpheus, foliage
  - sleep_stack_spoof: Spoof TEB stack during Ekko sleep
  - stack_spoof_chain: User-supplied return-address chain for sleep stack (module!function pairs)
  - num_spoof_frames: Number of fake frames to write (default 6)
  - lazy_checkin: Defer initial check-in N random polls
  - pad / pad_max: PKCS#7 random padding for fixed-size C2 traffic
  - work_hours: Restrict beacon to time window

================================================================================
                              BUILD SYSTEM
================================================================================

Compiler:    Clang++ targeting x86_64-w64-windows-gnu
Standard:    C++20 freestanding, no CRT
Optimization: -Oz (size), -flto=full (LTO)
Linker:      lld with PE target
Sections:    -ffunction-sections -fdata-sections + --gc-sections

Section Layout:
  .text  CODE   (encrypted during Ekko sleep)
  .rdata DATA
  .data  DATA  
  .obf   CODE   (stays RX - Ekko helpers)
  .reloc DATA

================================================================================
                            BOF DEVELOPMENT
================================================================================

Compile:
  cd BofDev/
  x86_64-w64-mingw32-gcc -c mybof.c -o mybof.o

Execute:
  Send via operator GUI: beacon > send bof > BofDev/mybof.o [args]

Imports use MODULE$Function notation:
  NTDLL$NtAllocateVirtualMemory
  KERNEL32$CreateFileW


================================================================================
                            SECURITY NOTES
================================================================================

- Always use HTTPS/WSS in production
- Enable sleep jitter to evade timing analysis
- Use redirectors between beacons and teamserver
- Lazy module loading spreads DLL load sequence
- Lazy unhook only during BOF execution, not polling

- Pandragon is, as of now, NOT ready for production use.

================================================================================
TROUBLESHOOTING
================================================================================

Build failures:
  apt install mingw-w64 lld                         - Missing linker
  pip install pycryptodome jsonschema               - Missing Python deps

Server fails to start (SSL errors):
  Run from server/ directory: cd server && ../server/venv/bin/python run.py
  Or use --data-dir: python server/run.py --data-dir server/

Server: No module named 'protocol.parser':
  make setup      # Recreates venv and rebuilds Cython parser

Beacon not checking in:
   1. Verify crypto keys match (server/known_beacons.json vs config)
   2. Check C2 channel URLs reachable
   3. Ensure sleep time reasonable
   4. Review beacon output (debug build)
   5. Open Github issue.
================================================================================
                              CREDITSSSS
================================================================================

This work was truly a journey. Pandragon is honestly my (Serexp) magnum opus (for now)!
It was hard, really. It is nothing but the fruit of, really, years of experience.
It was extremely fun to work on it, and it does a lot much better than other C2s,
but it can also be made much better. It should serve as a theorical base of what
could be, and an encouragement to do better, because we really can do better.

  A lot of my friends helped me tremendously throughout this, namely Sako which
has been here for many years [and many more to come]!!!, Amine that I saw as a
role model early on, Maria that helped me figure a lot of stuff out (even if she
probably doesn't realize it), Maddie (github @llmaddie) that also helped me a lot,
Lavender, that taught me so much, jonaslyk, an extremely smart person, the whole of
WG and the whole of the FGL, and so many others!
  
  What a journey, what incredible men and women!
  
  This project was initially planned for release on my 18th birthday, but perfectionism
has gotten the better of me, forcing me to release it... 1.5 months late!

after all maybe you can actually meet really good people on discord and twitter! x)

        [MEET THE LAB]
  Comments that FGL members had on Pandragon's final release:
    Maddie: "we goated twin"    Sako: "ouuuu shiiii"
    serexp: "a marvel of engineering"


    AND CREDITS TO MY MOTHER!

  Signed, Serexp @ Futuristic Gadgets Laboratory.

================================================================================
                                LICENSE
================================================================================

  For educational and authorized red team operations only.

  Unauthorized use against systems without explicit permission is strictly
prohibited.
