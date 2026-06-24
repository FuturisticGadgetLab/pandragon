#ifndef UNHOOK_H
#define UNHOOK_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include "resolver.h"

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// DLL Cache (Double-Linked List for KnownDlls-mapped DLLs)
// =============================================================================

#define MAX_DLL_NAME_LEN 64

struct KnownDllNode {
    char                dllName[MAX_DLL_NAME_LEN];  // DLL name (e.g., "kernel32")
    PVOID               baseAddress;                // Mapped base from KnownDlls
    bool                isMapped;                   // Whether successfully mapped
    KnownDllNode*       next;                       // Next node in list
    KnownDllNode*       prev;                       // Previous node in list
};

/**
 * @brief Initialize the DLL cache (must be called once at startup)
 */
void InitDllCache(void);

/**
 * @brief Shutdown and free the DLL cache
 *
 * @param funcTable Function table for Nt* API calls
 */
void ShutdownDllCache(functionTable* funcTable);

/**
 * @brief Resolve a function from a DLL, trying KnownDlls first, then LoadLibrary fallback.
 *
 * On-demand mapping: first time a DLL is requested, maps it from KnownDlls.
 * Subsequent requests use the cached mapped DLL or fall back to LoadLibrary if
 * KnownDlls mapping failed.
 *
 * @param funcTable Function table for Nt* API calls
 * @param dllName     DLL name (e.g., "kernel32", "ntdll", "ws2_32")
 * @param funcName   Function name to resolve (e.g., "VirtualAlloc")
 * @return Function pointer on success, NULL on failure
 */
[[nodiscard]] void* ResolveDllFunction(functionTable* funcTable, const char* dllName, const char* funcName);

/**
 * @brief Map a clean DLL from KnownDlls section (no child process).
 *
 * Opens \\KnownDlls\\<dllName>.dll section object which contains the unmodified
 * DLL from the OS. Maps it into our address space without overwriting our
 * existing (possibly hooked) DLL.
 *
 * @param funcTable Function table for Nt* API calls
 * @param dllName     DLL name (e.g., "ntdll", "kernel32", "ws2_32")
 * @return Clean DLL base pointer on success, NULL on failure
 */
[[nodiscard]] PVOID MapKnownDll(functionTable* funcTable, const char* dllName);

/**
 * @brief Resolve an API from a KnownDlls-mapped DLL by parsing its export directory.
 *
 * @param dllBase     Clean DLL base (from MapKnownDll), or NULL
 * @param functionName ANSI function name
 * @return Function pointer, or NULL
 */
[[nodiscard]] void* ResolveFromKnownDll(PVOID dllBase, const char* functionName);

/**
 * @brief Unmap a KnownDlls-mapped DLL.
 *
 * @param funcTable Function table for Nt* API calls
 * @param dllBase     DLL base to unmap (from MapKnownDll)
 */
void UnmapKnownDll(functionTable* funcTable, PVOID dllBase);

#ifdef __cplusplus
}
#endif

#endif // UNHOOK_H
