#include <windows.h>

WINBASEAPI HANDLE WINAPI kernel32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI BOOL   WINAPI kernel32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINBASEAPI BOOL   WINAPI kernel32$CloseHandle(HANDLE);
WINBASEAPI DWORD  WINAPI kernel32$GetLastError(VOID);

void BeaconPrintf(int type, char* fmt, ...);
void BeaconOutput(int type, char* data, int len);

void go(char* args, int alen) {
    if (!args || alen < 5) {
        BeaconPrintf(0, "[!] Usage: path_len(4) + path + data\n");
        return;
    }

    int name_len = *(int*)args;
    if (name_len <= 0 || name_len > 512 || 4 + name_len >= alen) {
        BeaconPrintf(0, "[!] Invalid path length: %d\n", name_len);
        return;
    }

    char path[512];
    for (int i = 0; i < name_len && i < 511; i++) path[i] = args[4 + i];
    path[name_len] = '\0';

    int data_len = alen - 4 - name_len;
    char* data = (data_len > 0) ? args + 4 + name_len : NULL;

    HANDLE hFile = kernel32$CreateFileA(
        path, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(0, "[!] CreateFileA failed: %lu\n", kernel32$GetLastError());
        return;
    }

    DWORD bytesWritten = 0;
    BOOL ok = TRUE;
    if (data && data_len > 0) {
        ok = kernel32$WriteFile(hFile, data, data_len, &bytesWritten, NULL);
    }

    kernel32$CloseHandle(hFile);

    if (ok) {
        BeaconPrintf(0, "[+] Wrote %lu bytes to %s\n", bytesWritten, path);
    } else {
        BeaconPrintf(0, "[!] WriteFile failed: %lu\n", kernel32$GetLastError());
    }
}
