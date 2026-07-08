/*
 * list_files.c: Directory listing BOF (Cobalt Strike compatible)
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -I ../../Beacon/include/coff -c list_files.c -o list_files.x64.o
 *
 * Usage from server CLI:
 *   bof_exec /path/to/list_files.x64.o "C:\Windows"
 *
 * Arguments are sent as raw UTF-8 text from the server.
 */

#include "../Beacon/include/coff/beacon_compatibility.h"

WINBASEAPI HANDLE WINAPI kernel32$FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
WINBASEAPI BOOL   WINAPI kernel32$FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
WINBASEAPI BOOL   WINAPI kernel32$FindClose(HANDLE hFindFile);
WINBASEAPI DWORD  WINAPI kernel32$GetLastError(VOID);
WINBASEAPI BOOL   WINAPI kernel32$FileTimeToSystemTime(const FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI LPVOID WINAPI kernel32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL   WINAPI kernel32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI BOOL   WINAPI kernel32$SystemTimeToTzSpecificLocalTime(LPTIME_ZONE_INFORMATION lpTimeZone, const SYSTEMTIME *lpUniversalTime, LPSYSTEMTIME lpLocalTime);
WINBASEAPI VOID   WINAPI msvcrt$memset(void* dest, int c, size_t count);

void go(char *args, int alen)
{
    WIN32_FIND_DATAW *fd;
    HANDLE            hFind = INVALID_HANDLE_VALUE;
    unsigned int      count = 0;
    int               plen;

    char     *path_buf   = NULL;
    wchar_t  *path_w     = NULL;
    wchar_t  *search     = NULL;
    char     *namebuf    = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] list_files: starting with args length %d", alen);

    if (!args || alen <= 0 || alen >= 1024) {
        BeaconPrintf(CALLBACK_ERROR, "list_files: no path or path too long");
        return;
    }

    /* All ALL memory is heap allocated via VirtualAlloc - NO STACK BUFFERS */
    path_buf = (char *)kernel32$VirtualAlloc(NULL, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    path_w   = (wchar_t *)kernel32$VirtualAlloc(NULL, 2048 * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    search   = (wchar_t *)kernel32$VirtualAlloc(NULL, 2048 * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    namebuf  = (char *)kernel32$VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    fd       = (WIN32_FIND_DATAW *)kernel32$VirtualAlloc(NULL, sizeof(WIN32_FIND_DATAW), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!path_buf || !path_w || !search || !namebuf || !fd) {
        BeaconPrintf(CALLBACK_ERROR, "list_files: memory allocation failed");
        goto cleanup;
    }

    msvcrt$memset(path_buf, 0, 2048);
    msvcrt$memset(path_w, 0, 2048 * sizeof(wchar_t));
    msvcrt$memset(search, 0, 2048 * sizeof(wchar_t));
    msvcrt$memset(namebuf, 0, 4096);
    msvcrt$memset(fd, 0, sizeof(WIN32_FIND_DATAW));

    BeaconPrintf(CALLBACK_OUTPUT, "[*] list_files: memory allocated successfully");

    {
        int i;
        for (i = 0; i < alen; i++)
            path_buf[i] = args[i];
        path_buf[alen] = '\0';
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] list_files: requested path: '%s'", path_buf);

    /* Convert UTF-8 path to wide string */
    if (!toWideChar(path_buf, path_w, 2047)) {
        BeaconPrintf(CALLBACK_ERROR, "list_files: path conversion failed");
        goto cleanup;
    }

    /* Build search pattern: path\* */
    plen = 0;
    while (path_w[plen] && plen < 2045) {
        search[plen] = path_w[plen];
        plen++;
    }

    /* Always leave at minimum 3 characters free for \ * NUL */
    if (plen > 2044) {
        BeaconPrintf(CALLBACK_ERROR, "list_files: path too long for search pattern");
        goto cleanup;
    }

    search[plen]     = L'\\';
    search[plen + 1] = L'*';
    search[plen + 2] = L'\0';

    BeaconPrintf(CALLBACK_OUTPUT, "[*] list_files: executing search pattern");

    hFind = kernel32$FindFirstFileW(search, fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD err = kernel32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "list_files: FindFirstFileW failed (error %lu)", err);
        goto cleanup;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] list_files: enumerating directory entries");
    BeaconPrintf(CALLBACK_OUTPUT, "\n Type        Last Write              Size  Name");
    BeaconPrintf(CALLBACK_OUTPUT, "----        ------------              ----  ----");

    do {
        /* Skip . and .. */
        if (fd->cFileName[0] == L'.') {
            if (fd->cFileName[1] == L'\0' ||
                (fd->cFileName[1] == L'.' && fd->cFileName[2] == L'\0'))
                continue;
        }

        const char *type = (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "<DIR>" : "     ";

        SYSTEMTIME st_utc, st_local;
        kernel32$FileTimeToSystemTime(&fd->ftLastWriteTime, &st_utc);
        kernel32$SystemTimeToTzSpecificLocalTime(NULL, &st_utc, &st_local);

        unsigned long long size;
        if (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            size = 0;
        } else {
            size = ((unsigned long long)fd->nFileSizeHigh << 32) | fd->nFileSizeLow;
        }

        int i, n = 0;
        msvcrt$memset(namebuf, 0, 4096);

        /* Leave at minimum 2 characters free for backslash + null terminator */
        for (i = 0; fd->cFileName[i] && n < 4094; i++, n++)
            namebuf[n] = (char)fd->cFileName[i];

        if (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            namebuf[n] = '\\';
            namebuf[n + 1] = '\0';
        } else {
            namebuf[n] = '\0';
        }

        BeaconPrintf(CALLBACK_OUTPUT_UTF8, " %s  %02d/%02d/%02d %02d:%02d:%02d  %8llu  %s",
                     type,
                     st_local.wMonth, st_local.wDay, st_local.wYear % 100,
                     st_local.wHour, st_local.wMinute, st_local.wSecond,
                     size, namebuf);

        count++;
    } while (kernel32$FindNextFileW(hFind, fd));

    {
        DWORD err = kernel32$GetLastError();
        if (err != ERROR_NO_MORE_FILES) {
            BeaconPrintf(CALLBACK_ERROR, "[!] list_files: enumeration terminated early with error %lu", err);
        }
    }

    kernel32$FindClose(hFind);
    hFind = INVALID_HANDLE_VALUE;

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] list_files: completed successfully, %d entries listed", count);

cleanup:
    BeaconPrintf(CALLBACK_OUTPUT, "[*] list_files: cleaning up resources");

    if (hFind != INVALID_HANDLE_VALUE)
        kernel32$FindClose(hFind);

    if (path_buf) kernel32$VirtualFree(path_buf, 0, MEM_RELEASE);
    if (path_w)   kernel32$VirtualFree(path_w, 0, MEM_RELEASE);
    if (search)   kernel32$VirtualFree(search, 0, MEM_RELEASE);
    if (namebuf)  kernel32$VirtualFree(namebuf, 0, MEM_RELEASE);
    if (fd)       kernel32$VirtualFree(fd, 0, MEM_RELEASE);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] list_files: exit");
}