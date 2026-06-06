#include <windows.h>
#include "../Beacon/include/coff/beacon.h"

DECLSPEC_IMPORT BOOL WINAPI kernel32$CreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

DECLSPEC_IMPORT BOOL WINAPI kernel32$CloseHandle(HANDLE hObject);

void go(char* args, int len) {
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    BOOL result = kernel32$CreateProcessA(
        "C:\\Windows\\explorer.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (result) {
        BeaconOutput(CALLBACK_OUTPUT, "[bof] explorer.exe spawned.", 27);
        kernel32$CloseHandle(pi.hProcess);
        kernel32$CloseHandle(pi.hThread);
    } else {
        BeaconOutput(CALLBACK_OUTPUT, "[bof] CreateProcessA failed.", 28);
    }

    return;
}
