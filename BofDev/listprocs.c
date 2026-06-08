/*
 * listprocs.c: Process listing BOF for Pandragon Beacon
 *
 * Uses NtQuerySystemInformation (SystemProcessInformation) to enumerate
 * all running processes. Outputs PID, thread count, and image name.
 *
 * Compile: x86_64-w64-mingw32-gcc -c listprocs.c -o listprocs.o
 */

#include <windows.h>
#include "../Beacon/include/coff/beacon.h"

DECLSPEC_IMPORT LONG NTAPI NTDLL$NtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

DECLSPEC_IMPORT PVOID NTAPI NTDLL$RtlAllocateHeap(
    PVOID HeapHandle,
    ULONG Flags,
    SIZE_T Size
);

DECLSPEC_IMPORT BOOL NTAPI NTDLL$RtlFreeHeap(
    PVOID HeapHandle,
    ULONG Flags,
    PVOID BaseAddress
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlUnicodeToMultiByteSize(
    PULONG BytesInMultiByteString,
    PCWSTR UnicodeString,
    ULONG UnicodeStringSizeInBytes
);

DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$RtlUnicodeToMultiByteN(
    PCHAR MultiByteString,
    ULONG MultiByteStringMaxBytes,
    PULONG NumberOfBytesTransferred,
    PCWSTR UnicodeString,
    ULONG UnicodeStringSizeInBytes
);

/* ============================================================
 * kernel32 imports
 * ============================================================ */
DECLSPEC_IMPORT HANDLE WINAPI kernel32$GetProcessHeap(void);

/* ============================================================
 * NT types and structures
 * ============================================================ */
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemProcessInformation    ((ULONG)5)

/* NT types that may not be defined in winternl.h */
typedef LONG KPRIORITY;

typedef struct _VM_COUNTERS {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG  PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;

typedef struct _IO_COUNTERS {
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
} IO_COUNTERS, *PIO_COUNTERS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    VM_COUNTERS VirtualMemoryCounters;
    SIZE_T PrivatePageCount;
    IO_COUNTERS IoCounters;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

/* ============================================================
 * Simplified process entry
 * ============================================================ */
typedef struct {
    DWORD pid;
    DWORD threads;
    CHAR  imageName[260];
} PROC_ENTRY;

/* ============================================================
 * Enumerate processes via NtQuerySystemInformation
 * Returns heap-allocated array of PROC_ENTRY, caller must free.
 * ============================================================ */
static PROC_ENTRY* enumerateProcesses(DWORD *outCount) {
    if (!outCount) return NULL;

    HANDLE hHeap = kernel32$GetProcessHeap();
    if (!hHeap) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetProcessHeap failed");
        return NULL;
    }

    /* ---- Phase 1: query SYSTEM_PROCESS_INFORMATION ---- */
    PVOID sysBuf  = NULL;
    ULONG bufSize = 0x40000;  /* 256 KB initial guess (covers ~500 processes) */
    ULONG retLen  = 0;
    NTSTATUS st;
    int attempts = 0;

    do {
        if (sysBuf) {
            NTDLL$RtlFreeHeap(hHeap, 0, sysBuf);
            sysBuf = NULL;
        }

        sysBuf = NTDLL$RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, bufSize);
        if (!sysBuf) {
            BeaconPrintf(CALLBACK_ERROR, "[-] RtlAllocateHeap failed (%lu bytes)", bufSize);
            return NULL;
        }

        st = NTDLL$NtQuerySystemInformation(
            SystemProcessInformation,
            sysBuf,
            bufSize,
            &retLen
        );

        /* If buffer too small, kernel tells us exact size needed; use it directly */
        if (st == STATUS_INFO_LENGTH_MISMATCH) {
            NTDLL$RtlFreeHeap(hHeap, 0, sysBuf);
            sysBuf = NULL;
            bufSize = retLen + 0x1000;  /* pad slightly for safety */
        }

        attempts++;
    } while (st == STATUS_INFO_LENGTH_MISMATCH && attempts < 5);

    if (!NT_SUCCESS(st)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] NtQuerySystemInformation failed: 0x%08lX", st);
        if (sysBuf) NTDLL$RtlFreeHeap(hHeap, 0, sysBuf);
        return NULL;
    }

    /* ---- Phase 2: count processes ---- */
    DWORD nProcs = 0;
    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)sysBuf;
    for (;;) {
        nProcs++;
        if (!spi->NextEntryOffset) break;
        spi = (PSYSTEM_PROCESS_INFORMATION)((UCHAR *)spi + spi->NextEntryOffset);
    }

    /* ---- Phase 3: allocate output array ---- */
    SIZE_T listBytes = nProcs * sizeof(PROC_ENTRY);
    PROC_ENTRY *list = (PROC_ENTRY *)NTDLL$RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, listBytes);
    if (!list) {
        BeaconPrintf(CALLBACK_ERROR, "[-] RtlAllocateHeap failed for output array");
        NTDLL$RtlFreeHeap(hHeap, 0, sysBuf);
        return NULL;
    }

    /* ---- Phase 4: fill output array ---- */
    spi = (PSYSTEM_PROCESS_INFORMATION)sysBuf;
    DWORD idx = 0;
    for (;;) {
        list[idx].pid     = (DWORD)(ULONG_PTR)spi->UniqueProcessId;
        list[idx].threads = spi->NumberOfThreads;

        if (spi->ImageName.Buffer && spi->ImageName.Length) {
            ULONG ansiSz = 0;
            NTDLL$RtlUnicodeToMultiByteSize(&ansiSz, spi->ImageName.Buffer, spi->ImageName.Length);
            ULONG copyLen = (ansiSz < sizeof(list[idx].imageName) - 1) ? ansiSz : (sizeof(list[idx].imageName) - 1);

            NTDLL$RtlUnicodeToMultiByteN(
                list[idx].imageName,
                copyLen,
                NULL,
                spi->ImageName.Buffer,
                spi->ImageName.Length
            );
            list[idx].imageName[copyLen] = '\0';
        } else {
            /* System process with no name (PID 0, 4, etc.) */
            list[idx].imageName[0] = '\0';
        }

        idx++;
        if (!spi->NextEntryOffset) break;
        spi = (PSYSTEM_PROCESS_INFORMATION)((UCHAR *)spi + spi->NextEntryOffset);
    }

    NTDLL$RtlFreeHeap(hHeap, 0, sysBuf);
    *outCount = nProcs;
    return list;
}

/* ============================================================
 * BOF entry point
 * ============================================================ */
void go(char *args, int alen) {
    (void)args;
    (void)alen;

    DWORD count = 0;
    PROC_ENTRY *procs = enumerateProcesses(&count);

    if (!procs || count == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to enumerate processes");
        return;
    }

    /*
     * Buffer sizing: worst case ~500 processes * ~80 chars/line = 40KB.
     * We flush in 64-line batches (~5KB) to stay well within beacon limits.
     * For systems with 300+ processes, this means ~5 flush cycles.
     */
    formatp fmt;
    BeaconFormatAlloc(&fmt, 80 * 64);  /* ~64 lines per batch */

    BeaconFormatPrintf(&fmt, "\n%-8s %-8s %s\n", "PID", "THREADS", "IMAGE NAME");
    BeaconFormatPrintf(&fmt, "%-8s %-8s %s\n", "--------", "--------", "------------------------------------------------------------");

    const int BATCH = 64;  /* lines per flush */
    int linesPrinted = 0;

    for (DWORD i = 0; i < count; i++) {
        BeaconFormatPrintf(&fmt, "%-8lu %-8lu %s\n", procs[i].pid, procs[i].threads, procs[i].imageName);
        linesPrinted++;

        /* Flush every BATCH lines or at end */
        if (linesPrinted >= BATCH || i == count - 1) {
            int outLen = 0;
            char *out = BeaconFormatToString(&fmt, &outLen);
            if (out && outLen > 0) {
                BeaconOutput(CALLBACK_OUTPUT, out, outLen);
            }
            BeaconFormatReset(&fmt);
            linesPrinted = 0;
        }
    }

    BeaconFormatPrintf(&fmt, "\n[+] %lu processes listed", count);
    int finalLen = 0;
    char *finalOut = BeaconFormatToString(&fmt, &finalLen);
    if (finalOut && finalLen > 0) {
        BeaconOutput(CALLBACK_OUTPUT, finalOut, finalLen);
    }

    BeaconFormatFree(&fmt);
    NTDLL$RtlFreeHeap(kernel32$GetProcessHeap(), 0, procs);
}
