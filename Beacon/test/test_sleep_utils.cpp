#include "../include/sleep_utils.h"
#include "minunit.h"

int tests_run = 0;

static char* test_deriveXorKey_known_answer() {
    uint8_t configKey[32] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
    };
    uint8_t beaconId[8] = { 0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE };

    uint8_t key[SLEEP_XOR_KEY_LENGTH];
    deriveXorKey(key, configKey, beaconId);

    uint8_t seed[32];
    for (int i = 0; i < 8; i++) seed[i] = configKey[i] ^ beaconId[i];
    for (int i = 8; i < 32; i++) seed[i] = configKey[i];

    for (int i = 0; i < SLEEP_XOR_KEY_LENGTH; i++) {
        uint8_t expected = seed[i % 32] ^ (uint8_t)(i / 32);
        mu_assert(key[i] == expected, "deriveXorKey: byte mismatch");
    }

    return 0;
}

int main() {
    printf("test_sleep_utils: ");
    mu_run_test(test_deriveXorKey_known_answer);
    printf("PASS (%d tests)\n", tests_run);
    return 0;
}
