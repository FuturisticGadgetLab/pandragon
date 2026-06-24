#include "minunit.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>

int tests_run = 0;

void pkcs7Pad(uint8_t* buf, size_t data_len, size_t padded_len);
size_t pkcs7Unpad(const uint8_t* buf, size_t padded_len);

static char* test_pad_no_padding_needed() {
    uint8_t buf[16] = {0};
    memset(buf, 0xAA, 8);
    pkcs7Pad(buf, 8, 8);
    for (int i = 0; i < 8; i++) mu_assert(buf[i] == 0xAA, "data unchanged");
    return 0;
}

static char* test_pad_full_block() {
    uint8_t buf[32] = {0};
    memset(buf, 0xBB, 16);
    pkcs7Pad(buf, 16, 32);
    for (int i = 0; i < 16; i++) mu_assert(buf[i] == 0xBB, "block1");
    mu_assert(buf[16] == 0x10, "first pad");
    mu_assert(buf[31] == 0x10, "last pad");
    return 0;
}

static char* test_unpad_valid() {
    uint8_t buf[32] = {0};
    memset(buf, 0xCC, 8);
    memset(buf + 8, 0x08, 8);
    size_t n = pkcs7Unpad(buf, 16);
    mu_assert(n == 8, "unpad returns 8");
    return 0;
}

static char* test_unpad_invalid_last_byte() {
    uint8_t buf[] = {0xFF, 0xFF, 0x02, 0x00};
    size_t n = pkcs7Unpad(buf, 4);
    mu_assert(n == (size_t)-1, "rejects zero pad byte");
    return 0;
}

static char* test_unpad_empty() {
    size_t n = pkcs7Unpad(NULL, 0);
    mu_assert(n == (size_t)-1, "empty returns -1");
    return 0;
}

static char* test_unpad_pad_too_large() {
    uint8_t buf[] = {0xAA, 0x10}; // padded_len=2, pad_val=16 > 2
    size_t n = pkcs7Unpad(buf, 2);
    mu_assert(n == (size_t)-1, "pad > buffer returns -1");
    return 0;
}

static char* test_pad_unpad_roundtrip() {
    uint8_t buf[32] = {0};
    const char* data = "hello world!";
    size_t len = strlen(data);
    memcpy(buf, data, len);
    pkcs7Pad(buf, len, 32);
    size_t n = pkcs7Unpad(buf, 32);
    mu_assert(n == len, "roundtrip length");
    mu_assert(memcmp(buf, data, len) == 0, "roundtrip data");
    return 0;
}

int main() {
    printf("test_pkcs7: ");
    mu_run_test(test_pad_no_padding_needed);
    mu_run_test(test_pad_full_block);
    mu_run_test(test_unpad_valid);
    mu_run_test(test_unpad_invalid_last_byte);
    mu_run_test(test_unpad_empty);
    mu_run_test(test_unpad_pad_too_large);
    mu_run_test(test_pad_unpad_roundtrip);
    printf("PASS (%d tests)\n", tests_run);
    return 0;
}
