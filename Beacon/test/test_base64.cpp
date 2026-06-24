#include "minunit.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int tests_run = 0;

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char* b64UrlEncode(const unsigned char* src, size_t srcLen) {
    if (!src) return NULL;
    if (srcLen == 0) {
        char* out = (char*)malloc(1);
        if (out) out[0] = '\0';
        return out;
    }
    size_t outLen = 4 * ((srcLen + 2) / 3) + 1;
    char* out = (char*)malloc(outLen);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i + 2 < srcLen) {
        out[j++] = B64[(src[i] >> 2) & 0x3F];
        out[j++] = B64[((src[i] << 4) | (src[i+1] >> 4)) & 0x3F];
        out[j++] = B64[((src[i+1] << 2) | (src[i+2] >> 6)) & 0x3F];
        out[j++] = B64[src[i+2] & 0x3F];
        i += 3;
    }
    if (srcLen - i == 2) {
        out[j++] = B64[(src[i] >> 2) & 0x3F];
        out[j++] = B64[((src[i] << 4) | (src[i+1] >> 4)) & 0x3F];
        out[j++] = B64[(src[i+1] << 2) & 0x3F];
    } else if (srcLen - i == 1) {
        out[j++] = B64[(src[i] >> 2) & 0x3F];
        out[j++] = B64[(src[i] << 4) & 0x3F];
    }
    out[j] = '\0';
    return out;
}

static unsigned char* b64UrlDecode(const char* src, size_t srcLen, size_t* outLen) {
    if (!src || !outLen) {
        if (outLen) *outLen = 0;
        return NULL;
    }
    if (srcLen == 0) {
        *outLen = 0;
        return (unsigned char*)malloc(1);
    }
    unsigned char tbl[256];
    for (int i = 0; i < 256; i++) tbl[i] = 0xFF;
    for (int i = 0; i < 64; i++) tbl[(unsigned char)B64[i]] = i;

    unsigned char* out = (unsigned char*)malloc((srcLen * 3 + 3) / 4 + 1);
    if (!out) { *outLen = 0; return NULL; }

    size_t i = 0, j = 0;
    while (i + 4 <= srcLen && src[i] != '=') {
        unsigned char a = tbl[(unsigned char)src[i]];
        unsigned char b = tbl[(unsigned char)src[i+1]];
        unsigned char c = (src[i+2] == '=') ? 0 : tbl[(unsigned char)src[i+2]];
        unsigned char d = (src[i+3] == '=') ? 0 : tbl[(unsigned char)src[i+3]];
        if (a == 0xFF || b == 0xFF || (src[i+2] != '=' && c == 0xFF) || (src[i+3] != '=' && d == 0xFF)) {
            free(out); *outLen = 0; return NULL;
        }
        out[j++] = (a << 2) | (b >> 4);
        if (src[i+2] != '=') out[j++] = (b << 4) | (c >> 2);
        if (src[i+3] != '=') out[j++] = (c << 6) | d;
        i += 4;
    }

    size_t rem = srcLen - i;
    if (rem == 2) {
        unsigned char a = tbl[(unsigned char)src[i]];
        unsigned char b = tbl[(unsigned char)src[i+1]];
        out[j++] = (a << 2) | (b >> 4);
    } else if (rem == 3) {
        unsigned char a = tbl[(unsigned char)src[i]];
        unsigned char b = tbl[(unsigned char)src[i+1]];
        unsigned char c = tbl[(unsigned char)src[i+2]];
        out[j++] = (a << 2) | (b >> 4);
        out[j++] = (b << 4) | (c >> 2);
    }

    *outLen = j;
    return out;
}

static char* test_b64_known_answers() {
    struct { const char* plain; size_t ptLen; const char* encoded; } cases[] = {
        {"",       0, ""},
        {"f",      1, "Zg"},
        {"fo",     2, "Zm8"},
        {"foo",    3, "Zm9v"},
        {"foob",   4, "Zm9vYg"},
        {"fooba",  5, "Zm9vYmE"},
        {"foobar", 6, "Zm9vYmFy"},
        {"\x00\x01\x02", 3, "AAEC"},
        {"\xFF\xFE\xFD", 3, "__79"},
    };
    for (int c = 0; c < 9; c++) {
        char* enc = b64UrlEncode((const unsigned char*)cases[c].plain, cases[c].ptLen);
        mu_assert(enc != NULL, "encode non-null");
        mu_assert(strcmp(enc, cases[c].encoded) == 0, "encode match");
        size_t decLen;
        unsigned char* dec = b64UrlDecode(enc, strlen(enc), &decLen);
        mu_assert(dec != NULL, "decode non-null");
        mu_assert(decLen == cases[c].ptLen, "decode length");
        mu_assert(memcmp(dec, cases[c].plain, cases[c].ptLen) == 0, "decode data");
        free(enc);
        free(dec);
    }
    return 0;
}

static char* test_b64_invalid_rejected() {
    size_t decLen;
    unsigned char* dec = b64UrlDecode("!!!invalid!!!", 13, &decLen);
    mu_assert(dec == NULL, "invalid returns NULL");
    return 0;
}

static char* test_b64_encode_null() {
    char* enc = b64UrlEncode(NULL, 5);
    mu_assert(enc == NULL, "encode NULL returns NULL");
    return 0;
}

static char* test_b64_decode_null() {
    size_t decLen;
    unsigned char* dec = b64UrlDecode(NULL, 0, &decLen);
    mu_assert(dec == NULL, "decode NULL returns NULL");
    return 0;
}

int main() {
    printf("test_base64: ");
    mu_run_test(test_b64_known_answers);
    mu_run_test(test_b64_invalid_rejected);
    mu_run_test(test_b64_encode_null);
    mu_run_test(test_b64_decode_null);
    printf("PASS (%d tests)\n", tests_run);
    return 0;
}
