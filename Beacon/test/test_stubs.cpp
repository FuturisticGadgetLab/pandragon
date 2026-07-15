#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

struct functionTable;

extern "C" {

    void* __malloc(size_t s) { return malloc(s); }
    void  __free(void* p)    { free(p); }
    void* __calloc(size_t n, size_t s) { return calloc(n, s); }
    void* __memcpy(void* d, const void* s, size_t n) { return memcpy(d, s, n); }
    void* __memset(void* d, int v, size_t n) { return memset(d, v, n); }
    int   __memcmp(const void* a, const void* b, size_t n) { return memcmp(a, b, n); }
    size_t __strlen(const char* s) { return strlen(s); }

    int __snprintf(char* buf, size_t n, const char* fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        int r = vsnprintf(buf, n, fmt, ap);
        va_end(ap);
        return r;
    }

    // Minimal struct matching the layout of network/net_internal.h
    struct NetworkState {
        struct functionTable* nt;
        uint8_t* beacon_id;
        uint8_t* crypto_key;
        uint32_t seq_num;
        bool identity_set;
        bool key_rotation_pending;
        wchar_t* host;
        wchar_t* poll_path;
        wchar_t* submit_path;
        wchar_t* userAgent;
        unsigned short port;
        bool is_https;
        bool validate_ssl;
    };

    NetworkState g_state;

    bool is_avx_supported(void) {
        return false;
    }
}

bool generateSecureRandom(functionTable*, unsigned char*, size_t) {
    return true;
}

struct _COFF_LOADED;
typedef struct _COFF_LOADED COFF_LOADED;
void CleanupCOFF(COFF_LOADED*) {}

void pkcs7Pad(uint8_t* buf, size_t data_len, size_t padded_len) {
    if (padded_len <= data_len) return;
    uint8_t pad_val = static_cast<uint8_t>(padded_len - data_len);
    for (size_t i = data_len; i < padded_len; i++) buf[i] = pad_val;
}

size_t pkcs7Unpad(const uint8_t* buf, size_t padded_len) {
    if (padded_len == 0) return (size_t)-1;
    uint8_t pad_val = buf[padded_len - 1];
    if (pad_val == 0 || pad_val > padded_len) return (size_t)-1;
    for (size_t i = padded_len - pad_val; i < padded_len - 1; i++) {
        if (buf[i] != pad_val) return (size_t)-1;
    }
    return padded_len - pad_val;
}
