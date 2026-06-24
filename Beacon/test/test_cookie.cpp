#include "minunit.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int tests_run = 0;

// -- URL-safe base64 (RFC 4648 no padding) copied from test_base64.cpp --------
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char* b64UrlEncode(const unsigned char* src, size_t srcLen) {
    if (!src) return NULL;
    if (srcLen == 0) { char* out = (char*)malloc(1); if (out) out[0] = '\0'; return out; }
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
    if (!src || !outLen) { if (outLen) *outLen = 0; return NULL; }
    if (srcLen == 0) { *outLen = 0; return (unsigned char*)malloc(1); }
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

// -- Simulate Set-Cookie line parsing (as done in winhttp.cpp) ---------------

// Given a raw response header string and a cookie name, extract the cookie value.
// Returns heap-alloc'd narrow string; caller must free.
// Returns NULL if not found.
static char* extractCookieValue(const char* rawHeaders, const char* cookieName) {
    if (!rawHeaders || !cookieName) return NULL;
    size_t cnLen = strlen(cookieName);
    const char* scan = rawHeaders;

    while (*scan) {
        // Look for "Set-Cookie: " (case-sensitive match on the server-cased variant)
        const char* scPos = strstr(scan, "Set-Cookie: ");
        if (!scPos) {
            scPos = strstr(scan, "set-cookie: ");
        }
        if (!scPos) break;

        const char* nameStart = scPos + 12; // past "Set-Cookie: "

        // Check if cookie name matches
        bool nameMatch = false;
        size_t ci;
        for (ci = 0; ci < cnLen; ci++) {
            if (cookieName[ci] != nameStart[ci]) break;
        }
        if (ci == cnLen && nameStart[ci] == '=') {
            nameMatch = true;
        }

        if (nameMatch) {
            // Extract value: after "name=" until ';' or end of line
            const char* valStart = nameStart + cnLen + 1;
            const char* valEnd = strchr(valStart, ';');
            if (!valEnd) {
                valEnd = strchr(valStart, '\r');
                if (!valEnd) valEnd = strchr(valStart, '\n');
                if (!valEnd) valEnd = valStart + strlen(valStart);
            }
            size_t valLen = valEnd - valStart;
            if (valLen > 0) {
                char* val = (char*)malloc(valLen + 1);
                if (val) {
                    memcpy(val, valStart, valLen);
                    val[valLen] = '\0';
                }
                return val;
            }
            return NULL;
        }

        // Move past this header line
        scan = scPos + 12;
        const char* eol = strchr(scan, '\n');
        if (eol) scan = eol + 1;
        else break;
    }
    return NULL;
}

// -- Tests -------------------------------------------------------------------

static char* test_beacon_id_encode_decode() {
    // Simulate a beacon_id (8 bytes)
    unsigned char beacon_id[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

    // Encode to base64url (same as winhttp.cpp does)
    char* encoded = b64UrlEncode(beacon_id, 8);
    mu_assert(encoded != NULL, "encode non-null");
    // base64url(8 bytes) = ceil(8*8/6) = 11 chars (no padding)
    mu_assert(strlen(encoded) == 11, "encoded length = 11");

    // Decode back
    size_t decLen;
    unsigned char* decoded = b64UrlDecode(encoded, strlen(encoded), &decLen);
    mu_assert(decoded != NULL, "decode non-null");
    mu_assert(decLen == 8, "decode length = 8");
    mu_assert(memcmp(decoded, beacon_id, 8) == 0, "decode matches original");

    free(encoded);
    free(decoded);
    return 0;
}

static char* test_set_cookie_extract_simple() {
    const char* headers =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Set-Cookie: session=SGVsbG9Xb3JsZDEyMzQ1Njc4OTA; path=/\r\n"
        "\r\n";
    char* val = extractCookieValue(headers, "session");
    mu_assert(val != NULL, "found cookie 'session'");
    mu_assert(strcmp(val, "SGVsbG9Xb3JsZDEyMzQ1Njc4OTA") == 0, "cookie value matches");
    free(val);
    return 0;
}

static char* test_set_cookie_extract_not_found() {
    const char* headers =
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: other=value123; path=/\r\n";
    char* val = extractCookieValue(headers, "session");
    mu_assert(val == NULL, "non-matching cookie returns NULL");
    return 0;
}

static char* test_set_cookie_extract_multiple() {
    const char* headers =
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: session=SGVsbG9Xb3JsZDEyMzQ1Njc4OTA; path=/\r\n"
        "Set-Cookie: tracking=abc123; path=/\r\n"
        "Set-Cookie: session=nope;\r\n";
    // Should find FIRST matching cookie
    char* val = extractCookieValue(headers, "session");
    mu_assert(val != NULL, "found cookie 'session'");
    mu_assert(strcmp(val, "SGVsbG9Xb3JsZDEyMzQ1Njc4OTA") == 0, "first match");
    free(val);
    return 0;
}

static char* test_set_cookie_extract_lowercase_header() {
    const char* headers =
        "HTTP/1.1 200 OK\r\n"
        "set-cookie: session=SGVsbG9Xb3JsZDEyMzQ1Njc4OTA; path=/\r\n";
    char* val = extractCookieValue(headers, "session");
    mu_assert(val != NULL, "lowercase header match");
    mu_assert(strcmp(val, "SGVsbG9Xb3JsZDEyMzQ1Njc4OTA") == 0, "value matches");
    free(val);
    return 0;
}

static char* test_set_cookie_extract_no_semicolon() {
    // Cookie value without attributes (no ';')
    const char* headers =
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: session=SGVsbG9Xb3JsZDEyMzQ1Njc4OTA\r\n";
    char* val = extractCookieValue(headers, "session");
    mu_assert(val != NULL, "no-semicolon match");
    mu_assert(strcmp(val, "SGVsbG9Xb3JsZDEyMzQ1Njc4OTA") == 0, "value matches");
    free(val);
    return 0;
}

static char* test_set_cookie_extract_empty() {
    // No Set-Cookie headers at all
    const char* headers =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 0\r\n";
    char* val = extractCookieValue(headers, "session");
    mu_assert(val == NULL, "no Set-Cookie returns NULL");
    return 0;
}

static char* test_cookie_decode_payload() {
    // Simulate the full round-trip:
    // 1. Start with a payload (e.g. an encrypted packet)
    // 2. Base64url-encode it (as server would for Set-Cookie)
    // 3. Extract from Set-Cookie header
    // 4. Base64url-decode it
    
    const unsigned char original[] = "test payload data 12345!@#$%";
    size_t origLen = sizeof(original) - 1; // exclude null
    
    char* encoded = b64UrlEncode(original, origLen);
    mu_assert(encoded != NULL, "payload encode non-null");
    
    // Build mock headers
    char headers[1024];
    snprintf(headers, sizeof(headers),
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: session=%s; path=/\r\n",
        encoded);
    
    char* extracted = extractCookieValue(headers, "session");
    mu_assert(extracted != NULL, "extracted value");
    mu_assert(strcmp(extracted, encoded) == 0, "extracted matches encoded");
    
    size_t decLen;
    unsigned char* decoded = b64UrlDecode(extracted, strlen(extracted), &decLen);
    mu_assert(decoded != NULL, "payload decode non-null");
    mu_assert(decLen == origLen, "decoded length matches original");
    mu_assert(memcmp(decoded, original, origLen) == 0, "decoded matches original");
    
    free(encoded);
    free(extracted);
    free(decoded);
    return 0;
}

int main() {
    printf("test_cookie: ");
    mu_run_test(test_beacon_id_encode_decode);
    mu_run_test(test_set_cookie_extract_simple);
    mu_run_test(test_set_cookie_extract_not_found);
    mu_run_test(test_set_cookie_extract_multiple);
    mu_run_test(test_set_cookie_extract_lowercase_header);
    mu_run_test(test_set_cookie_extract_no_semicolon);
    mu_run_test(test_set_cookie_extract_empty);
    mu_run_test(test_cookie_decode_payload);
    printf("PASS (%d tests)\n", tests_run);
    return 0;
}
