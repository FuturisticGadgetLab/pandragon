#pragma once
#include <stddef.h>
#include <stdint.h>
#include <utility>
#include "../../include/generated_config.h"

// =============================================================================
// Transport Abstraction Layer
// =============================================================================
// Decouples net_abstract.cpp (protocol logic: encryption, serialization,
// malleable profiles) from the actual wire transport (WinHTTP, TCP sockets,
// future DNS/DoH, etc.).
//
// Every transport implements the same signature:
//   std::pair<void*, size_t> TransportFn(ntFt, host, dest, userAgent, port, body, bodyLen)
//
// - For HTTP:  dest = full URL path (e.g. L"/api/checkin?q=...")
// - For TCP:   dest = NULL (unused; host:port is the connection target)
// - body/bodyLen: request body (NULL/0 for GET-style polls)
// - Returns { buffer, len }, caller must __free(buffer)
// =============================================================================

#include "../../include/resolver.h"

// Transport function pointer type
typedef std::pair<void*, size_t> (*TransportRequestFn)(
    functionTable* funcTable,
    const wchar_t*   host,        // Server hostname
    const wchar_t*   dest,        // URL path (HTTP) or NULL (TCP)
    const wchar_t*   userAgent,   // User-Agent string (HTTP) or NULL (TCP)
    uint16_t         port,        // Server port
    const void*      bodyData,    // Request body (NULL for no body)
    size_t           bodyLen      // Request body length
);

// Set/get the active transport (call once during init)
void setTransport(TransportRequestFn fn);
TransportRequestFn getTransport(void);

// Set transport type for protocol-specific behavior (encoding decisions)
void setTransportType(const char* type);  // "http", "tcp", or "pipe"
bool isTcpTransport(void);
bool isPipeTransport(void);

// TCP malleable prefix/suffix (static, per-session, set during channel activation)
void setTcpMalleable(const void* prefix, size_t prefixLen, const void* suffix, size_t suffixLen);
const void* getTcpMalleablePrefix(void);
size_t getTcpMalleablePrefixLen(void);
const void* getTcpMalleableSuffix(void);
size_t getTcpMalleableSuffixLen(void);

// Built-in transport implementations
#if defined(PANDRAGON_ENABLE_HTTP) || defined(PANDRAGON_ENABLE_HTTPS)
std::pair<void*, size_t> winhttpRequest(
    functionTable* funcTable,
    const wchar_t*   host,
    const wchar_t*   dest,
    const wchar_t*   userAgent,
    uint16_t         port,
    const void*      bodyData,
    size_t           bodyLen
);
#endif

#ifdef PANDRAGON_ENABLE_TCP
std::pair<void*, size_t> tcpSocketRequest(
    functionTable* funcTable,
    const wchar_t*   host,
    const wchar_t*   dest,
    const wchar_t*   userAgent,
    uint16_t         port,
    const void*      bodyData,
    size_t           bodyLen
);
#endif

#ifdef PANDRAGON_ENABLE_PIPE
std::pair<void*, size_t> pipeSocketRequest(
    functionTable* funcTable,
    const wchar_t*   host,
    const wchar_t*   dest,
    const wchar_t*   userAgent,
    uint16_t         port,
    const void*      bodyData,
    size_t           bodyLen
);
#endif
