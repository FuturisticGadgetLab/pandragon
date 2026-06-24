#include "../include/network/net_abstract.h"
#include "minunit.h"

#include <string.h>
#include <stdio.h>

int tests_run = 0;

using namespace pandragon;

// ---------------------------------------------------------------
// Helper: build a raw wire-format packet header at `buf`.
// `buf` must be at least HEADER_LEN bytes.
// The payload region right after the header is NOT written here.
// ---------------------------------------------------------------
static void build_header(uint8_t* buf, uint8_t opcode, uint32_t payload_len) {
    memset(buf, 0, HEADER_LEN);

    uint32_t magic = PANDRAGON_MAGIC;
    memcpy(buf, &magic, 4);           // offset 0: magic
    buf[4] = 0;                       // offset 4: version_t::epoch
    memset(buf + 5, 0x42, 8);         // offset 5: beacon_id (8 bytes)
    buf[13] = opcode;                 // offset 13: opcode
    uint32_t seq = 0;
    memcpy(buf + 14, &seq, 4);       // offset 14: seq_num
    memset(buf + 18, 0xAA, 24);       // offset 18: nonce (24 bytes)
    memcpy(buf + 42, &payload_len, 4);// offset 42: payload_len
}

// ---------------------------------------------------------------
// parsePacket tests
// ---------------------------------------------------------------

static char* test_parse_null_buffer() {
    parsed_packet out;
    parse_err err = parsePacket(nullptr, HEADER_LEN, true, out);
    mu_assert(err == parse_err::NULL_BUFFER, "NULL_BUFFER expected for null buf");
    return 0;
}

static char* test_parse_too_small() {
    uint8_t buf[10] = {};
    parsed_packet out;
    parse_err err = parsePacket(buf, 10, true, out);
    mu_assert(err == parse_err::BUFFER_TOO_SMALL,
              "BUFFER_TOO_SMALL expected for buf < HEADER_LEN");
    return 0;
}

static char* test_parse_bad_magic() {
    uint8_t buf[HEADER_LEN + 16];
    build_header(buf, 0x00, 0);
    // Corrupt magic
    uint32_t bad_magic = 0xDEADBEEF;
    memcpy(buf, &bad_magic, 4);

    parsed_packet out;
    parse_err err = parsePacket(buf, sizeof(buf), true, out);
    mu_assert(err == parse_err::BAD_MAGIC, "BAD_MAGIC expected");
    return 0;
}

static char* test_parse_valid_s2b_notasks() {
    uint8_t buf[HEADER_LEN + 16];
    build_header(buf, 0x00, 0); // NO_TASKS

    parsed_packet out;
    parse_err err = parsePacket(buf, sizeof(buf), true, out);
    mu_assert(err == parse_err::OK, "OK expected for NO_TASKS");
    mu_assert(out.magic == PANDRAGON_MAGIC, "magic match");
    mu_assert(out.opcode == 0x00, "opcode match");
    return 0;
}

static char* test_parse_valid_s2b_die() {
    uint8_t buf[HEADER_LEN + 16];
    build_header(buf, 0xFF, 0); // DIE

    parsed_packet out;
    parse_err err = parsePacket(buf, sizeof(buf), true, out);
    mu_assert(err == parse_err::OK, "OK expected for DIE");
    mu_assert(out.opcode == 0xFF, "opcode match");
    return 0;
}

static char* test_parse_invalid_s2b_opcode() {
    uint8_t buf[HEADER_LEN + 16];
    build_header(buf, 0xFE, 0); // Not a valid S2B opcode

    parsed_packet out;
    parse_err err = parsePacket(buf, sizeof(buf), true, out);
    mu_assert(err == parse_err::BAD_OPCODE, "BAD_OPCODE expected for invalid opcode");
    return 0;
}

static char* test_parse_valid_b2s_checkin() {
    uint8_t buf[HEADER_LEN + 16];
    build_header(buf, 0x01, 0); // BEACON_CHECK_IN

    parsed_packet out;
    parse_err err = parsePacket(buf, sizeof(buf), false, out);
    mu_assert(err == parse_err::OK, "OK expected for BEACON_CHECK_IN (b2s)");
    return 0;
}

static char* test_parse_invalid_b2s_opcode() {
    // The DIE opcode (0xFF) is only valid for S2B, not B2S
    uint8_t buf[HEADER_LEN + 16];
    build_header(buf, 0xFF, 0); // DIE is not a valid B2S opcode

    parsed_packet out;
    parse_err err = parsePacket(buf, sizeof(buf), false, out);
    mu_assert(err == parse_err::BAD_OPCODE,
              "BAD_OPCODE expected for DIE in b2s direction");
    return 0;
}

static char* test_parse_payload_overflow() {
    // payload_len = 9999 but only 16 bytes available after header
    uint8_t buf[HEADER_LEN + 16];
    build_header(buf, 0x00, 9999);

    parsed_packet out;
    parse_err err = parsePacket(buf, sizeof(buf), true, out);
    mu_assert(err == parse_err::PAYLOAD_OVERFLOW,
              "PAYLOAD_OVERFLOW expected");
    return 0;
}

// ---------------------------------------------------------------
// Serialize / deserialize round-trip test (pad=false)
// ---------------------------------------------------------------

static char* test_serialize_roundtrip() {
    const uint8_t test_key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
    };
    const uint8_t test_nonce[24] = {
        0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
        0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,
        0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
    };
    const uint8_t test_beacon_id[8] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 };

    const uint8_t plaintext[] = "hello beacon!";
    const size_t pt_len = sizeof(plaintext); // includes null terminator

    auto ser = serializePacket(
        test_beacon_id,
        b2s_opcode::BEACON_POLL,
        1,
        test_nonce,
        plaintext,
        pt_len,
        test_key,
        false,  // pad=false
        0       // pad_max unused
    );

    mu_assert(ser.first == parse_err::OK, "serializePacket returned OK");
    mu_assert(ser.second.first != nullptr, "serializePacket returned non-null buffer");
    mu_assert(ser.second.second > HEADER_LEN, "serialized length > header");

    auto des = deserializePacket(
        ser.second.first,
        ser.second.second,
        test_key,
        false  // direction_s2b=false (this is a b2s packet)
    );

    mu_assert(des.first == parse_err::OK, "deserializePacket returned OK");
    mu_assert(des.second.decrypted_payload != nullptr, "decrypted payload non-null");
    mu_assert(des.second.decrypted_len == pt_len,
              "decrypted length matches original");
    mu_assert(memcmp(des.second.decrypted_payload, plaintext, pt_len) == 0,
              "decrypted payload matches plaintext");

    // Also verify header fields survived
    mu_assert(des.second.magic == PANDRAGON_MAGIC, "roundtrip magic");
    mu_assert(des.second.opcode == static_cast<uint8_t>(b2s_opcode::BEACON_POLL),
              "roundtrip opcode");
    mu_assert(des.second.seq_num == 1, "roundtrip seq_num");

    // Cleanup
    __free(ser.second.first);
    __free(des.second.decrypted_payload);

    return 0;
}

// ---------------------------------------------------------------
// Main test runner
// ---------------------------------------------------------------

int main() {
    printf("test_net_crypto: ");

    mu_run_test(test_parse_null_buffer);
    mu_run_test(test_parse_too_small);
    mu_run_test(test_parse_bad_magic);
    mu_run_test(test_parse_valid_s2b_notasks);
    mu_run_test(test_parse_valid_s2b_die);
    mu_run_test(test_parse_invalid_s2b_opcode);
    mu_run_test(test_parse_valid_b2s_checkin);
    mu_run_test(test_parse_invalid_b2s_opcode);
    mu_run_test(test_parse_payload_overflow);
    mu_run_test(test_serialize_roundtrip);

    printf("PASS (%d tests)\n", tests_run);
    return 0;
}
