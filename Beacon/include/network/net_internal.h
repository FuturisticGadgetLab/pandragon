#pragma once
#include "../resolver.h"
#include "../config_parser.h"
#include <cstdint>

// Shared state defined in net_abstract.cpp, accessed by net_*.cpp files.
// These are implementation details of the network module, not public API.

struct NetworkState {
    functionTable* nt               = nullptr;
    uint8_t*       beacon_id        = nullptr;
    uint8_t*       crypto_key       = nullptr;
    uint32_t       seq_num          = 1;
    bool           identity_set     = false;
    bool           key_rotation_pending = false;

    wchar_t*         host           = nullptr;
    wchar_t*         poll_path      = nullptr;   // GET path for poll operations
    wchar_t*         submit_path    = nullptr;   // POST path for submit operations
    wchar_t*         userAgent      = nullptr;
    INTERNET_PORT    port           = INTERNET_DEFAULT_HTTPS_PORT;
    bool             is_https       = true;
    bool             validate_ssl   = true;
};

extern NetworkState g_state;
