#pragma once

#include <windows.h>


/* Internal function entry structure */
struct InternalFunctionEntry {
    const char* name;
    void*       func;
};

/* Internal functions table - extern declaration */
extern struct InternalFunctionEntry InternalFunctions[32];

/* Sleep state constants (C-compatible) */
#define MASK_STATE_AWAKE    0
#define MASK_STATE_SLEEPING 1

typedef enum CHANNEL_TYPE {
    CHANNEL_TYPE_NONE         = 0,
    CHANNEL_TYPE_NAMED_PIPE = 1,
    CHANNEL_TYPE_SHMEM      = 2,
} CHANNEL_TYPE;

typedef struct bof_prepared_channel {
    CHANNEL_TYPE type;
    uint32_t     buffer_size;
    wchar_t      pipe_name[260];
    void*        shmem_ptr;
} bof_prepared_channel;

/* BOF Channel Signal Types */
typedef enum CHANNEL_SIGNAL {
    CHANNEL_SIGNAL_NONE          = 0,
    CHANNEL_SIGNAL_ARGS_UPDATE  = 1,
    CHANNEL_SIGNAL_ABORT        = 2,

    /* Async BOF <-> Sleep Mask Integration Signals */
    CHANNEL_SIGNAL_FORCE_SLEEP   = 3,  /* BOF requests beacon to enter sleep mask (with duration in async_state->requested_sleep_sec) */
    CHANNEL_SIGNAL_WAKEUP_SEND  = 4,  /* BOF requests beacon to wake, flush output, re-enter mask */
    CHANNEL_SIGNAL_WAKEUP_EXIT  = 5,  /* BOF done - beacon wakes, restores main loop, clears signal */
} CHANNEL_SIGNAL;

/* BOF Channel structure (full definition for C BOF access) */
typedef struct bof_channel {
    volatile long  bof_writing; // here we use long instead of LONG to avoid including windows.h BUT this could be an issue eventually
    volatile long  beacon_writing;
    volatile long  data_valid;
    volatile long  data_acked;
    volatile long  signal;
    volatile long  signal_ack;
    uint32_t      record_type;
    uint32_t      record_length;
    uint8_t       data[];
} bof_channel;

/* Forward declare BeaconConfig */
struct BeaconConfig;

typedef struct {
    char * original;
    char * buffer;
    int    length;
    int    size;
} datap;

typedef struct {
    char * original;
    char * buffer;
    int    length;
    int    size;
} formatp;

#ifdef __cplusplus
extern "C" {
#endif

void    BeaconDataParse(datap * parser, char * buffer, int size);
int     BeaconDataInt(datap * parser);
short   BeaconDataShort(datap * parser);
int     BeaconDataLength(datap * parser);
char *  BeaconDataExtract(datap * parser, int * size);

void    BeaconFormatAlloc(formatp * format, int maxsz);
void    BeaconFormatReset(formatp * format);
void    BeaconFormatFree(formatp * format);
void    BeaconFormatAppend(formatp * format, char * text, int len);
void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
char *  BeaconFormatToString(formatp * format, int * size);
void    BeaconFormatInt(formatp * format, int value);

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

void   BeaconPrintf(int type, char * fmt, ...);
void   BeaconOutput(int type, char * data, int len);

#ifndef __cplusplus // _bool is native to c++ on g++
    #define bool\t_Bool
        #if defined __STDC_VERSION__ && __STDC_VERSION__ > 201710L
            #define true\t((_Bool)+1u)
            #define false\t((_Bool)+0u)
    #else
        #define true\t1
        #define false\t0
    #endif
#endif

/* Token Functions */
bool   BeaconUseToken(HANDLE token);
void   BeaconRevertToken();
bool   BeaconIsAdmin();

/* Spawn+Inject Functions */
void   BeaconGetSpawnTo(bool x86, char * buffer, int length);
bool   BeaconSpawnTemporaryProcess(bool x86, bool ignoreToken, STARTUPINFOW * sInfo, PROCESS_INFORMATION * pInfo);
void   BeaconInjectProcess(HANDLE hProc, int pid, char * payload, int p_len, int p_offset, char * arg, int a_len);
void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char * payload, int p_len, int p_offset, char * arg, int a_len);
void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
bool   toWideChar(char * src, wchar_t * dst, int max);

char* BeaconGetOutputData(int *outsize);

/* Config initialization */
void setBeaconConfig(const struct BeaconConfig* config);

/* Persistent BOF State API */
void* BeaconGetPersistentStateData(uint64_t UUID, size_t* out_len);
bool  BeaconSetPersistentStateData(uint64_t UUID, void* src, size_t len);
bool  BeaconIncreasePersistentStateData(uint64_t UUID, size_t new_len);

/* Async BOF <-> Sleep Mask Integration API */
/* These macros write to the shared bof_channel pointer passed by the BOF.
 * The BOF developer is responsible for:
 *   1. Caching the channel pointer passed via BOF arguments (see async_bof_test.c)
 *   2. Checking sleep state via channel->signal or their own tracking
 *   3. Implementing their own yield/wait if needed
 * CRITICAL: Every async BOF MUST call MASK_WAKEUP_EXIT before returning,
 *           otherwise the beacon will remain asleep indefinitely. */

/* C-compatible channel signal writes (ch = channel pointer passed to BOF) */
#define MASK_FORCE_SLEEP(ch, sec) \
    do { \
        if (ch) { \
            while (_InterlockedCompareExchange(&(ch)->beacon_writing, 1, 0) != 0) { } \
            (ch)->signal = CHANNEL_SIGNAL_FORCE_SLEEP; \
            (ch)->record_type = (sec); \
            _InterlockedExchange(&(ch)->beacon_writing, 0); \
        } \
    } while(0)

#define MASK_WAKEUP_SEND(ch) \
    do { \
        if (ch) { \
            while (_InterlockedCompareExchange(&(ch)->beacon_writing, 1, 0) != 0) { } \
            (ch)->signal = CHANNEL_SIGNAL_WAKEUP_SEND; \
            _InterlockedExchange(&(ch)->beacon_writing, 0); \
        } \
    } while(0)

#define MASK_WAKEUP_EXIT(ch) \
    do { \
        if (ch) { \
            while (_InterlockedCompareExchange(&(ch)->beacon_writing, 1, 0) != 0) { } \
            (ch)->signal = CHANNEL_SIGNAL_WAKEUP_EXIT; \
            _InterlockedExchange(&(ch)->beacon_writing, 0); \
        } \
    } while(0)

#define MASK_STOP_TASK(ch) \
    (ch && (ch)->signal == CHANNEL_SIGNAL_ABORT)

/* Sleep state check - check channel signal directly */
#define MASK_IS_SLEEPING(ch) \
    (ch && ((ch)->signal == CHANNEL_SIGNAL_FORCE_SLEEP || (ch)->signal == CHANNEL_SIGNAL_WAKEUP_SEND))

/* Convenience: only emit output if beacon is awake */
#define MASK_PRINTF_IF_AWAKE(ch, fmt, ...) \
    do { \
        if (!MASK_IS_SLEEPING(ch)) { \
            BeaconPrintf(CALLBACK_OUTPUT, fmt, ##__VA_ARGS__); \
        } \
    } while(0)

#define MASK_OUTPUT_IF_AWAKE(ch, type, data, len) \
    do { \
        if (!MASK_IS_SLEEPING(ch)) { \
            BeaconOutput(type, data, len); \
        } \
    } while(0)

#ifdef __cplusplus
}
#endif
