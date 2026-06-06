#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <utility>
#include "COFFLoader.h"
#include "coff_loader.h"

typedef enum BOF_CLASS {
    BOF_CLASS_BLOCKING      = 0,
    BOF_CLASS_LONG_RUNNING  = 1,
    BOF_CLASS_INTERRUPTIBLE = 2
} BOF_CLASS;

#define BOF_CHANNEL_DATA_SIZE  (64 * 1024)

typedef enum CHANNEL_TYPE {
    CHANNEL_TYPE_NONE         = 0,
    CHANNEL_TYPE_NAMED_PIPE = 1,
    CHANNEL_TYPE_SHMEM      = 2,
} CHANNEL_TYPE;

typedef enum CHANNEL_SIGNAL {
    CHANNEL_SIGNAL_NONE          = 0,
    CHANNEL_SIGNAL_ARGS_UPDATE  = 1,
    CHANNEL_SIGNAL_ABORT        = 2,

    /* Async BOF <-> Sleep Mask Integration Signals */
    CHANNEL_SIGNAL_FORCE_SLEEP   = 3,  /* BOF requests beacon to enter sleep mask (with duration in async_state->requested_sleep_sec) */
    CHANNEL_SIGNAL_WAKEUP_SEND  = 4,  /* BOF requests beacon to wake, flush output, re-enter mask */
    CHANNEL_SIGNAL_WAKEUP_EXIT  = 5,  /* BOF done — beacon wakes, restores main loop, clears signal */
} CHANNEL_SIGNAL;

typedef struct bof_prepared_channel {
    CHANNEL_TYPE type;
    uint32_t     buffer_size;
    wchar_t      pipe_name[260];
    void*        shmem_ptr;
} bof_prepared_channel;

typedef struct bof_channel {
    volatile LONG  bof_writing;
    volatile LONG  beacon_writing;
    volatile LONG  data_valid;
    volatile LONG  data_acked;
    volatile LONG  signal;
    volatile LONG  signal_ack;
    uint32_t      record_type;
    uint32_t      record_length;
    uint8_t       data[];
} bof_channel;

typedef struct async_bof_thread_ctx {
    void (*bof_entry)(char*, unsigned long);
    char* argumentdata;
    int   argumentSize;
    COFF_LOADED* ctx;
    uint32_t task_id;
    functionTable* funcTable;
    volatile LONG completed;
    volatile LONG signalledDone;
    int exitCode;
} async_bof_thread_ctx;

typedef struct async_bof_state {
    uint32_t                    task_id;
    BOF_CLASS                   bof_class;
    CHANNEL_TYPE                channel_type;
    HANDLE                      handle;
    uint64_t                    last_checkin;
    uint32_t                    missed_checkins_threshold;
    struct bof_channel*         channel;
    uint32_t                    channel_size;
    uint32_t                    flags;
    void*                       threadCtx;

    union {
        wchar_t      pipe_name[260];
        void*        shmem_ptr;
    } comms_info;

    /* Async BOF <-> Sleep Mask Integration */
    uint32_t                    requested_sleep_sec;  /* For CHANNEL_SIGNAL_FORCE_SLEEP */

    struct async_bof_state *prev;
    struct async_bof_state *next;
} async_bof_state;

class AsyncBofManager {
public:
    static AsyncBofManager& instance();

    async_bof_state* alloc();
    void insert(async_bof_state* state);
    void remove(async_bof_state* state);
    async_bof_state* find(uint32_t task_id);
    void reapCycle();

    async_bof_state* getHead() { return m_head; }
    uint64_t getCurrentTimeMs();

    void dispatchCommands();

    AsyncBofManager(const AsyncBofManager&) = delete;
    AsyncBofManager& operator=(const AsyncBofManager&) = delete;

private:
    AsyncBofManager() = default;

    uint64_t getTimeMs();
    void free(async_bof_state* state);

    async_bof_state* m_head = nullptr;
    async_bof_state* m_tail = nullptr;
    uint32_t         m_nextTaskId = 0;
};

#define MAX_CACHED_BOFS 8

typedef struct bof_cache_entry {
    uint32_t        bof_id;
    COFF_LOADED*     ctx;
    struct bof_cache_entry* next;
} bof_cache_entry;

class BofCacheManager {
public:
    static BofCacheManager& instance();

    bof_cache_entry* find(uint32_t bof_id);
    bool insert(uint32_t bof_id, COFF_LOADED* ctx);
    bool remove(uint32_t bof_id);
    void clear();
    uint32_t getCount() const { return m_count; }
    bof_cache_entry* getEntries() const { return m_entries; }

    uint8_t* gatherCachedBofIds(size_t* out_len);

    BofCacheManager(const BofCacheManager&) = delete;
    BofCacheManager& operator=(const BofCacheManager&) = delete;

private:
    BofCacheManager() = default;

    bof_cache_entry* m_entries = nullptr;
    uint32_t        m_count = 0;
};