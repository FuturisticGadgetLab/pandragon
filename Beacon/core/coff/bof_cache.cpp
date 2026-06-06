/*
 * bof_cache.cpp - BOF Cache Manager
 *
 * Caches loaded BOF contexts to avoid repeated SetupCOFF calls
 * for frequently executed BOFs.
 */

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#include "../../include/coff/COFFSetup.h"
#include "../../include/utils.h"
#include "../../include/coff/coff_loader.h"

#define MAX_CACHED_BOFS 8

BofCacheManager& BofCacheManager::instance() {
    static BofCacheManager s_instance;
    return s_instance;
}

bof_cache_entry* BofCacheManager::find(uint32_t bof_id) {
    bof_cache_entry* cur = m_entries;
    while (cur) {
        if (cur->bof_id == bof_id) return cur;
        cur = cur->next;
    }
    return nullptr;
}

bool BofCacheManager::insert(uint32_t bof_id, COFF_LOADED* ctx) {
    if (!ctx || m_count >= MAX_CACHED_BOFS) return false;

    bof_cache_entry* entry = (bof_cache_entry*)__malloc(sizeof(bof_cache_entry));
    if (!entry) return false;

    entry->bof_id = bof_id;
    entry->ctx = ctx;
    entry->next = m_entries;
    m_entries = entry;
    m_count++;
    return true;
}

bool BofCacheManager::remove(uint32_t bof_id) {
    bof_cache_entry* cur = m_entries;
    bof_cache_entry* prev = nullptr;

    while (cur) {
        if (cur->bof_id == bof_id) {
            if (prev) {
                prev->next = cur->next;
            } else {
                m_entries = cur->next;
            }
            __free(cur);
            m_count--;
            return true;
        }
        prev = cur;
        cur = cur->next;
    }
    return false;
}

void BofCacheManager::clear() {
    bof_cache_entry* cur = m_entries;
    while (cur) {
        bof_cache_entry* next = cur->next;
        if (cur->ctx) {
            CleanupCOFF(cur->ctx);
            __free(cur->ctx);
        }
        __free(cur);
        cur = next;
    }
    m_entries = nullptr;
    m_count = 0;
}

uint8_t* BofCacheManager::gatherCachedBofIds(size_t* out_len) {
    if (!out_len) return nullptr;

    uint8_t count = static_cast<uint8_t>(m_count);
    if (count == 0) {
        uint8_t* buf = (uint8_t*)__malloc(1);
        if (!buf) {
            *out_len = 0;
            return nullptr;
        }
        buf[0] = 0;
        *out_len = 1;
        return buf;
    }

    size_t len = 1 + count * 4;
    uint8_t* buf = (uint8_t*)__malloc(len);
    if (!buf) {
        *out_len = 0;
        return nullptr;
    }

    buf[0] = count;
    uint32_t idx = 1;
    for (bof_cache_entry* cur = m_entries; cur && idx < len; cur = cur->next) {
        buf[idx++] = (cur->bof_id) & 0xFF;
        buf[idx++] = (cur->bof_id >> 8) & 0xFF;
        buf[idx++] = (cur->bof_id >> 16) & 0xFF;
        buf[idx++] = (cur->bof_id >> 24) & 0xFF;
    }
    *out_len = len;
    return buf;
}