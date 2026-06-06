/*
 * async_bof_test.c - Async BOF with Sleep Mask Integration Test
 * 
 * This BOF demonstrates the new async BOF <-> Sleep Mask integration:
 * - MASK_FORCE_SLEEP(ch, sec)  : Request beacon to enter sleep mask for 'sec' seconds
 * - MASK_WAKEUP_SEND(ch)       : Request beacon to wake, flush output, re-enter mask
 * - MASK_WAKEUP_EXIT(ch)       : Request beacon to wake and restore main loop (MUST CALL)
 * - MASK_STOP_TASK(ch)         : Check if operator sent stop_task
 * - MASK_IS_SLEEPING(ch)       : Check if beacon is in sleep mask state
 * - MASK_PRINTF_IF_AWAKE(ch, ...) : Safe printf that only emits when beacon is awake
 * 
 * Build: clang -target x86_64-w64-windows-gnu -I ../Beacon/include/coff -c async_bof_test.c -o async_bof_test.o
 * 
 * IMPORTANT: The beacon prepends the channel pointer (8 bytes) to the BOF arguments.
 * The BOF MUST extract it first using BeaconDataExtract before parsing other args.
 */

#include "../Beacon/include/coff/beacon_compatibility.h"

void prepare(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    /* Request shared memory channel */
    bof_prepared_channel* ch = (bof_prepared_channel*)BeaconGetOutputData(NULL);
    if (ch) {
        ch->type = CHANNEL_TYPE_SHMEM;
        ch->buffer_size = BOF_CHANNEL_DATA_SIZE;
        ch->shmem_ptr = NULL;  // Beacon will allocate
    }
}

void go(char* args, int len) {
    /* FIRST: Extract channel pointer from prepended argument (first 8 bytes) */
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    int dummy;
    volatile struct bof_channel* ch = (volatile struct bof_channel*)BeaconDataExtract(&parser, &dummy);
    if (!ch) {
        BeaconPrintf(CALLBACK_OUTPUT, "[async_bof_test] ERROR: No channel pointer in args!");
        return;
    }
    
    /* Now parse actual BOF arguments (after the channel pointer) */
    int sleep_seconds = BeaconDataInt(&parser);
    if (sleep_seconds <= 0) sleep_seconds = 30;
    
    MASK_PRINTF_IF_AWAKE(ch, "[async_bof_test] Starting async test, requesting FORCE_SLEEP for %d sec", sleep_seconds);
    
    /* Request beacon to enter sleep mask */
    MASK_FORCE_SLEEP(ch, sleep_seconds);
    
    MASK_PRINTF_IF_AWAKE(ch, "[async_bof_test] Beacon is now sleep-masked. Doing work...");
    
    /* Simulate work */
    for (int i = 0; i < 3; i++) {
        if (MASK_STOP_TASK(ch)) {
            MASK_PRINTF_IF_AWAKE(ch, "[async_bof_test] Stop task received, cleaning up");
            MASK_WAKEUP_EXIT(ch);
            return;
        }
        
        MASK_PRINTF_IF_AWAKE(ch, "[async_bof_test] Working... %d/3", i+1);
        
        /* Request beacon to wake, flush output, and re-enter mask */
        MASK_WAKEUP_SEND(ch);
        
        /* Small delay */
        for (volatile int j = 0; j < 1000000; j++);
    }
    
    MASK_PRINTF_IF_AWAKE(ch, "[async_bof_test] Work complete, requesting WAKEUP_EXIT");
    
    /* MUST call this - tells beacon to wake up and restore main loop */
    MASK_WAKEUP_EXIT(ch);
}