#include "../include/coff/COFFSetup.h"
#include "minunit.h"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int tests_run = 0;

static COFF_LOADED* make_ctx() {
    COFF_LOADED* ctx = (COFF_LOADED*)malloc(sizeof(COFF_LOADED));
    memset(ctx, 0, sizeof(COFF_LOADED));
    return ctx;
}

static void manual_cleanup(BofCacheManager& mgr) {
    bof_cache_entry* e = mgr.getEntries();
    while (e) {
        if (e->ctx) free(e->ctx);
        e = e->next;
    }
    mgr.clear();
}

static char* test_insert_find() {
    BofCacheManager& mgr = BofCacheManager::instance();
    mgr.clear();

    COFF_LOADED* ctx = make_ctx();
    mu_assert(mgr.insert(42, ctx), "insert 42");
    mu_assert(mgr.find(42) != nullptr, "find 42");
    mu_assert(mgr.find(99) == nullptr, "not find 99");
    mu_assert(mgr.getCount() == 1, "count 1");

    mu_assert(mgr.remove(42), "remove 42");
    free(ctx);
    mu_assert(mgr.find(42) == nullptr, "gone after remove");
    mu_assert(mgr.getCount() == 0, "count 0");
    return 0;
}

static char* test_insert_nothing() {
    BofCacheManager& mgr = BofCacheManager::instance();
    mu_assert(mgr.find(0) == nullptr, "not find in empty");
    mu_assert(mgr.getCount() == 0, "count 0 empty");
    return 0;
}

static char* test_remove_nonexistent() {
    BofCacheManager& mgr = BofCacheManager::instance();
    mu_assert(!mgr.remove(0), "remove missing returns false");
    return 0;
}

static char* test_clear() {
    BofCacheManager& mgr = BofCacheManager::instance();
    mgr.clear();

    COFF_LOADED* ctx1 = make_ctx();
    COFF_LOADED* ctx2 = make_ctx();
    mgr.insert(10, ctx1);
    mgr.insert(20, ctx2);
    mu_assert(mgr.getCount() == 2, "count 2 before clear");

    mgr.clear();
    mu_assert(mgr.getCount() == 0, "count 0 after clear");
    return 0;
}

static char* test_max_capacity() {
    BofCacheManager& mgr = BofCacheManager::instance();
    mgr.clear();

    COFF_LOADED* ctxs[9];
    int i;
    for (i = 0; i < 8; i++) {
        ctxs[i] = make_ctx();
        mu_assert(mgr.insert(i + 1, ctxs[i]), "insert up to 8");
    }
    mu_assert(mgr.getCount() == 8, "count 8 at capacity");

    ctxs[8] = make_ctx();
    mu_assert(!mgr.insert(9, ctxs[8]), "9th insert fails");
    mu_assert(mgr.getCount() == 8, "count still 8");

    for (i = 0; i < 8; i++) {
        mu_assert(mgr.remove(i + 1), "remove each");
        free(ctxs[i]);
    }
    free(ctxs[8]);
    mu_assert(mgr.getCount() == 0, "count 0 after drain");
    return 0;
}

static char* test_gather_ids() {
    BofCacheManager& mgr = BofCacheManager::instance();
    mgr.clear();

    COFF_LOADED* ctx1 = make_ctx();
    COFF_LOADED* ctx2 = make_ctx();
    mgr.insert(100, ctx1);
    mgr.insert(200, ctx2);

    size_t outLen;
    uint8_t* ids = mgr.gatherCachedBofIds(&outLen);
    mu_assert(ids != nullptr, "gather non-null");
    // Format: uint8_t count + count * LE uint32 ids
    // For count=2: 1 + 8 = 9
    mu_assert(outLen == 9, "gather length 9");
    mu_assert(ids[0] == 2, "gather count 2");

    free(ids);
    manual_cleanup(mgr);
    return 0;
}

static char* test_gather_ids_empty() {
    BofCacheManager& mgr = BofCacheManager::instance();
    mgr.clear();

    size_t outLen;
    uint8_t* ids = mgr.gatherCachedBofIds(&outLen);
    mu_assert(ids != nullptr, "gather empty non-null");
    mu_assert(outLen == 1, "empty gather length 1");
    mu_assert(ids[0] == 0, "empty gather count 0");
    free(ids);
    return 0;
}

int main() {
    printf("test_bof_cache: ");
    mu_run_test(test_insert_find);
    mu_run_test(test_insert_nothing);
    mu_run_test(test_remove_nonexistent);
    mu_run_test(test_clear);
    mu_run_test(test_max_capacity);
    mu_run_test(test_gather_ids);
    mu_run_test(test_gather_ids_empty);
    printf("PASS (%d tests)\n", tests_run);
    return 0;
}
