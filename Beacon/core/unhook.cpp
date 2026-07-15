/*
 * KnownDlls-based Unhooking with DLL Cache
 *
 * Maps clean DLLs from \\KnownDlls\\ section on-demand.
 * Falls back to LoadLibrary if KnownDlls mapping fails.
 */

#include "../include/unhook.h"
#include "../include/resolver.h"
#include "../include/utils.h"
#include "../libs/bastia/bastia.h"
#include <windows.h>
#include <winnt.h>

// =============================================================================
// DLL Cache
// =============================================================================

static KnownDllNode* g_cacheHead = nullptr;

// =============================================================================
// Internal Helpers
// =============================================================================

static KnownDllNode* FindNode(const char* dllName) {
    for (KnownDllNode* node = g_cacheHead; node; node = node->next) {
        if (__strcmp(node->dllName, dllName) == 0) return node;
    }
    return nullptr;
}

static KnownDllNode* GetOrCreateNode(const char* dllName) {
    KnownDllNode* node = FindNode(dllName);
    if (node) return node;

    node = (KnownDllNode*)__malloc(sizeof(KnownDllNode));
    if (!node) return nullptr;

    __memset(node, 0, sizeof(KnownDllNode));
    __strncpy(node->dllName, dllName, MAX_DLL_NAME_LEN - 1);
    node->dllName[MAX_DLL_NAME_LEN - 1] = '\0';

    node->next = g_cacheHead;
    if (g_cacheHead) g_cacheHead->prev = node;
    g_cacheHead = node;
    return node;
}


/* Expects a dllName that does NOT have .dll in it.
Example: kernel32, not kernel32.dll*/
static PVOID MapDllFromKnownDlls(functionTable* nt, const char* dllName) {
    const wchar_t* prefix = lcg_encryptw(L"\\KnownDlls\\");
    const size_t prefixLen = (sizeof(L"\\KnownDlls\\") / sizeof(wchar_t)) - 1;

    size_t dllLen = __strlen(dllName);
    size_t totalLen = prefixLen + dllLen + 4 + 1;

    wchar_t* wideName = (wchar_t*)__malloc((dllLen + 1) * sizeof(wchar_t));
    if (!wideName) return nullptr;

    wchar_t* path = (wchar_t*)__malloc(totalLen * sizeof(wchar_t));
    if (!path) { __free(wideName); return nullptr; }

    __mbstowcs(wideName, dllName, dllLen + 1);

    __memcpy(path, prefix, prefixLen * sizeof(wchar_t));
    size_t pos = prefixLen;
    for (size_t i = 0; wideName[i]; i++) {
        path[pos++] = wideName[i];
    }
    path[pos++] = L'.';
    path[pos++] = L'd';
    path[pos++] = L'l';
    path[pos++] = L'l';
    path[pos++] = L'\0';

    __free(wideName);

    UNICODE_STRING us = {};
    nt->RtlInitUnicodeString(&us, path);

    OBJECT_ATTRIBUTES objAttr = {};
    InitializeObjectAttributes(&objAttr, &us, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE hSection = nullptr;
    NTSTATUS status = nt->NtOpenSection(&hSection, SECTION_ALL_ACCESS, &objAttr); // we should try GENERIC_EXECUTE?
    __free(path);
    if (!NT_SUCCESS(status)) return nullptr;

    PVOID base = nullptr;
    SIZE_T viewSize = 0;
    /* It can be set as RO. From docs:
            For section objects created with the SEC_IMAGE attribute,
            the Win32Protect parameter has no effect, and can be set
            to any valid value such as PAGE_READONLY.*/
    status = nt->NtMapViewOfSection(hSection, NtCurrentProcess(), &base,
                                     0, 0, nullptr, &viewSize, ViewShare, 0, PAGE_READONLY);
    nt->NtClose(hSection);

    if (!NT_SUCCESS(status) || !base) return nullptr;

    auto dos = (PIMAGE_DOS_HEADER)base;
#ifdef _WIN64
    auto ntHdrs = (PIMAGE_NT_HEADERS64)((PBYTE)base + dos->e_lfanew);
#else
    auto ntHdrs = (PIMAGE_NT_HEADERS)((PBYTE)base + dos->e_lfanew);
#endif

    if (dos->e_magic != IMAGE_DOS_SIGNATURE || ntHdrs->Signature != IMAGE_NT_SIGNATURE) {
        nt->NtUnmapViewOfSection(NtCurrentProcess(), base);
        return nullptr;
    }

    c_debugPrint(nt, "[+] KnownDlls %s @ 0x%p", dllName, base);
    return base;
}

// =============================================================================
// Public API
// =============================================================================

void InitDllCache(void) {
    g_cacheHead = nullptr;
}

void ShutdownDllCache(functionTable* nt) {
    while (g_cacheHead) {
        KnownDllNode* next = g_cacheHead->next;
        if (g_cacheHead->isMapped && g_cacheHead->baseAddress) {
            nt->NtUnmapViewOfSection(NtCurrentProcess(), g_cacheHead->baseAddress);
        }
        __free(g_cacheHead);
        g_cacheHead = next;
    }
}

void* ResolveDllFunction(functionTable* nt, const char* dllName, const char* funcName) {
    if (!dllName || !funcName || !nt) return nullptr;

    KnownDllNode* node = GetOrCreateNode(dllName);
    if (!node) return nullptr;

    if (!node->isMapped) {
        node->baseAddress = MapDllFromKnownDlls(nt, dllName);
        node->isMapped = (node->baseAddress != nullptr);
    }

    if (node->isMapped) {
        void* func = (void*)__GetProcAddress((HMODULE)node->baseAddress, funcName);
        if (func) return func;
    }

    HMODULE hMod = __LoadLibraryA(dllName);
    return hMod ? (void*)__GetProcAddress(hMod, funcName) : nullptr;
}

PVOID MapKnownDll(functionTable* nt, const char* dllName) {
    return MapDllFromKnownDlls(nt, dllName);
}

void* ResolveFromKnownDll(PVOID base, const char* funcName) {
    return (void*)__GetProcAddress((HMODULE)base, funcName);
}

void UnmapKnownDll(functionTable* nt, PVOID base) {
    if (base) nt->NtUnmapViewOfSection(NtCurrentProcess(), base);
}
