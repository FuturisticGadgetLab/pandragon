#pragma once
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <utility>
#include "COFFLoader.h"
#include "../include/resolver.h"

#define COFF_ERR_SUCCESS           0
#define COFF_ERR_SETUP           100
#define COFF_ERR_NT_FUNCS        101
#define COFF_ERR_BAD_HEADER      102
#define COFF_ERR_BAD_SYMTAB      103
#define COFF_ERR_BAD_SECTIONS    104
#define COFF_ERR_ALLOC_FAIL      105
#define COFF_ERR_RELOC_OOB       106
#define COFF_ERR_UNRESOLVED_SYM  107
#define COFF_ERR_BAD_RELOC_TYPE  108
#define COFF_ERR_ENTRY_NOT_FOUND 109
#define COFF_ERR_PROTECT_FAIL    110
#define COFF_ERR_CRASH           111

typedef struct _COFF_LOADED {
    char   **sectionMapping;
    SIZE_T  *sectionSizes;      // committed size per section (for bounds checks + secure wipe)
    void   **functionMapping;
    HANDLE   fmHandle;
    uint16_t sectionCount;
    uint16_t functionMappingCount;
    void    *entryPoint;
    void    *blockBase;
} COFF_LOADED;

int  SetupCOFF  (functionTable* funcTable, char *functionname, unsigned char *coff_data,
                 uint32_t filesize,  COFF_LOADED *out);

void CleanupCOFF(COFF_LOADED *ctx);

functionTable* coff_loader_get_nt_func_table();

bool coff_loader_set_nt_func_table(functionTable* nt);