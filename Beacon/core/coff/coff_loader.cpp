/*
 * coff_loader.cpp - Pure COFF Loader
 *
 * Memory model:
 *   1. Reserve one contiguous VA region (MEM_RESERVE | MEM_TOP_DOWN)
 *   2. Commit each section as PAGE_READWRITE, copy data, zero padding
 *   3. Promote to final protection per section:
 *      - Code:  PAGE_EXECUTE_READ  (RX)
 *      - Data:  PAGE_READWRITE     (RW)
 *      - Rdata: PAGE_READONLY      (RO)
 *   4. Process relocations (all within contiguous block -> REL32 safe)
 *   5. Cleanup: revert to RW -> crypto_wipe -> decommit sections -> release
 *
 *   functionMapping (GOT):
 *       NtCreateSection PAGE_READWRITE, stays RW
 *       freed via NtUnmapViewOfSection + NtClose
 */

#include <cstddef>
#include <limits.h>
#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <utility>

#include "../../include/coff/beacon_compatibility.h"
#include "../../include/resolver.h"
#include "../../include/utils.h"
#include "../../include/coff/coff_loader.h"
#include "../../include/coff/beacon_api_resolver.h"
#include "../../include/network/net_abstract.h"
#include "../../libs/bastia/bastia.h"

//#if defined(__x86_64__) || defined(_WIN64)
#  define PREPENDSYMBOLVALUE "__imp_"
//#else
//#  define PREPENDSYMBOLVALUE "__imp__"
//#endif

#define COFFSETUP_BAIL_IF(expr, code, fmt, ...) \
    if ((expr)) { \
        return code; \
    }

#ifndef NT_SUCCESS
#  define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

extern functionTable* g_functionTable;

functionTable* coff_loader_get_nt_func_table() {
    return g_functionTable;
}

bool coff_loader_set_nt_func_table(functionTable* nt) {
    if (nt && !g_functionTable) {
        g_functionTable = nt;
        return true;
    } else if (g_functionTable) {
        return true;
    }
    return false;
}

static bool sym_is_defined(struct coff_sym* s) {
    return s->SectionNumber > 0;
}

static bool sym_is_external(struct coff_sym* s) {
    return s->StorageClass == IMAGE_SYM_CLASS_EXTERNAL
        || s->StorageClass == IMAGE_SYM_CLASS_EXTERNAL_DEF;
}

static void* alloc_data_mem(SIZE_T size, HANDLE* hSect) {
    LARGE_INTEGER sz;
    sz.QuadPart = (LONGLONG)size;

    NTSTATUS st = g_functionTable->NtCreateSection(hSect, SECTION_ALL_ACCESS, NULL,
                                   &sz, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(st)) { *hSect = NULL; return NULL; }

    PVOID  base     = NULL;
    SIZE_T viewSize = 0;
    st = g_functionTable->NtMapViewOfSection(*hSect, (HANDLE)-1, &base,
                             0, size, NULL, &viewSize,
                             ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(st)) {
        g_functionTable->NtClose(*hSect);
        *hSect = NULL;
        return NULL;
    }
    return base;
}

static void free_section_mem(PVOID base, HANDLE hSect) {
    if (!base) return;
    if (hSect) {
        g_functionTable->NtUnmapViewOfSection((HANDLE)-1, base);
        g_functionTable->NtClose(hSect);
    } else {
        SIZE_T sz = 0;
        g_functionTable->NtFreeVirtualMemory((HANDLE)-1, &base, &sz, MEM_RELEASE);
    }
}

int SetupCOFF(
    functionTable* funcTable,
    char*            functionname,
    unsigned char*   coff_data,
    uint32_t         filesize,
    COFF_LOADED*     out)
{
    __memset(out, 0, sizeof(COFF_LOADED));

    if(!g_functionTable) {
        g_functionTable = funcTable;
    }

    COFFSETUP_BAIL_IF(!functionname,       COFF_ERR_SETUP, "functionname is NULL\n");
    COFFSETUP_BAIL_IF(!coff_data,          COFF_ERR_SETUP, "coff_data is NULL\n");
    COFFSETUP_BAIL_IF(filesize == 0,       COFF_ERR_BAD_HEADER, "filesize is 0\n");
    COFFSETUP_BAIL_IF(filesize < sizeof(coff_file_header_t),
                      COFF_ERR_BAD_HEADER, "File too small for COFF header\n");

    coff_file_header_t* hdr = (coff_file_header_t*)coff_data;

    debugPrint("\t\tDEBUG raw header bytes: %02x %02x %02x %02x | %02x %02x | %02x %02x %02x %02x | %02x %02x %02x %02x | %02x %02x %02x %02x | %02x %02x\n",
               coff_data[0], coff_data[1], coff_data[2], coff_data[3],
               coff_data[4], coff_data[5],
               coff_data[6], coff_data[7], coff_data[8], coff_data[9],
               coff_data[10], coff_data[11], coff_data[12], coff_data[13],
               coff_data[14], coff_data[15], coff_data[16], coff_data[17],
               coff_data[18], coff_data[19]);
    VERBOSE("\tsizeof(coff_file_header_t)=%zu\n", sizeof(coff_file_header_t));
    VERBOSE("\tMachine=0x%x\n", hdr->Machine);
    VERBOSE("\tNumberOfSections=%u\n", hdr->NumberOfSections);
    VERBOSE("\tTimeDateStamp=0x%x\n", hdr->TimeDateStamp);
    VERBOSE("\tPointerToSymbolTable=0x%x (%u)\n", hdr->PointerToSymbolTable, hdr->PointerToSymbolTable);
    VERBOSE("\tNumberOfSymbols=%u\n", hdr->NumberOfSymbols);
    VERBOSE("\tSizeOfOptionalHeader=%u\n", hdr->SizeOfOptionalHeader);
    VERBOSE("\tCharacteristics=0x%x\n", hdr->Characteristics);
    VERBOSE("\tfilesize=%u\n", filesize);
    VERBOSE("\tcheck: filesize(%u) < PointerToSymbolTable(%u) = %d\n",
               filesize, hdr->PointerToSymbolTable, (int)(filesize < hdr->PointerToSymbolTable));

    COFFSETUP_BAIL_IF(hdr->PointerToSymbolTable < sizeof(coff_file_header_t),
                      COFF_ERR_BAD_SYMTAB, "Symbol table overlaps file header (PtrSymTab=%u < sizeof(hdr)=%zu)\n",
                      hdr->PointerToSymbolTable, sizeof(coff_file_header_t));
    COFFSETUP_BAIL_IF(filesize < hdr->PointerToSymbolTable,
                      COFF_ERR_BAD_SYMTAB, "Symbol table offset exceeds file size (filesize=%u, symtab_offset=0x%x=%u)\n",
                      filesize, hdr->PointerToSymbolTable, hdr->PointerToSymbolTable);

    size_t strtab_off = hdr->PointerToSymbolTable
                      + (size_t)hdr->NumberOfSymbols * sizeof(struct coff_sym);

    COFFSETUP_BAIL_IF(filesize < strtab_off + sizeof(uint32_t),
                      COFF_ERR_BAD_SYMTAB, "String table size field exceeds file\n");

    uint32_t strtab_size = *(uint32_t*)(coff_data + strtab_off);

    COFFSETUP_BAIL_IF(filesize < strtab_off + strtab_size,
                      COFF_ERR_BAD_SYMTAB, "String table exceeds file\n");

    struct coff_sym* symtab = (struct coff_sym*)(coff_data + hdr->PointerToSymbolTable);

    char detail[384];
    int  retcode = 0;
    int  fmCount = 0;
    int  totalRelocs = 0;
    char shortbuf[9] = {0};

    constexpr uint16_t MAX_SECTIONS = 100;
    constexpr uint32_t MAX_SYMBOLS = 100000;

    char* entryfunc = functionname;
#if !defined(__x86_64__) && !defined(_WIN64)
    size_t eflen = __strlen(functionname);
    entryfunc = (char*)__malloc(eflen + 2);
    COFFSETUP_BAIL_IF(!entryfunc, COFF_ERR_ALLOC_FAIL, "calloc failed (entryfunc)\n");
    entryfunc[0] = '_';
    __memcpy(entryfunc + 1, functionname, eflen + 1);
#endif

    if (hdr->NumberOfSections == 0 || hdr->NumberOfSections > MAX_SECTIONS) {
        debugPrint( "Invalid section count: %u (max %u)",
                   hdr->NumberOfSections, MAX_SECTIONS);
        retcode = COFF_ERR_BAD_SECTIONS; goto cleanup;
    }

    if (hdr->NumberOfSymbols > MAX_SYMBOLS) {
        debugPrint( "Symbol table too large: %u (max %u)",
                   hdr->NumberOfSymbols, MAX_SYMBOLS);
        retcode = COFF_ERR_BAD_SYMTAB; goto cleanup;
    }

    totalRelocs = 0;
    for (int i = 0; i < hdr->NumberOfSections; i++) {
        coff_sect_t* s = (coff_sect_t*)(coff_data
            + sizeof(coff_file_header_t) + sizeof(coff_sect_t) * i);
        if (s->NumberOfRelocations > 10000) {
            debugPrint( "Too many relocations in section %d: %u",
                       i, s->NumberOfRelocations);
            retcode = COFF_ERR_BAD_SECTIONS; goto cleanup;
        }
        totalRelocs += s->NumberOfRelocations;
    }

    if (totalRelocs > 100000) {
        debugPrint( "Total relocations too large: %d", totalRelocs);
        retcode = COFF_ERR_BAD_SECTIONS; goto cleanup;
    }

    out->sectionCount   = hdr->NumberOfSections;
    out->sectionMapping = (char**)  __calloc(sizeof(char*)  * (hdr->NumberOfSections + 1), 1);
    out->sectionSizes   = (SIZE_T*) __calloc(sizeof(SIZE_T) * (hdr->NumberOfSections + 1), 1);

    if (!out->sectionMapping || !out->sectionSizes) {
        debugPrint( "calloc failed for tracking arrays (sections=%u)",
                   hdr->NumberOfSections);
        retcode = COFF_ERR_ALLOC_FAIL; goto cleanup;
    }

    {
        constexpr SIZE_T PAGE_SIZE = 0x1000;

        SIZE_T current_offset = 0;
        for (int i = 0; i < hdr->NumberOfSections; i++) {
            coff_sect_t* sect = (coff_sect_t*)(coff_data
                + sizeof(coff_file_header_t) + sizeof(coff_sect_t) * i);
            SIZE_T sz = sect->SizeOfRawData;
            if (sect->VirtualSize > sz) sz = sect->VirtualSize;
            if (!sz) sz = 8;
            if (sz > (SIZE_T)-1 - PAGE_SIZE) {
                debugPrint(
                          "Section %u size 0x%zx overflows page alignment", i, sz);
                return COFF_ERR_ALLOC_FAIL;
            }
            SIZE_T page_rounded = (sz + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
            if (page_rounded > (SIZE_T)-1 - current_offset) {
                debugPrint(
                          "Section layout overflow at section %u (offset=0x%zx)", i, current_offset);
                return COFF_ERR_ALLOC_FAIL;
            }
            current_offset = (current_offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
            current_offset += page_rounded;
        }

        if (current_offset > (SIZE_T)-1 - 0xFFFF) {
            debugPrint(
                      "Total reservation overflow: 0x%zx", current_offset);
            return COFF_ERR_ALLOC_FAIL;
        }
        SIZE_T total_reserve = (current_offset + 0xFFFF) & ~(SIZE_T)0xFFFF;

        PVOID reserve_base = NULL;
        NTSTATUS st = g_functionTable->NtAllocateVirtualMemory(
            (HANDLE)-1, &reserve_base, 0, &total_reserve,
            MEM_RESERVE | MEM_TOP_DOWN, PAGE_NOACCESS);
        if (!NT_SUCCESS(st) || !reserve_base) {
            debugPrint(
                      "Failed to reserve %zu bytes: 0x%08x", total_reserve, st);
            retcode = COFF_ERR_ALLOC_FAIL; goto cleanup;
        }

        out->blockBase    = reserve_base;

        current_offset = 0;
        for (int i = 0; i < hdr->NumberOfSections; i++) {
            coff_sect_t* sect = (coff_sect_t*)(coff_data
                + sizeof(coff_file_header_t) + sizeof(coff_sect_t) * i);

            SIZE_T sz = sect->SizeOfRawData;
            if (sect->VirtualSize > sz) sz = sect->VirtualSize;
            if (!sz) sz = 8;

            current_offset = (current_offset + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
            SIZE_T page_size = (sz + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

            PVOID addr = (char*)reserve_base + current_offset;

            SIZE_T commit_sz = page_size;
            st = g_functionTable->NtAllocateVirtualMemory(
                (HANDLE)-1, &addr, 0, &commit_sz,
                MEM_COMMIT, PAGE_READWRITE);
            if (!NT_SUCCESS(st)) {
                debugPrint(
                          "Commit failed for section %d at %p (size 0x%zx): 0x%08x",
                          i, addr, page_size, st);
                retcode = COFF_ERR_ALLOC_FAIL; goto cleanup;
            }

            if (sect->PointerToRawData && sect->SizeOfRawData) {
                __memcpy(addr, coff_data + sect->PointerToRawData, sect->SizeOfRawData);
                if (page_size > sect->SizeOfRawData)
                    __memset((char*)addr + sect->SizeOfRawData, 0, page_size - sect->SizeOfRawData);
            } else {
                __memset(addr, 0, page_size);
            }

            out->sectionMapping[i] = (char*)reserve_base + current_offset;
            out->sectionSizes[i]   = page_size;

            debugPrint("\tSection %d @ %p (rva 0x%zx)  sz=0x%zx  chars=0x%x  prot=RW (deferred)\n",
                       i, out->sectionMapping[i], current_offset, sz, sect->Characteristics);

            current_offset += page_size;
        }
    }

    {
        SIZE_T fmSz = (SIZE_T)totalRelocs * sizeof(void*) + sizeof(void*);

        out->functionMapping = (void**)alloc_data_mem(fmSz, &out->fmHandle);
        if (!out->functionMapping) {
            debugPrint("GOT allocation failed: %u bytes for %d relocs",
                      (unsigned int)fmSz, totalRelocs);
            retcode = COFF_ERR_ALLOC_FAIL; goto cleanup;
        }
    }

    for (int si = 0; si < hdr->NumberOfSections; si++) {
        coff_sect_t*  sect  = (coff_sect_t*)(coff_data
            + sizeof(coff_file_header_t) + sizeof(coff_sect_t) * si);
        coff_reloc_t* reloc = (coff_reloc_t*)(coff_data + sect->PointerToRelocations);

        for (int ri = 0; ri < sect->NumberOfRelocations; ri++, reloc++) {
            if (reloc->SymbolTableIndex >= hdr->NumberOfSymbols) {
                debugPrint("SymbolTableIndex OOB: %u >= %u (section %d)",
                          reloc->SymbolTableIndex, hdr->NumberOfSymbols, si);
                retcode = COFF_ERR_RELOC_OOB;
                goto cleanup;
            }
            struct coff_sym* sym = &symtab[reloc->SymbolTableIndex];
            char* symname = NULL;

            if (sym->first.value[0] == 0) {
                uint32_t stroff = sym->first.value[1];
                if (stroff >= strtab_size) {
                    debugPrint(
                              "String table OOB: offset %u >= %u (section %d)",
                              stroff, strtab_size, si);
                    retcode = COFF_ERR_RELOC_OOB; goto cleanup;
                }
                symname = (char*)(symtab + hdr->NumberOfSymbols) + stroff;
            } else {
                if (sym->first.Name[7] != '\0') {
                    __memcpy(shortbuf, sym->first.Name, 8);
                    shortbuf[8] = '\0';
                    symname = shortbuf;
                } else {
                    symname = sym->first.Name;
                }
            }

            debugPrint("[SetupCOFF]\t[%d/%d] sym=%s type=0x%x\n", si, ri, symname, reloc->Type);

            void* target = NULL;

            if (sym_is_defined(sym)) {
                if (sym->SectionNumber == 0) {
                    debugPrint(
                              "Undefined section for reloc [%d] sym='%s'",
                              si, symname ? symname : "unknown");
                    retcode = COFF_ERR_RELOC_OOB; goto cleanup;
                }
                if (sym->SectionNumber > hdr->NumberOfSections) {
                    debugPrint(
                              "SectionNumber OOB: %u > %u (section %d, sym='%s')",
                              sym->SectionNumber, hdr->NumberOfSections, si, symname ? symname : "unknown");
                    retcode = COFF_ERR_RELOC_OOB; goto cleanup;
                }
                target = (void*)((char*)out->sectionMapping[sym->SectionNumber - 1]
                               + sym->Value);
            } else if (sym_is_external(sym) && sym->Value == 0) {
                target = process_symbol(symname);
                if (!target) {
                    debugPrint(
                              "Unresolved external: '%s' (section %d, type 0x%x)",
                              symname ? symname : "unknown", si, reloc->Type);
                    retcode = COFF_ERR_UNRESOLVED_SYM; goto cleanup;
                }
                out->functionMapping[fmCount] = target;
                target = &out->functionMapping[fmCount];
                fmCount++;
            } else {
                debugPrint(
                          "Undefined symbol: '%s' (section %d, defined=%d, external=%d)",
                          symname ? symname : "unknown", si, sym_is_defined(sym), sym_is_external(sym));
                retcode = COFF_ERR_UNRESOLVED_SYM; goto cleanup;
            }

            {
                SIZE_T writeSize = (reloc->Type == IMAGE_REL_AMD64_ADDR64) ? 8 : 4;
                if (reloc->VirtualAddress + writeSize > out->sectionSizes[si]) {
                    debugPrint(
                              "Reloc VirtualAddress OOB: sect=%d va=0x%x writesz=%zu sectsz=%zu (sym='%s')",
                              si, reloc->VirtualAddress, writeSize, out->sectionSizes[si],
                              symname ? symname : "unknown");
                    retcode = COFF_ERR_RELOC_OOB; goto cleanup;
                }
            }

#ifdef _WIN32
#ifdef _WIN64
            {
                uint64_t lval = 0;

                if (reloc->Type == IMAGE_REL_AMD64_ADDR64) {
                    __memcpy(&lval, out->sectionMapping[si] + reloc->VirtualAddress, 8);
                    lval += (uint64_t)(uintptr_t)target;
                    __memcpy(out->sectionMapping[si] + reloc->VirtualAddress, &lval, 8);
                }
                else if (reloc->Type == IMAGE_REL_AMD64_ADDR32NB) {
                    ptrdiff_t diff =
                        (char*)out->sectionMapping[sym->SectionNumber - 1] + sym->Value
                        - ((char*)out->sectionMapping[si] + reloc->VirtualAddress + 4);

                    if ((ptrdiff_t)(int32_t)diff != diff) {
                        debugPrint(
                                  "ADDR32NB overflow: diff=0x%llx (section %u, sym='%s')",
                                  (unsigned long long)diff, si, symname ? symname : "unknown");
                        retcode = COFF_ERR_RELOC_OOB; goto cleanup;
                    }

                    uint32_t oval32 = (uint32_t)(int32_t)diff;
                    __memcpy(out->sectionMapping[si] + reloc->VirtualAddress, &oval32, 4);
                }
                else if (reloc->Type >= IMAGE_REL_AMD64_REL32 &&
                         reloc->Type <= IMAGE_REL_AMD64_REL32_5) {
                    int addend = reloc->Type - IMAGE_REL_AMD64_REL32;
                    uint32_t existing_val;
                    __memcpy(&existing_val, out->sectionMapping[si] + reloc->VirtualAddress, 4);
                    long long delta =
                        (long long)(uintptr_t)target
                        - (long long)((uintptr_t)(out->sectionMapping[si]
                                                  + reloc->VirtualAddress + 4 + addend));
                    if (llabs(delta) > (long long)INT32_MAX) {
                        debugPrint(
                                  "REL32_%d overflow: delta=%lld (section %u, sym='%s')",
                                  addend, (long long)delta, si, symname ? symname : "unknown");
                        retcode = COFF_ERR_RELOC_OOB; goto cleanup;
                    }
                    uint32_t result32 = existing_val + (uint32_t)delta;
                    __memcpy(out->sectionMapping[si] + reloc->VirtualAddress, &result32, 4);
                }
                else {
                    debugPrint(
                              "Unhandled reloc type 0x%x in section %u (sym='%s')",
                              reloc->Type, si, symname ? symname : "unknown");
                    retcode = COFF_ERR_BAD_RELOC_TYPE; goto cleanup;
                }
            }
#else
            {
                size_t oval = 0;
                if (reloc->Type == IMAGE_REL_I386_DIR32) {
                    __memcpy(&oval, out->sectionMapping[si] + reloc->VirtualAddress, 4);
                    oval = (uint32_t)(uintptr_t)target + oval;
                    __memcpy(out->sectionMapping[si] + reloc->VirtualAddress, &oval, 4);
                }
                else if (reloc->Type == IMAGE_REL_I386_REL32) {
                    __memcpy(&oval, out->sectionMapping[si] + reloc->VirtualAddress, 4);
                    oval += (uint32_t)(uintptr_t)target
                          - (uint32_t)((uintptr_t)(out->sectionMapping[si]
                                                   + reloc->VirtualAddress + 4));
                    __memcpy(out->sectionMapping[si] + reloc->VirtualAddress, &oval, 4);
                }
                else {
                    debugPrint("\tUnhandled reloc type 0x%x (section %d)\n",
                               reloc->Type, si);
                }
            }
#endif
#endif
        }
    }

    out->functionMappingCount = (uint16_t)fmCount;

    {
        constexpr SIZE_T PAGE_SIZE = 0x1000;

        for (int i = 0; i < hdr->NumberOfSections; i++) {
            if (!out->sectionMapping[i])
                continue;

            coff_sect_t* sect = (coff_sect_t*)(coff_data
                + sizeof(coff_file_header_t) + sizeof(coff_sect_t) * i);

            bool is_exec  = !!(sect->Characteristics & IMAGE_SCN_MEM_EXECUTE);
            bool is_write = !!(sect->Characteristics & IMAGE_SCN_MEM_WRITE);
            ULONG final_prot = is_exec ? (is_write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ)
                             : is_write ? PAGE_READWRITE
                             : PAGE_READONLY;

            PVOID base = out->sectionMapping[i];
            SIZE_T sz = sect->SizeOfRawData;
            if (sect->VirtualSize > sz) sz = sect->VirtualSize;
            if (!sz) sz = 8;
            SIZE_T page_sz = (sz + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
            ULONG old_prot = 0;

            NTSTATUS st = g_functionTable->NtProtectVirtualMemory(
                (HANDLE)-1, &base, &page_sz, final_prot, &old_prot);
            if (!NT_SUCCESS(st)) {
                debugPrint(
                          "NtProtectVirtualMemory failed for section %d: 0x%08x", i, st);
                retcode = COFF_ERR_PROTECT_FAIL; goto cleanup;
            }

            debugPrint("\tSection %d @ %p promoted to %s\n",
                       i, out->sectionMapping[i],
                       is_exec ? "RX" : is_write ? "RW" : "RO");
        }
    }

    {
        struct coff_sym* cursym = NULL;
        for (uint32_t si = 0; si < hdr->NumberOfSymbols; ) {
            cursym = &symtab[si];
            char* symname = NULL;

            if (cursym->first.value[0] == 0) {
                uint32_t stroff = cursym->first.value[1];
                if (stroff < strtab_size)
                    symname = (char*)(symtab + hdr->NumberOfSymbols) + stroff;
            } else {
                if (cursym->first.Name[7] != '\0') {
                    __memcpy(shortbuf, cursym->first.Name, 8);
                    shortbuf[8] = '\0';
                    symname = shortbuf;
                } else {
                    symname = cursym->first.Name;
                }
            }

            if (symname && __strcmp(symname, entryfunc) == 0) {
                if (cursym->SectionNumber == 0 || cursym->SectionNumber > hdr->NumberOfSections) {
                    debugPrint(
                              "Entry '%s' has invalid section number %u (sections=%u)",
                              entryfunc, cursym->SectionNumber, hdr->NumberOfSections);
                    retcode = COFF_ERR_ENTRY_NOT_FOUND;
                    goto cleanup;
                }
                out->entryPoint = (void*)((char*)out->sectionMapping[cursym->SectionNumber - 1]
                                         + cursym->Value);
                debugPrint("\tEntry '%s' @ %p\n", entryfunc, out->entryPoint);
                break;
            }

            si += 1 + cursym->NumberOfAuxSymbols;
        }
    }

    if (!out->entryPoint) {
        /* Maybe we should __snprintf(detail, sizeof(detail)) this to make sure it gets sent to
        server. This is kinda an important error... Eh.
        I guess we could check server-side instead... */
        debugPrint(
                  "Entry '%s' not found in symbol table (BOF size=%u, sections=%u, symbols=%u)",
                  entryfunc, filesize, hdr->NumberOfSections, hdr->NumberOfSymbols);
        retcode = COFF_ERR_ENTRY_NOT_FOUND; goto cleanup;
    }

cleanup:
    if (entryfunc && entryfunc != functionname)
        __free(entryfunc);
    if (retcode != 0)
        CleanupCOFF(out);
    return retcode;
}

void CleanupCOFF(COFF_LOADED* ctx) {
    if (!ctx) return;

    if (ctx->blockBase && ctx->sectionMapping && ctx->sectionCount > 0) {
        for (int i = 0; i < ctx->sectionCount; i++) {
            if (ctx->sectionMapping[i]) {
                PVOID base = ctx->sectionMapping[i];
                ULONG old = 0;
                SIZE_T dummy = 0;
                g_functionTable->NtProtectVirtualMemory(
                    (HANDLE)-1, &base, &dummy, PAGE_READWRITE, &old);
                SIZE_T wipeSize = ctx->sectionSizes ? ctx->sectionSizes[i] : 4096;
                crypto_wipe(ctx->sectionMapping[i], wipeSize);
            }
        }

        PVOID base = ctx->blockBase;
        SIZE_T zero = 0;
        g_functionTable->NtFreeVirtualMemory(
            (HANDLE)-1, &base, &zero, MEM_RELEASE);
    }

    if (ctx->functionMapping) {
        crypto_wipe(ctx->functionMapping, ctx->functionMappingCount * sizeof(void*));
        free_section_mem(ctx->functionMapping, ctx->fmHandle);
    }

    __free(ctx->sectionMapping);
    __free(ctx->sectionSizes);
    __memset(ctx, 0, sizeof(COFF_LOADED));
}