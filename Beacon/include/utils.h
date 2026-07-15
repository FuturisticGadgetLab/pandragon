#ifndef UTILS_H
#define UTILS_H


#include <stddef.h>
#include <stdint.h>
#include <atomic>

#define storeintext __attribute__((section(".text")))
#define storeintext_used __attribute__((used, section(".text")))
#define noinline __attribute__((noinline))

#define FILE_OPEN                         0x00000001
#define FILE_SYNCHRONOUS_IO_NONALERT      0x00000020
#define FILE_NON_DIRECTORY_FILE           0x00000040

#define MIN(a, b) \
    ((a) < (b) ? (a) : (b))

typedef unsigned short  uint16_t;

typedef signed char int8_t;
typedef unsigned char   uint8_t;

typedef unsigned   uint32_t;

typedef unsigned long long   uint64_t;
typedef long long  int64_t;
#ifndef size_t
#ifdef _WIN64
typedef unsigned long long size_t;
#else
typedef unsigned int size_t;
#endif
#endif
#ifndef SIZE_T
#ifdef _WIN64
typedef unsigned long long SIZE_T;
#else
typedef unsigned long SIZE_T;
#endif
#endif
#define UINT8_MAX 255
#define UINT16_MAX 65535
#define UINT32_MAX 0xffffffffU  /* 4294967295U */
#define UINT64_MAX 0xffffffffffffffffULL /* 18446744073709551615ULL */



/*
    Due to issues with gcc warnings:
    warning: 'wcsnicmp' redeclared without dllimport attribute: previous dllimport ignored [-Wattributes],
    it was decided that all custom functions will be prefixed with _, because _ still resulted in
    naming conflicts.
    Apologies.
*/

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Read the CPU time-stamp counter (x86 RDTSC instruction) */
uint64_t ___rdtsc(void);

size_t __wcslen(const wchar_t *str);
const wchar_t* __wcschr(const wchar_t* str, wchar_t ch);
char* __strtok(char* str, const char* delim);


int __atoi(const char *str);
int __wtoi(const wchar_t *str);
void* memcpy(void* dest, const void* src, size_t n);
void* __memcpy(void* dest, const void* src, size_t n);




void* __memset(void* dest, int value, size_t n);
int   __memcmp(const void *ptr1, const void *ptr2, size_t num);


int __snprintf(char *buffer, size_t size, const char *format, ...);
size_t __strlen(const char *str);

int __strcmp(const char *str1, const char *str2);
int __stricmp(const char *s1, const char *s2);
int __strncmp(const char *s1, const char *s2, size_t n);




int __wcsnicmp(const wchar_t *str1, const wchar_t *str2, size_t count);
int __wcsncmp(const wchar_t *str1, const wchar_t *str2, size_t count);
wchar_t* __wcsstr(const wchar_t* haystack, const wchar_t* needle);
int __wcscmp(const wchar_t *s1, const wchar_t *s2);


char *__strchr(const char *s, int c);
char *__strncpy(char *dest, const char *src, size_t n);


// Macro expansion (malleable C2)
char* expandMacros(const char* input);



int __wcsicmp(const wchar_t* a, const wchar_t* b);



void urlEncode(const char* input, char* output, size_t outputSize);
size_t __wcstombs(char *mbstr, const wchar_t *wcstr, size_t maxlen);
size_t __mbstowcs(wchar_t *wcstr, const char *mbstr, size_t max);

int __vsprintf(char* buf, const char* fmt, va_list args);
int __vsnprintf(char *buf, size_t limit, const char *fmt, va_list args);

void* __calloc(SIZE_T num, SIZE_T size);
[[nodiscard]] void* __malloc(SIZE_T size);
void  __free(void* ptr);
uint16_t __htons(uint16_t v);


bool is_avx_supported(void);

#ifndef __cplusplus // _bool is native to c++ on g++
    #define bool\t_Bool
        #if defined __STDC_VERSION__ && __STDC_VERSION__ > 201710L
            #define true\t((_Bool)+1u)
            #define false\t((_Bool)+0u)
    #else
        #define true\t1
        #define false\t0
    #endif
#endif


#ifndef __has_builtin
  #define __has_builtin(x) 0
#endif

/*
    Why flush in debugPrint? There was an issue where after 30-40 seconds, beacon stopped debug prints.
This is very likely coming from STDOUT being too buffered [?] so we flush it to not block print
statements [??]. It does not seem to work on Wine and I am out of ideas on how to fix it anyway.
                                                                    - Serexp
    maybe we need WriteConsole...
*/

#ifdef DEBUG
    #define debugPrint(fmt, ...) \
    { \
    funcTable->printf("[%s] " fmt "\n", __func__, ##__VA_ARGS__); \
    funcTable->FlushFileBuffers(getCurrentPEB()->ProcessParameters->StdOutputHandle); \
    }
    #define g_debugPrint(fmt, ...)  \
    { \
        g_functionTable->printf("[%s] " fmt "\n", __func__, ##__VA_ARGS__); \
        g_functionTable->FlushFileBuffers(getCurrentPEB()->ProcessParameters->StdOutputHandle); \
    };
    #define c_debugPrint(table, fmt, ...) \
    { \
        table->printf("[%s] " fmt "\n", __func__, ##__VA_ARGS__); /* for custom non-funcTable/g_functionTable tables. */ \
            table->FlushFileBuffers(getCurrentPEB()->ProcessParameters->StdOutputHandle); \
    };
    
#else
    #define debugPrint(fmt, ...) ;
    #define g_debugPrint(fmt, ...) ;
    #define c_debugPrint(table, fmt, ...) ;
#endif

#ifdef VERBOSE
    #define VERBOSE(fmt, ...) \
    { \
    funcTable->printf("[VERBOSE] [%s] " fmt "\n", __func__, ##__VA_ARGS__); \
    funcTable->FlushFileBuffers(getCurrentPEB()->ProcessParameters->StdOutputHandle); \
    }
    #define g_VERBOSE(fmt, ...) \
    { \
        g_functionTable->printf("[VERBOSE] [%s] " fmt "\n", __func__, ##__VA_ARGS__); \
        g_functionTable->FlushFileBuffers(getCurrentPEB()->ProcessParameters->StdOutputHandle); \
    }
    #define c_VERBOSE(t, fmt, ...) t->printf("[VERBOSE] [%s] " fmt "\n", __func__, ##__VA_ARGS__);
#else
    #define VERBOSE(fmt, ...) ;
    #define g_VERBOSE(fmt, ...) ;
    #define c_VERBOSE(t, fmt, ...) ;
#endif



#ifdef __cplusplus
}
#endif

void enterLock(volatile long* lock);
void leaveLock(volatile long* lock);

// Stack canary protection
void __init_stack_canary();
uint64_t __get_stack_canary();
void __stack_chk_fail() __attribute__((noreturn));

extern "C" void ___chkstk_ms(void);
extern "C" void __chkstk(void);

void safeWcsCopyBounded(wchar_t* dst, const wchar_t* src, size_t max_len);
void safeStrCopyBounded(char* dst, const char* src, size_t max_len);
void safeBoundedCopy(char* dst, const uint8_t* src, uint8_t src_len, size_t max_len);
void safeWcsCopyN(wchar_t* dst, const wchar_t* src, uint16_t n);

// PKCS#7 Padding Helpers
void pkcs7Pad(uint8_t* buf, size_t data_len, size_t padded_len);
// Returns unpadded length, or (size_t)-1 if padding is invalid/absent
size_t pkcs7Unpad(const uint8_t* buf, size_t padded_len);

#endif
