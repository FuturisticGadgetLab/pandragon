#include "../include/utils.h"
#include "../include/resolver.h"
#include "../libs/bastia/bastia.h"

/* Read from hardware clock */
#if defined(__i386__)
    uint64_t ___rdtsc(void) {
        uint64_t x;
        __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
        return x;
    }
#elif defined(__x86_64__)
    uint64_t ___rdtsc(void) {
        unsigned int hi, lo;
        __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
        return ((uint64_t)lo) | (((uint64_t)hi) << 32);
    }
#endif

/*  Tell the optimiser: “return value depends only on the arguments
    (none here) and has no observable side effects on the C world.”
    The CPUID is still executed every time the function is called. */
__attribute__((const))
bool is_avx_supported(void) {
    unsigned int eax, ebx, ecx, edx;
    __asm__ volatile (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "0"(1)
        : "cc"
    );
    return (ecx >> 28) & 1u;
}

size_t __wcslen(const wchar_t *str) {
    const wchar_t *s = str;
    while (*s) {
        s++;
    }
    return s - str;
}

wchar_t __wtolower(wchar_t ch) {
    if (ch >= L'A' && ch <= L'Z') {
        return ch + (L'a' - L'A');
    }
    return ch;
}

char tolower_char(char ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch + ('a' - 'A');
    }
    return ch;
}

void __tolower(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower_char(str[i]);
    }
}

int64_t __strtoll(const char* str, char** endptr, int base) {
    if (!str || (base < 2 || base > 36)) {
        if (endptr) *endptr = (char*)str;
        return 0;
    }

    // Skip leading whitespace
    while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r' || *str == '\v' || *str == '\f') {
        str++;
    }

    // Handle optional sign
    int sign = 1;
    if (*str == '-') {
        sign = -1;
        str++;
    } else if (*str == '+') {
        str++;
    }

    int64_t result = 0;
    while (*str) {
        int digit;
        if (*str >= '0' && *str <= '9') {
            digit = *str - '0';
        } else if (*str >= 'a' && *str <= 'z') {
            digit = *str - 'a' + 10;
        } else if (*str >= 'A' && *str <= 'Z') {
            digit = *str - 'A' + 10;
        } else {
            break; // Non-numeric character
        }

        if (digit >= base) {
            break; // Invalid digit for the given base
        }

        // Accumulate the result
        result = result * base + digit;
        str++;
    }

    if (endptr) {
        *endptr = (char*)str;
    }

    return result * sign;
}

char* __strrchr(const char* str, int c) {
    char* last_occurrence = NULL;
    char* current = (char*)str;

    while (*current != '\0') {
        if (*current == (char)c) {
            last_occurrence = current;
        }
        current++;
    }

    return last_occurrence;
}

/* ------------------------------------------------------------------ */
/* generic unsigned converter                                           */
static unsigned long long __strtoull(const char *nptr, char **endptr, int base,
           unsigned long long maxval, int is_unsigned)
{
    const unsigned char *s = (const unsigned char *)nptr;
    unsigned long long cutoff, cutlim, acc = 0;
    int overflow = 0;
    int neg = 0;
    int any = 0;

    (void)is_unsigned; (void)neg;  /* suppress unused warnings */

    /* skip white-space */
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r' || *s == '\f' || *s == '\v') {
        ++s;
    }

    /* optional sign */
    if (*s == '-') { neg = 1; ++s; }
    else if (*s == '+') ++s;

    /* auto-detect base */
    if (base == 0) {
        if (*s == '0') {
            if ((s[1] | 32) == 'x' && __isxdigit(s[2])) {
                base = 16;
                s += 2;
            } else {
                base = 8;
            }
        } else {
            base = 10;
        }
    } else if (base < 2 || base > 36) {
        if (endptr) *endptr = (char *)nptr;
        return 0;
    }

    /* thresholds for overflow test */
    cutoff = maxval / (unsigned long long)base;
    cutlim = maxval % (unsigned long long)base;

    /* main conversion loop */
    for ( ; ; ++s) {
        unsigned int c = *s;
        unsigned int digit;

        if (c >= '0' && c <= '9')      digit = c - '0';
        else if (c >= 'A' && c <= 'Z') digit = c - 'A' + 10;
        else if (c >= 'a' && c <= 'z') digit = c - 'a' + 10;
        else break;

        if (digit >= (unsigned)base) break;

        if (acc > cutoff || (acc == cutoff && digit > cutlim))
            overflow = 1;
        else {
            acc = acc * (unsigned long long)base + digit;
            any = 1;
        }
    }

    if (endptr) *endptr = (char *)(any ? (const char *)s : nptr);

    if (overflow) {
        // errno = ERANGE;
        return maxval;
    }

    /* for unsigned types the minus sign is ignored by the standard */
    return acc;
}

/* ------------------------------------------------------------------ */
/* public interfaces                                                    */

unsigned long __strtoul(const char *nptr, char **endptr, int base)
{
    return (unsigned long)__strtoull(nptr, endptr, base,
                                     ULONG_MAX, 1);
}

unsigned long long __strtoull(const char *nptr, char **endptr, int base)
{
    return __strtoull(nptr, endptr, base, ULLONG_MAX, 1);
}

uintmax_t __strtoumax(const char *nptr, char **endptr, int base)
{
    return (uintmax_t)__strtoull(nptr, endptr, base,
                                 (unsigned long long)UINTMAX_MAX, 1);
}

intmax_t __strtoimax(const char *nptr, char **endptr, int base)
{
    unsigned long long u = __strtoull(nptr, endptr, base,
                                      (unsigned long long)INTMAX_MAX + 1ULL, 1);
    if (u > (unsigned long long)INTMAX_MAX)
        return INTMAX_MIN + (u - (unsigned long long)INTMAX_MAX - 1);
    return u;
}

wchar_t* __wcsstr(const wchar_t* haystack, const wchar_t* needle) {
    if (*needle == L'\0') {
        return (wchar_t*)haystack; // Empty needle found at the beginning
    }

    for (; *haystack != L'\0'; ++haystack) {
        // If the first character matches, check for the rest of the needle
        if (*haystack == *needle) {
            const wchar_t* h = haystack;
            const wchar_t* n = needle;

            // Start comparing the next characters of haystack and needle
            while (*n != L'\0' && *h == *n) {
                ++h;
                ++n;
            }

            // If the whole needle is found, return the starting point in haystack
            if (*n == L'\0') {
                return (wchar_t*)haystack;
            }
        }
    }

    return NULL; // Needle not found
}


char* __strcat(char* dest, const char* src) {
    // Move the dest pointer to the end of the existing string
    while (*dest != '\0') {
        dest++;
    }

    // Append the src string to the dest string
    while (*src != '\0') {
        *dest = *src; // Copy each character from src to dest
        dest++;
        src++;
    }

    // Null-terminate the concatenated string
    *dest = '\0';

    // Return the original pointer to the start of the destination string
    return dest;
}

double __strtod(const char* str, char** endptr) {
    if (!str) {
        if (endptr) *endptr = (char*)str;
        return 0.0;
    }

    // Skip leading whitespace
    while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r' || *str == '\v' || *str == '\f') {
        str++;
    }

    // Handle optional sign
    int sign = 1;
    if (*str == '-') {
        sign = -1;
        str++;
    } else if (*str == '+') {
        str++;
    }

    // Parse integer part
    double result = 0.0;
    while (*str >= '0' && *str <= '9') {
        result = result * 10.0 + (*str - '0');
        str++;
    }

    // Parse fractional part
    if (*str == '.') {
        str++;
        double divisor = 10.0;
        while (*str >= '0' && *str <= '9') {
            result += (*str - '0') / divisor;
            divisor *= 10.0;
            str++;
        }
    }

    // Parse exponent
    if (*str == 'e' || *str == 'E') {
        str++;
        int expSign = 1;
        if (*str == '-') {
            expSign = -1;
            str++;
        } else if (*str == '+') {
            str++;
        }

        int exp = 0;
        while (*str >= '0' && *str <= '9') {
            exp = exp * 10 + (*str - '0');
            str++;
        }

        // Apply exponent
        double expFactor = 1.0;
        for (int i = 0; i < exp; i++) {
            expFactor *= 10.0;
        }
        if (expSign < 0) {
            result /= expFactor;
        } else {
            result *= expFactor;
        }
    }

    if (endptr) {
        *endptr = (char*)str;
    }

    return result * sign;
}

// URL-encode function for handling special characters (like newlines).
void urlEncode(const char* input, char* output, SIZE_T outputSize) {
    SIZE_T i = 0, j = 0;
    while (input[i] != '\0' && j < outputSize - 1) {
        if (input[i] == '\n') {
            // Replace newline with URL-encoded version "%0A"
            if (j + 3 <= outputSize) {
                output[j++] = '%';
                output[j++] = '0';
                output[j++] = 'A';
            }
        } else if (input[i] == ' ') {
            // Replace space with URL-encoded version "%20"
            if (j + 3 <= outputSize) {
                output[j++] = '%';
                output[j++] = '2';
                output[j++] = '0';
            }
        } else if (input[i] == '+') {
            // Replace plus sign with URL-encoded version "%2B"
            if (j + 3 <= outputSize) {
                output[j++] = '%';
                output[j++] = '2';
                output[j++] = 'B';
            }
        } else if (input[i] == '`') {
            // Replace backtick with URL-encoded version "%60"
            if (j + 3 <= outputSize) {
                output[j++] = '%';
                output[j++] = '6';
                output[j++] = '0';
            }
        } else if (input[i] == '\\') {
            // Double encode backslash for Markdown rendering
            if (j + 6 <= outputSize) {
                output[j++] = '%';
                output[j++] = '5';
                output[j++] = 'C';
                output[j++] = '%';
                output[j++] = '5';
                output[j++] = 'C';
            }
        } else {
            // Copy other characters as they are
            output[j++] = input[i];
        }
        i++;
    }
    output[j] = '\0'; // Null-terminate the output string
}

int __wtoi(const wchar_t *str) {
    int sign = 1;
    int result = 0;

    // Skip leading whitespace
    while (*str && *str <= L' ') {
        str++;
    }

    // Handle sign
    if (*str == L'-') {
        sign = -1;
        str++;
    } else if (*str == L'+') {
        str++;
    }

    // Convert digits
    while (*str >= L'0' && *str <= L'9') {
        int digit = *str - L'0';

        // Check for potential overflow before adding the digit
        if (result > INT_MAX / 10 || (result == INT_MAX / 10 && digit > INT_MAX % 10)) {
            return (sign == 1) ? INT_MAX : INT_MIN; // Return max or min based on sign
        }

        result = result * 10 + digit;
        str++;
    }

    return result * sign;
}

int __atoi(const char *str) {
    int sign = 1;
    int result = 0;

    //Skip leading whitespace
    while (*str && *str <= ' ') {
        str++;
    }

    //Handle sign
    if (*str == '-') {
        sign = -1;
        str++;
    } else if (*str == '+') {
        str++;
    }

    //Convert digits
    while (*str >= '0' && *str <= '9') {
        int digit = *str - '0';

        //Check for potential overflow before adding the digit.
        if (result > INT_MAX / 10 || (result == INT_MAX / 10 && digit > INT_MAX % 10)) {
            return (sign == 1) ? INT_MAX : INT_MIN; //Return max or min based on sign
        }

        result = result * 10 + digit;
        str++;
    }

    return result * sign;
}

char* __strncat(char* dest, const char* src, size_t n) {
    char* original_dest = dest;

    // Move the dest pointer to the end of the current string
    while (*dest != '\0') {
        dest++;
    }

    // Append up to n characters from src to dest
    while (n > 0 && *src != '\0') {
        *dest = *src;
        dest++;
        src++;
        n--;
    }

    // Null-terminate the concatenated string
    *dest = '\0';

    return original_dest; // Return the original destination pointer
}

wchar_t* __wcscat(wchar_t* dest, const wchar_t* src) {
    wchar_t* original_dest = dest;

    // Move the dest pointer to the end of the current string
    while (*dest != L'\0') {
        dest++;
    }

    // Copy src to the end of dest
    while (*src != L'\0') {
        *dest = *src;
        dest++;
        src++;
    }

    // Null-terminate the concatenated string
    *dest = L'\0';

    return original_dest; // Return the original destination pointer
}

wchar_t* __wcscpy(wchar_t* dest, const wchar_t* src) {
    wchar_t* original_dest = dest;

    // Copy src to dest including null terminator
    while (*src != L'\0') {
        *dest = *src;
        dest++;
        src++;
    }
    *dest = L'\0';

    return original_dest; // Return the original destination pointer
}



int __wcsnicmp(const wchar_t *str1, const wchar_t *str2, size_t count) {
    while (count-- > 0) {
        wchar_t ch1 = __wtolower(*str1);
        wchar_t ch2 = __wtolower(*str2);

        if (ch1 != ch2) {
            return (ch1 < ch2) ? -1 : 1;
        }
        if (ch1 == L'\0') {
            break;
        }
        str1++;
        str2++;
    }
    return 0;
}

int __wcsncmp(const wchar_t *str1, const wchar_t *str2, size_t count) {
    while (count-- > 0) {
        if (*str1 != *str2) {
            return (*str1 < *str2) ? -1 : 1;
        }
        if (*str1 == L'\0') {
            break;
        }
        str1++;
        str2++;
    }
    return 0;
}

char *__strchr(const char *s, int c) {
    while (*s) {
        if (*s == (char)c) {
            return (char *)s;
        }
        s++;
    }
    return NULL; // return NULL if character not found
}


int __wcscmp(const wchar_t *s1, const wchar_t *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned short *)s1 - *(unsigned short *)s2;
}

char *__strncpy(char *dest, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0'; // fill the remaining space with null bytes
    }
    return dest;
}

wchar_t *__wcsncpy(wchar_t *dest, const wchar_t *src, size_t n) {
    size_t i;
    for (i = 0; i < n && src[i] != L'\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = L'\0'; // fill the remaining space with null bytes
    }
    return dest;
}

void* __memcpy(void* dest, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;

    // Copy n bytes from src to dest
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }

    return dest;
}

void* memcpy(void* dest, const void* src, size_t n) {
    return __memcpy(dest, src, n);
}

void* __wmemcpy(void* dest, const void* src, size_t n) {
    wchar_t* d = (wchar_t*)dest;
    const wchar_t* s = (const wchar_t*)src;

    // Copy n wide characters from src to dest
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }

    return dest;
}

void* __memset(void* dest, int value, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    unsigned char v = (unsigned char)value;

    // Set n bytes to the specified value
    for (size_t i = 0; i < n; i++) {
        d[i] = v;
    }

    return dest;
}

void* memset(void* dest, int value, size_t n) {
    return __memset(dest, value, n);
}

int __memcmp(const void *ptr1, const void *ptr2, size_t num) {
    const unsigned char *p1 = (const unsigned char *)ptr1;
    const unsigned char *p2 = (const unsigned char *)ptr2;

    for (size_t i = 0; i < num; i++) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0; // They are equal
}

static pNtAllocateVirtualMemory NtAllocateVirtualMemory = NULL;
static pNtFreeVirtualMemory NtFreeVirtualMemory = NULL;
static HMODULE ntdllBase = NULL;
static char* ntAllocateVirtualMemoryName = NULL;
static char* ntFreeVirtualMemoryName = NULL;
static wchar_t* ntdllName = NULL;

void* __malloc(SIZE_T size) {
    if (size == 0) return NULL;  // Reject zero-size allocations
    
    if (!ntAllocateVirtualMemoryName) { ntAllocateVirtualMemoryName = lcg_encrypt("NtAllocateVirtualMemory"); }
    if (!ntdllName) { ntdllName = lcg_encryptw(L"ntdll.dll"); }
    if (!NtAllocateVirtualMemory) {
        if (!ntdllBase) { ntdllBase = GetModuleBaseAddress(ntdllName); }
        if (!ntdllBase) {
            return NULL;
        }
        NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)__GetProcAddress(ntdllBase, ntAllocateVirtualMemoryName);
        if (!NtAllocateVirtualMemory) return NULL;
    }

    void* baseAddress = NULL;
    NTSTATUS status = NtAllocateVirtualMemory(
        NtCurrentProcess(), // Or -1 for current process
        &baseAddress,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    return NT_SUCCESS(status) ? baseAddress : NULL;
}

void* __calloc(SIZE_T num, SIZE_T size) {
    // Check for integer overflow before multiplication
    if (num != 0 && size > SIZE_MAX / num) {
        return NULL;
    }
    SIZE_T total_size = num * size;
    void* ptr = __malloc(total_size);
    if (ptr) {
        __memset(ptr, 0, total_size);
    }
    return ptr;
}

void __free(void* ptr) {
    if (!ptr) return;
    if (!ntFreeVirtualMemoryName) { ntFreeVirtualMemoryName = lcg_encrypt("NtFreeVirtualMemory");}
    if (!ntdllName) { ntdllName = lcg_encryptw(L"ntdll.dll"); }
    if (!NtFreeVirtualMemory) {
        if (!ntdllBase) { ntdllBase = GetModuleBaseAddress(ntdllName); }
        NtFreeVirtualMemory = (pNtFreeVirtualMemory)__GetProcAddress(ntdllBase, ntFreeVirtualMemoryName);
        if (!NtFreeVirtualMemory) return;
    }
    if (NtFreeVirtualMemory) {
        void* base = ptr;
        NtFreeVirtualMemory(
            NtCurrentProcess(),
            &base,
            NULL,
            MEM_RELEASE
        );
    }
}

/*
 * Swap bytes in a 16-bit value:
 *   0xAABB -> 0xBBAA
 */
uint16_t __htons(uint16_t v) {
    return (uint16_t)((v << 8) | (v >> 8));
}

/* Network-to-host short is identical on little-endian machines */
uint16_t __ntohs(uint16_t v) {
    return __htons(v);
}

/*
 * Swap bytes in a 32-bit value:
 *   0xAABBCCDD -> 0xDDCCBBAA
 */
uint32_t __htonl(uint32_t v) {
    return ((v & 0x000000FFU) << 24) |
           ((v & 0x0000FF00U) <<  8) |
           ((v & 0x00FF0000U) >>  8) |
           ((v & 0xFF000000U) >> 24);
}

/* Network-to-host long is identical on little-endian machines */
uint32_t __ntohl(uint32_t v) {
    return __htonl(v);
}

size_t __strlen(const char *str) {
    const char *s = str; // Pointer to iterate through the string
    while (*s) { // Loop until the null terminator
        s++; // Move to the next character
    }
    return (size_t)(s - str); // Return the length
}

int __strcmp(const char *str1, const char *str2) {
    if (!str1) return str2 ? -1 : 0;
    if (!str2) return 1;
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return (unsigned char)(*str1) - (unsigned char)(*str2);
}


int __strncmp(const char *s1, const char *s2, size_t n) {
    // Check for null pointers
    if (s1 == NULL || s2 == NULL) {
        return (s1 == s2) ? 0 : (s1 ? 1 : -1);
    }

    while (n > 0) {
        unsigned char c1 = (unsigned char)*s1++;
        unsigned char c2 = (unsigned char)*s2++;

        // If characters differ, return the difference
        if (c1 != c2) {
            return (int)c1 - (int)c2;
        }

        // If we reached end of string, strings are equal
        if (c1 == '\0') {
            return 0;
        }

        n--;
    }

    return 0;
}

// =============================================================================
// Macro Expansion System
// =============================================================================
// Supported macros:
//   ${TIMESTAMP}      - Unix timestamp in seconds
//   ${RAND_B64:N}     - Random base64 string of N characters
//   ${JUNK:N}         - Random junk data of N characters (printable ASCII)
//   ${PAD_BASE64}     - Base64-like padding (== or =X where X is alphanumeric)

/*
 * Function-local statics for character tables.
 * Uses Meyer's singleton pattern because -nostartfiles bypasses C++ static initialization.
 */
static const char* get_base64_chars(void) {
    // URL-safe base64 (RFC 4648 §5): - instead of +, _ instead of /
    static const char* base64_chars = lcg_encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
    return base64_chars;
}

static const char* get_alnum_chars(void) {
    static const char* alnum_chars = lcg_encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    return alnum_chars;
}

/**
 * Generate random base64 string of specified length
 */
static void randB64(char* dest, size_t len) {
    if (!dest || len == 0) return;

    for (size_t i = 0; i < len; i++) {
        uint64_t r = ___rdtsc();
        dest[i] = get_base64_chars()[r % 64];
    }
    dest[len] = '\0';
}

/**
 * Generate random junk data (URL-safe alphanumeric only)
 */
static void randJunk(char* dest, size_t len) {
    if (!dest || len == 0) return;
    
    // URL-safe alphanumeric only: A-Z, a-z, 0-9
    static const char* url_safe = lcg_encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    
    for (size_t i = 0; i < len; i++) {
        uint64_t r = ___rdtsc();
        dest[i] = url_safe[r % 62];
    }
    dest[len] = '\0';
}

/**
 * Convert unsigned long long to string (simple implementation)
 */
static char* ulltoa(uint64_t val, char* buf, size_t bufsize) {
    if (!buf || bufsize < 2) return NULL;
    
    char* p = buf + bufsize - 1;
    *p = '\0';
    
    if (val == 0) {
        *--p = '0';
        return p;
    }
    
    while (val > 0 && p > buf) {
        *--p = '0' + (val % 10);
        val /= 10;
    }
    
    return p;
}

/**
 * Expand macros in a string
 * Returns newly allocated string (caller must __free)
 * 
 * Supported macros:
 *   ${TIMESTAMP}   - Unix timestamp
 *   ${RAND_B64:N}  - Random base64 (N chars)
 *   ${JUNK:N}      - Random junk (N chars)
 *   ${PAD_BASE64}  - Base64 padding
 */
char* expandMacros(const char* input) {
    if (!input) return NULL;

    // First pass: calculate expanded size
    size_t expanded_len = 0;
    const char* p = input;
    
    while (*p) {
        if (p[0] == '$' && p[1] == '{') {
            const char* end = __strchr(p, '}');
            if (!end) {
                expanded_len++;
                p++;
                continue;
            }
            
            size_t macro_len = end - p + 1;
            
            // Check for ${TIMESTAMP}
            if (macro_len == 12 && __strncmp(p, lcg_encrypt("${TIMESTAMP}"), 12) == 0) {
                // Timestamp is ~10 digits
                expanded_len += 10;
                p = end + 1;
                continue;
            }
            
            // Check for ${PAD_BASE64}
            if (macro_len == 12 && __strncmp(p, lcg_encrypt("${PAD_BASE64}"), 12) == 0) {
                expanded_len += 2;  // "==" or "=X"
                p = end + 1;
                continue;
            }
            
            // Check for ${RAND_B64:N} or ${JUNK:N}
            // ${JUNK:1} = 9 chars, ${RAND_B64:1} = 12 chars
            if (macro_len >= 9) {
                char macro_name[16] = {0};
                int arg_val = 0;

                // Extract macro name and argument
                const char* colon = __strchr(p, ':');
                if (colon && colon < end) {
                    size_t name_len = colon - p - 2;  // Skip "${"
                    if (name_len < sizeof(macro_name)) {
                        __memcpy(macro_name, p + 2, name_len);
                        macro_name[name_len] = '\0';
                        arg_val = __atoi(colon + 1);
                    }
                }

                if (arg_val > 0 && arg_val < 1000) {
                    if (__strcmp(macro_name, lcg_encrypt("RAND_B64")) == 0) {
                        expanded_len += arg_val;
                        p = end + 1;
                        continue;
                    }
                    if (__strcmp(macro_name, lcg_encrypt("JUNK")) == 0) {
                        expanded_len += arg_val;
                        p = end + 1;
                        continue;
                    }
                }
            }
            
            // Unknown macro, copy as-is
            expanded_len += macro_len;
            p = end + 1;
        } else {
            expanded_len++;
            p++;
        }
    }
    
    // Allocate result buffer
    char* result = (char*)__malloc(expanded_len + 1);
    if (!result) return NULL;
    
    // Second pass: expand macros
    char* out = result;
    p = input;
    
    while (*p) {
        if (p[0] == '$' && p[1] == '{') {
            const char* end = __strchr(p, '}');
            if (!end) {
                *out++ = *p++;
                continue;
            }
            
            size_t macro_len = end - p + 1;
            
            // ${TIMESTAMP}
            if (macro_len == 12 && __strncmp(p, lcg_encrypt("${TIMESTAMP}"), 12) == 0) {
                uint64_t ts = ___rdtsc() / 1000000;  // Approximate timestamp
                char ts_buf[24];
                char* ts_str = ulltoa(ts, ts_buf, sizeof(ts_buf));
                size_t ts_len = __strlen(ts_str);
                __memcpy(out, ts_str, ts_len);
                out += ts_len;
                p = end + 1;
                continue;
            }
            
            // ${PAD_BASE64}
            if (macro_len == 12 && __strncmp(p, lcg_encrypt("${PAD_BASE64}"), 12) == 0) {
                uint64_t r = ___rdtsc();
                if (r & 1) {
                    *out++ = '=';
                    *out++ = '=';
                } else {
                    *out++ = '=';
                    *out++ = get_alnum_chars()[r % 62];
                }
                p = end + 1;
                continue;
            }
            
            // ${RAND_B64:N} and ${JUNK:N}
            // ${JUNK:1} = 9 chars, ${RAND_B64:1} = 12 chars
            if (macro_len >= 9) {
                char macro_name[16] = {0};
                int arg_val = 0;

                const char* colon = __strchr(p, ':');
                if (colon && colon < end) {
                    size_t name_len = colon - p - 2;
                    if (name_len < sizeof(macro_name)) {
                        __memcpy(macro_name, p + 2, name_len);
                        macro_name[name_len] = '\0';
                        arg_val = __atoi(colon + 1);
                    }
                }

                if (arg_val > 0 && arg_val < 1000) {
                    if (__strcmp(macro_name, lcg_encrypt("RAND_B64")) == 0) {
                        randB64(out, arg_val);
                        out += arg_val;
                        p = end + 1;
                        continue;
                    }
                    if (__strcmp(macro_name, lcg_encrypt("JUNK")) == 0) {
                        randJunk(out, arg_val);
                        out += arg_val;
                        p = end + 1;
                        continue;
                    }
                }
            }
            
            // Unknown macro, copy as-is
            __memcpy(out, p, macro_len);
            out += macro_len;
            p = end + 1;
        } else {
            *out++ = *p++;
        }
    }
    
    *out = '\0';
    return result;
}

int __strnicmp(const char *s1, const char *s2, size_t n) {
    // Check for null pointers
    if (s1 == NULL || s2 == NULL) {
        return (s1 == s2) ? 0 : (s1 ? 1 : -1);
    }

    while (n > 0) {
        unsigned char c1 = (unsigned char)*s1++;
        unsigned char c2 = (unsigned char)*s2++;

        // Convert to lower case if they are alphabetic
        if (c1 >= 'A' && c1 <= 'Z') {
            c1 += ('a' - 'A');
        }
        if (c2 >= 'A' && c2 <= 'Z') {
            c2 += ('a' - 'A');
        }

        // If characters differ, return the difference
        if (c1 != c2) {
            return c1 - c2;
        }

        // If we've reached the end of either string, break
        if (c1 == '\0') {
            break;
        }

        n--;
    }

    return 0; // Strings are equal up to n characters
}

char* __strtok(char *str, const char *delim) {
    static char *next_token = NULL; //Static variable to maintain state between calls

    // First call: Initialize or reset the parsing
    if (str != NULL) {
        next_token = str;
    }

    // If there are no more tokens, return NULL
    if (next_token == NULL || *next_token == '\0') {
        return NULL;
    }

    char *token_start = next_token;
    char *token_end = __strchr(next_token, *delim);


    //If delim is not found, update the next_token and return the whole string
    if(token_end == NULL){
        next_token = next_token + __strlen(next_token);
        return token_start;
    }
    //Found the delimiter
    *token_end = '\0'; //Null-terminate the token
    next_token = token_end + 1; //Advance to the next character

    //Skip leading delimiters at the start of next token
    while (*next_token != '\0' && __strchr(delim, *next_token) != NULL) {
        next_token++;
    }


    return token_start;
}

wchar_t* __wcstok(wchar_t* str, const wchar_t* delim) {
    static wchar_t* next_token = NULL; // Static variable to maintain state between calls

    // First call: Initialize or reset the parsing
    if (str != NULL) {
        next_token = str;
    }

    // If there are no more tokens, return NULL
    if (next_token == NULL || *next_token == L'\0') {
        return NULL;
    }

    wchar_t* token_start = next_token;
    wchar_t* token_end = NULL;

    // Find the first delimiter in the string
    while (*next_token != L'\0') {
        const wchar_t* d = delim;
        while (*d != L'\0') {
            if (*next_token == *d) {
                token_end = next_token;
                break;
            }
            d++;
        }
        if (token_end != NULL) {
            break;
        }
        next_token++;
    }

    // If no delimiter found, return the whole string
    if (token_end == NULL) {
        next_token = next_token + __wcslen(next_token);
        return token_start;
    }

    // Found the delimiter
    *token_end = L'\0'; // Null-terminate the token
    next_token = token_end + 1; // Advance to the next character

    // Skip leading delimiters at the start of next token
    while (*next_token != L'\0') {
        const wchar_t* d = delim;
        int is_delim = 0;
        while (*d != L'\0') {
            if (*next_token == *d) {
                is_delim = 1;
                break;
            }
            d++;
        }
        if (!is_delim) {
            break;
        }
        next_token++;
    }

    return token_start;
}

int __isalnum(char c) {
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'));
}

int __iswalnum(wchar_t c) {
    return ((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') || (c >= L'0' && c <= L'9'));
}

#include <stdarg.h>
#include <stddef.h>

typedef unsigned int uint32_t;

[[maybe_unused]] static void utoa_reverse(char *buf, unsigned len)
/* reverse the digits we just generated */
{
    for (unsigned i = 0; i < len / 2; ++i) {
        char tmp      = buf[i];
        buf[i]        = buf[len - 1 - i];
        buf[len - 1 - i] = tmp;
    }
}

int __snwprintf(wchar_t *buffer, size_t size, const wchar_t *format, ...) {
    va_list args;
    size_t i = 0;
    const wchar_t *p = format;

    if (size == 0) return 0;

    va_start(args, format);

    while (*p) {
        if (*p == L'%') {
            const wchar_t *start = p++; // remember start for fall-back

            /* ---------- flags ---------- */
            int flags = 0;
            #define FL_ZERO     (1 << 0)    // zero-pad
            #define FL_LEFT     (1 << 1)    // left justify
            #define FL_SPACE    (1 << 2)    // space for positive numbers
            #define FL_PLUS     (1 << 3)    // force sign
            #define FL_UPPER    (1 << 4)    // uppercase hex

            while (1) {
                switch (*p) {
                case L'0': flags |= FL_ZERO; p++; continue;
                case L'-': flags |= FL_LEFT; p++; continue;
                case L' ': flags |= FL_SPACE; p++; continue;
                case L'+': flags |= FL_PLUS; p++; continue;
                }
                break;
            }

            /* ---------- width ---------- */
            int width = 0;
            if (*p >= L'0' && *p <= L'9') {
                while (*p >= L'0' && *p <= L'9') {
                    width = width * 10 + (*p++ - L'0');
                }
            } else if (*p == L'*') {
                width = va_arg(args, int);
                if (width < 0) { flags |= FL_LEFT; width = -width; }
                p++;
            }

            /* ---------- precision ---------- */
            int precision = -1;
            if (*p == L'.') {
                p++;
                if (*p >= L'0' && *p <= L'9') {
                    precision = 0;
                    while (*p >= L'0' && *p <= L'9') {
                        precision = precision * 10 + (*p++ - L'0');
                    }
                } else if (*p == L'*') {
                    precision = va_arg(args, int);
                    p++;
                } else {
                    precision = 0;
                }
            }

            /* ---------- length modifier ---------- */
            int is_long = 0;
            if (*p == L'l') { is_long = 1; p++; }

            switch (*p) {
            /* ---------------- strings / chars ---------------- */
            case L's': {
                const wchar_t *s = va_arg(args, const wchar_t *);
                if (!s) s = L"(null)";

                size_t len = __wcslen(s);
                if (precision >= 0 && (size_t)precision < len) {
                    len = precision;
                }

                // Apply width padding
                int pad = 0;
                if ((size_t)width > len) {
                    pad = width - len;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = (flags & FL_ZERO) ? L'0' : L' ';
                    }
                }

                // Copy string
                for (size_t k = 0; k < len && i < size - 1; k++) {
                    buffer[i++] = s[k];
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            case L'c': {
                wchar_t ch = (wchar_t)va_arg(args, int);
                int pad = 0;
                if (width > 1) {
                    pad = width - 1;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = (flags & FL_ZERO) ? L'0' : L' ';
                    }
                }

                if (i < size - 1) {
                    buffer[i++] = ch;
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            /* ---------------- signed decimal ---------------- */
            case L'd':
            case L'i': {
                long v;
                if (is_long) v = va_arg(args, long);
                else v = va_arg(args, int);

                wchar_t tmp[32];
                unsigned len = 0, neg = 0;

                if (v < 0) { neg = 1; v = -v; }

                if (v == 0) {
                    tmp[len++] = L'0';
                } else {
                    do { tmp[len++] = (wchar_t)(L'0' + (v % 10)); } while (v /= 10);
                }

                if (neg) tmp[len++] = L'-';

                // Apply precision
                if (precision >= 0) {
                    while (len < (unsigned)precision) {
                        tmp[len++] = L'0';
                    }
                }

                // Apply width padding
                int pad = 0;
                if ((size_t)width > len) {
                    pad = width - len;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    wchar_t pad_char = (flags & FL_ZERO) ? L'0' : L' ';
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = pad_char;
                    }
                }

                // Copy number
                for (unsigned k = 0; k < len && i < size - 1; k++) {
                    buffer[i++] = tmp[k];
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            /* ---------------- unsigned decimal ---------------- */
            case L'u': {
                unsigned long v;
                if (is_long) v = va_arg(args, unsigned long);
                else v = va_arg(args, unsigned int);

                wchar_t tmp[32];
                unsigned len = 0;

                if (v == 0) {
                    tmp[len++] = L'0';
                } else {
                    do { tmp[len++] = (wchar_t)(L'0' + (v % 10)); } while (v /= 10);
                }

                // Apply precision
                if (precision >= 0) {
                    while (len < (unsigned)precision) {
                        tmp[len++] = L'0';
                    }
                }

                // Apply width padding
                int pad = 0;
                if ((size_t)width > len) {
                    pad = width - len;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    wchar_t pad_char = (flags & FL_ZERO) ? L'0' : L' ';
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = pad_char;
                    }
                }

                // Copy number
                for (unsigned k = 0; k < len && i < size - 1; k++) {
                    buffer[i++] = tmp[k];
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            /* ---------------- octal ---------------- */
            case L'o': {
                unsigned long v;
                if (is_long) v = va_arg(args, unsigned long);
                else v = va_arg(args, unsigned int);

                wchar_t tmp[32];
                unsigned len = 0;

                if (v == 0) {
                    tmp[len++] = L'0';
                } else {
                    do { tmp[len++] = (wchar_t)(L'0' + (v & 7)); } while (v >>= 3);
                }

                // Apply precision
                if (precision >= 0) {
                    while (len < (unsigned)precision) {
                        tmp[len++] = L'0';
                    }
                }

                // Apply width padding
                int pad = 0;
                if ((size_t)width > len) {
                    pad = width - len;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    wchar_t pad_char = (flags & FL_ZERO) ? L'0' : L' ';
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = pad_char;
                    }
                }

                // Copy number
                for (unsigned k = 0; k < len && i < size - 1; k++) {
                    buffer[i++] = tmp[k];
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            /* ---------------- hex ---------------- */
            case L'x':
            case L'X': {
                unsigned long v;
                if (is_long) v = va_arg(args, unsigned long);
                else v = va_arg(args, unsigned int);

                wchar_t tmp[32];
                unsigned len = 0;
                const wchar_t *digits = (*p == L'x') ? L"0123456789abcdef"
                                                     : L"0123456789ABCDEF";

                if (v == 0) {
                    tmp[len++] = L'0';
                } else {
                    do { tmp[len++] = digits[v & 0xF]; } while (v >>= 4);
                }

                // Apply precision
                if (precision >= 0) {
                    while (len < (unsigned)precision) {
                        tmp[len++] = L'0';
                    }
                }

                // Apply width padding
                int pad = 0;
                if ((size_t)width > len) {
                    pad = width - len;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    wchar_t pad_char = (flags & FL_ZERO) ? L'0' : L' ';
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = pad_char;
                    }
                }

                // Copy number
                for (unsigned k = 0; k < len && i < size - 1; k++) {
                    buffer[i++] = tmp[k];
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            /* ---------------- pointer ---------------- */
            case L'p': {
                uintptr_t v = (uintptr_t)va_arg(args, void *);

                if (!v) {
                    const wchar_t nil[] = L"(nil)";
                    for (size_t k = 0; nil[k] && i < size - 1; k++) {
                        buffer[i++] = nil[k];
                    }
                    break;
                }

                // 0x prefix
                if (i < size - 1) buffer[i++] = L'0';
                if (i < size - 1) buffer[i++] = L'x';

                wchar_t tmp[32];
                unsigned len = 0;
                const wchar_t digits[] = L"0123456789abcdef";

                do { tmp[len++] = digits[v & 0xF]; } while (v >>= 4);

                // Apply width padding (after prefix)
                int pad = 0;
                if ((size_t)width > len + 2) {
                    pad = width - len - 2;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }

                // Copy number
                for (unsigned k = 0; k < len && i < size - 1; k++) {
                    buffer[i++] = tmp[k];
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            /* ---------------- literal % ---------------- */
            case L'%':
                if (i < size - 1) buffer[i++] = L'%';
                break;

            /* ---------------- unknown ---------------- */
            default:
                for (const wchar_t *q = start; q <= p && i < size - 1; q++) {
                    buffer[i++] = *q;
                }
                break;
            }
            ++p;
        } else {
            if (i < size - 1) buffer[i++] = *p++;
            else ++p;
        }
    }

    if (i < size)
        buffer[i] = L'\0';
    else if (size > 0)
        buffer[size - 1] = L'\0';

    va_end(args);
    return (int)i;
}

int __swprintf(wchar_t *buffer, size_t size, const wchar_t *format, ...) {
    va_list args;
    size_t i = 0;
    const wchar_t *p = format;

    if (size == 0) return 0;

    va_start(args, format);

    while (*p) {
        if (*p == L'%') {
            const wchar_t *start = p++; // remember start for fall-back

            /* ---------- flags ---------- */
            int flags = 0;
            #define FL_ZERO     (1 << 0)    // zero-pad
            #define FL_LEFT     (1 << 1)    // left justify
            #define FL_SPACE    (1 << 2)    // space for positive numbers
            #define FL_PLUS     (1 << 3)    // force sign
            #define FL_UPPER    (1 << 4)    // uppercase hex

            while (1) {
                switch (*p) {
                case L'0': flags |= FL_ZERO; p++; continue;
                case L'-': flags |= FL_LEFT; p++; continue;
                case L' ': flags |= FL_SPACE; p++; continue;
                case L'+': flags |= FL_PLUS; p++; continue;
                }
                break;
            }

            /* ---------- width ---------- */
            int width = 0;
            if (*p >= L'0' && *p <= L'9') {
                while (*p >= L'0' && *p <= L'9') {
                    width = width * 10 + (*p++ - L'0');
                }
            } else if (*p == L'*') {
                width = va_arg(args, int);
                if (width < 0) { flags |= FL_LEFT; width = -width; }
                p++;
            }

            /* ---------- precision ---------- */
            int precision = -1;
            if (*p == L'.') {
                p++;
                if (*p >= L'0' && *p <= L'9') {
                    precision = 0;
                    while (*p >= L'0' && *p <= L'9') {
                        precision = precision * 10 + (*p++ - L'0');
                    }
                } else if (*p == L'*') {
                    precision = va_arg(args, int);
                    p++;
                } else {
                    precision = 0;
                }
            }

            /* ---------- length modifier ---------- */
            int is_long = 0;
            if (*p == L'l') { is_long = 1; p++; }

            switch (*p) {
            /* ---------------- strings / chars ---------------- */
            case L's': {
                const wchar_t *s = va_arg(args, const wchar_t *);
                if (!s) s = L"(null)";

                size_t len = __wcslen(s);
                if (precision >= 0 && (size_t)precision < len) {
                    len = precision;
                }

                // Apply width padding
                int pad = 0;
                if ((size_t)width > len) {
                    pad = width - len;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = (flags & FL_ZERO) ? L'0' : L' ';
                    }
                }

                // Copy string
                for (size_t k = 0; k < len && i < size - 1; k++) {
                    buffer[i++] = s[k];
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            case L'c': {
                wchar_t ch = (wchar_t)va_arg(args, int);
                int pad = 0;
                if (width > 1) {
                    pad = width - 1;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = (flags & FL_ZERO) ? L'0' : L' ';
                    }
                }

                if (i < size - 1) {
                    buffer[i++] = ch;
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            /* ---------------- signed decimal ---------------- */
            case L'd':
            case L'i': {
                long v;
                if (is_long) v = va_arg(args, long);
                else v = va_arg(args, int);

                wchar_t tmp[32];
                unsigned len = 0, neg = 0;

                if (v < 0) { neg = 1; v = -v; }

                if (v == 0) {
                    tmp[len++] = L'0';
                } else {
                    do { tmp[len++] = (wchar_t)(L'0' + (v % 10)); } while (v /= 10);
                }

                if (neg) tmp[len++] = L'-';

                // Apply precision
                if (precision >= 0) {
                    while (len < (unsigned)precision) {
                        tmp[len++] = L'0';
                    }
                }

                // Apply width padding
                int pad = 0;
                if ((size_t)width > len) {
                    pad = width - len;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    wchar_t pad_char = (flags & FL_ZERO) ? L'0' : L' ';
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = pad_char;
                    }
                }

                // Copy number
                for (unsigned k = 0; k < len && i < size - 1; k++) {
                    buffer[i++] = tmp[k];
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            /* ---------------- unsigned decimal ---------------- */
            case L'u': {
                unsigned long v;
                if (is_long) v = va_arg(args, unsigned long);
                else v = va_arg(args, unsigned int);

                wchar_t tmp[32];
                unsigned len = 0;

                if (v == 0) {
                    tmp[len++] = L'0';
                } else {
                    do { tmp[len++] = (wchar_t)(L'0' + (v % 10)); } while (v /= 10);
                }

                // Apply precision
                if (precision >= 0) {
                    while (len < (unsigned)precision) {
                        tmp[len++] = L'0';
                    }
                }

                // Apply width padding
                int pad = 0;
                if ((size_t)width > len) {
                    pad = width - len;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    wchar_t pad_char = (flags & FL_ZERO) ? L'0' : L' ';
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = pad_char;
                    }
                }

                // Copy number
                for (unsigned k = 0; k < len && i < size - 1; k++) {
                    buffer[i++] = tmp[k];
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            /* ---------------- octal ---------------- */
            case L'o': {
                unsigned long v;
                if (is_long) v = va_arg(args, unsigned long);
                else v = va_arg(args, unsigned int);

                wchar_t tmp[32];
                unsigned len = 0;

                if (v == 0) {
                    tmp[len++] = L'0';
                } else {
                    do { tmp[len++] = (wchar_t)(L'0' + (v & 7)); } while (v >>= 3);
                }

                // Apply precision
                if (precision >= 0) {
                    while (len < (unsigned)precision) {
                        tmp[len++] = L'0';
                    }
                }

                // Apply width padding
                int pad = 0;
                if ((size_t)width > len) {
                    pad = width - len;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    wchar_t pad_char = (flags & FL_ZERO) ? L'0' : L' ';
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = pad_char;
                    }
                }

                // Copy number
                for (unsigned k = 0; k < len && i < size - 1; k++) {
                    buffer[i++] = tmp[k];
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            /* ---------------- hex ---------------- */
            case L'x':
            case L'X': {
                unsigned long v;
                if (is_long) v = va_arg(args, unsigned long);
                else v = va_arg(args, unsigned int);

                wchar_t tmp[32];
                unsigned len = 0;
                const wchar_t *digits = (*p == L'x') ? L"0123456789abcdef"
                                                     : L"0123456789ABCDEF";

                if (v == 0) {
                    tmp[len++] = L'0';
                } else {
                    do { tmp[len++] = digits[v & 0xF]; } while (v >>= 4);
                }

                // Apply precision
                if (precision >= 0) {
                    while (len < (unsigned)precision) {
                        tmp[len++] = L'0';
                    }
                }

                // Apply width padding
                int pad = 0;
                if ((size_t)width > len) {
                    pad = width - len;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    wchar_t pad_char = (flags & FL_ZERO) ? L'0' : L' ';
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = pad_char;
                    }
                }

                // Copy number
                for (unsigned k = 0; k < len && i < size - 1; k++) {
                    buffer[i++] = tmp[k];
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            /* ---------------- pointer ---------------- */
            case L'p': {
                uintptr_t v = (uintptr_t)va_arg(args, void *);

                if (!v) {
                    const wchar_t nil[] = L"(nil)";
                    for (size_t k = 0; nil[k] && i < size - 1; k++) {
                        buffer[i++] = nil[k];
                    }
                    break;
                }

                // 0x prefix
                if (i < size - 1) buffer[i++] = L'0';
                if (i < size - 1) buffer[i++] = L'x';

                wchar_t tmp[32];
                unsigned len = 0;
                const wchar_t digits[] = L"0123456789abcdef";

                do { tmp[len++] = digits[v & 0xF]; } while (v >>= 4);

                // Apply width padding (after prefix)
                int pad = 0;
                if ((size_t)width > len + 2) {
                    pad = width - len - 2;
                }

                // Right justify (pad left) unless left justify flag
                if (!(flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }

                // Copy number
                for (unsigned k = 0; k < len && i < size - 1; k++) {
                    buffer[i++] = tmp[k];
                }

                // Left justify (pad right)
                if ((flags & FL_LEFT) && pad > 0) {
                    for (int k = 0; k < pad && i < size - 1; k++) {
                        buffer[i++] = L' ';
                    }
                }
                break;
            }

            /* ---------------- literal % ---------------- */
            case L'%':
                if (i < size - 1) buffer[i++] = L'%';
                break;

            /* ---------------- unknown ---------------- */
            default:
                for (const wchar_t *q = start; q <= p && i < size - 1; q++) {
                    buffer[i++] = *q;
                }
                break;
            }
            ++p;
        } else {
            if (i < size - 1) buffer[i++] = *p++;
            else ++p;
        }
    }

    if (i < size)
        buffer[i] = L'\0';
    else if (size > 0)
        buffer[size - 1] = L'\0';

    va_end(args);
    return (int)i;
}


char* __strcpy(char *dest, const char *src) {
    char *temp = dest;
    while ((*dest++ = *src++) != '\0');
    return temp;
}

char* __strstr(const char *haystack, const char *needle) {
    if (*needle == '\0') {
        return (char *)haystack; // Empty needle found at the beginning
    }

    for (; *haystack != '\0'; ++haystack) {
        // If the first character matches, check for the rest of the needle.
        if (*haystack == *needle) {
            const char *h = haystack;
            const char *n = needle;

            // Start comparing the next characters of haystack and needle.
            while (*n != '\0' && *h == *n) {
                ++h;
                ++n;
            }

            // If the whole needle is found, return the starting point in haystack
            if (*n == '\0') {
                return (char *)haystack;
            }
        }
    }

    return NULL; // Needle not found
}

void* __memmove(void* dest, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;

    // Check for overlapping regions
    if (d < s) {
        // Non-overlapping or src is after dest
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
    } else if (d > s) {
        // Overlapping regions, copy backwards
        for (size_t i = n; i > 0; i--) {
            d[i - 1] = s[i - 1];
        }
    }
    // If d == s, do nothing (no need to move)

    return dest; // Return the destination pointer
}

int __isxdigit(int c) {
    // Check if the character is between '0' and '9'
    if (c >= '0' && c <= '9') {
        return 1; // Return true (1) for digits
    }
    // Check if the character is between 'a' and 'f'
    if (c >= 'a' && c <= 'f') {
        return 1; // Return true (1) for lowercase hex digits
    }
    // Check if the character is between 'A' and 'F'
    if (c >= 'A' && c <= 'F') {
        return 1; // Return true (1) for uppercase hex digits
    }
    return 0; // Return false (0) for non-hexadecimal characters
}

int __isalphanum(int c) {
    // Check if the character is a digit (0-9)
    if (c >= '0' && c <= '9') {
        return 1; // Return true (1) for digits
    }
    // Check if the character is a lowercase letter (a-z)
    if (c >= 'a' && c <= 'z') {
        return 1; // Return true (1) for lowercase letters
    }
    // Check if the character is an uppercase letter (A-Z)
    if (c >= 'A' && c <= 'Z') {
        return 1; // Return true (1) for uppercase letters
    }
    return 0; // Return false (0) for non-alphanumeric characters
}

size_t __wcstombs(char* mbstr, const wchar_t* wcstr, size_t maxlen) {
    if (mbstr == NULL || wcstr == NULL || maxlen == 0) {
        return 0;
    }

    size_t i = 0; // index for wcstr
    size_t count = 0; // count of bytes written to mbstr

    while (wcstr[i] != L'\0' && count < maxlen) {
        wchar_t wc = wcstr[i++];
        
        // Handle surrogate pairs (U+10000 to U+10FFFF)
        if (wc >= 0xD800 && wc <= 0xDBFF) { // High surrogate
            if (wcstr[i] >= 0xDC00 && wcstr[i] <= 0xDFFF) { // Low surrogate
                uint32_t codepoint = (((wc - 0xD800) << 10) | (wcstr[i] - 0xDC00)) + 0x10000;
                i++; // Consume low surrogate

                if (count + 4 < maxlen) {
                    mbstr[count++] = (char)(0xF0 | (codepoint >> 18));
                    mbstr[count++] = (char)(0x80 | ((codepoint >> 12) & 0x3F));
                    mbstr[count++] = (char)(0x80 | ((codepoint >> 6) & 0x3F));
                    mbstr[count++] = (char)(0x80 | (codepoint & 0x3F));
                } else {
                    break; // Not enough space
                }
            } else { // Unmatched high surrogate, treat as error
                 if (count + 1 < maxlen) {
                    mbstr[count++] = '?';
                } else {
                    break;
                }
            }
        }
        // Basic Multilingual Plane (BMP)
        else if (wc < 0x80) {
            if (count + 1 < maxlen) {
                mbstr[count++] = (char)wc;
            } else {
                break;
            }
        } else if (wc < 0x800) {
            if (count + 2 < maxlen) {
                mbstr[count++] = (char)(0xC0 | (wc >> 6));
                mbstr[count++] = (char)(0x80 | (wc & 0x3F));
            } else {
                break;
            }
        } else { // 0x800 <= wc <= 0xFFFF (excluding surrogates which are handled above)
            if (count + 3 < maxlen) {
                mbstr[count++] = (char)(0xE0 | (wc >> 12));
                mbstr[count++] = (char)(0x80 | ((wc >> 6) & 0x3F));
                mbstr[count++] = (char)(0x80 | (wc & 0x3F));
            } else {
                break;
            }
        }
    }

    if (count < maxlen) {
        mbstr[count] = '\0';
    } else if (maxlen > 0) {
        mbstr[maxlen - 1] = '\0';
    }
    
    return count;
}

size_t __mbstowcs(wchar_t *wcstr, const char *mbstr, size_t max) {
    size_t count = 0;
    size_t i = 0;

    if (wcstr == NULL || mbstr == NULL) {
        return (size_t)-1; // Error: null pointer
    }

    while (mbstr[i] && count < max) {
        unsigned char c = (unsigned char)mbstr[i];
        uint32_t codepoint = 0;

        if (c < 0x80) { // 1-byte
            codepoint = c;
            i += 1;
        } else if ((c & 0xE0) == 0xC0) { // 2-byte
            if ((mbstr[i+1] & 0xC0) == 0x80) {
                codepoint = ((c & 0x1F) << 6) | (mbstr[i+1] & 0x3F);
                i += 2;
            } else { return (size_t)-1; }
        } else if ((c & 0xF0) == 0xE0) { // 3-byte
            if ((mbstr[i+1] & 0xC0) == 0x80 && (mbstr[i+2] & 0xC0) == 0x80) {
                codepoint = ((c & 0x0F) << 12) | ((mbstr[i+1] & 0x3F) << 6) | (mbstr[i+2] & 0x3F);
                i += 3;
            } else { return (size_t)-1; }
        } else if ((c & 0xF8) == 0xF0) { // 4-byte
             if ((mbstr[i+1] & 0xC0) == 0x80 && (mbstr[i+2] & 0xC0) == 0x80 && (mbstr[i+3] & 0xC0) == 0x80) {
                codepoint = ((c & 0x07) << 18) | ((mbstr[i+1] & 0x3F) << 12) | ((mbstr[i+2] & 0x3F) << 6) | (mbstr[i+3] & 0x3F);
                i += 4;
            } else { return (size_t)-1; }
        } else {
            return (size_t)-1;
        }

        if (codepoint <= 0xFFFF) {
            if (count < max) {
                wcstr[count++] = (wchar_t)codepoint;
            } else {
                break;
            }
        } else { // Create surrogate pair
            if (count + 1 < max) {
                codepoint -= 0x10000;
                wcstr[count++] = (wchar_t)((codepoint >> 10) + 0xD800);
                wcstr[count++] = (wchar_t)((codepoint & 0x03FF) + 0xDC00);
            } else {
                break;
            }
        }
    }

    if (count < max) {
        wcstr[count] = L'\0';
    }

    return count;
}

int dcTokens_snprintf(char *buf, size_t size, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    const char *ptr = format;
    size_t i = 0;

    while (*ptr != '\0') {
        if (*ptr == '%' && *(ptr + 1) == '.') {
            // Found the "%.*s" format specifier
            ptr += 2;  // Skip '%' and '.'
            size_t precision = (size_t)va_arg(args, int);  // Get precision and convert to size_t
            const char *str = va_arg(args, const char *);  // Get the string argument

            // Determine the number of characters to copy based on precision
            size_t len = __strlen(str);
            size_t to_copy = (precision < len) ? precision : len;

            // Ensure there is enough space in the buffer
            size_t space_left = size - i;
            to_copy = (to_copy < space_left) ? to_copy : space_left;

            // Copy the string (up to the precision or remaining buffer size)
            for (size_t j = 0; j < to_copy; ++j) {
                buf[i++] = str[j];
            }

            // Continue parsing the format string
            ptr++;
        } else {
            // Copy the regular character to the buffer
            if (i < size - 1) {  // Ensure there's space in the buffer
                buf[i++] = *ptr;
            }
            ptr++;
        }
    }

    // Null-terminate the string
    buf[i] = '\0';

    va_end(args);
    return (int)i;  // Return the number of characters written (excluding null-terminator)
}

int __stricmp(const char *s1, const char *s2) {
    // Handle null pointer cases (implementation-defined behavior)
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    
    // Process characters one by one until difference or end of string
    while (1) {
        unsigned char c1 = (unsigned char)*s1;
        unsigned char c2 = (unsigned char)*s2;
        
        // Convert to lowercase for comparison
        int lc1 = tolower_char(c1);
        int lc2 = tolower_char(c2);
        
        // If characters differ, return the difference
        if (lc1 != lc2) {
            return lc1 - lc2;
        }
        
        // If we reached end of both strings, they are equal
        if (lc1 == 0) {
            return 0;
        }
        
        s1++;
        s2++;
    }
}
/*
 * Windows Stack Probing Routines (__chkstk / ___chkstk_ms)
 * * Implemented in inline assembly for GCC/Clang (MinGW/LLVM).
 * These functions must be 'naked' because they manipulate the stack pointer
 * and registers before a standard C frame exists.
 */

// Macros to handle architecture detection
#if defined(__x86_64__) || defined(_M_X64)
    #define ARCH_X64 1
#elif defined(__i386__) || defined(_M_IX86)
    #define ARCH_X86 1
#else
    #error "Unsupported architecture. Only x86 and x64 are supported."
#endif

// Helper macro for naked functions
#define NAKED __attribute__((naked))

#if defined(ARCH_X64)

/* * ----------------------------------------------------------------------------
 * x64 Implementation
 * * On x64, ___chkstk_ms and __chkstk have identical semantics. 
 * Neither adjusts the stack pointer (rsp). The caller adjusts rsp after the probe.
 * * Input:  RAX = Frame size
 * Output: None (Preserves all registers)
 * ----------------------------------------------------------------------------
 */

extern "C"
__attribute__((used))

NAKED void ___chkstk_ms(void) {
    __asm__ volatile (
        "push   %rax                  \n\t"
        "push   %rcx                  \n\t"
        "mov    %gs:(0x10), %rcx     \n\t" // rcx = TIB->StackLimit
        "neg    %rax                  \n\t" // rax = -frame_size
        "add    %rsp, %rax           \n\t" // rax = target frame low address
        "jb     1f                     \n\t" // If overflow (unsigned <), jump to 1
        "xor    %eax, %eax           \n\t" // Overflowed: frame low address = 0
        "0:                            \n\t"
        "sub    $0x1000, %rcx         \n\t" // Move down one page (4096 bytes)
        "test   %eax, (%rcx)         \n\t" // Probe: read/write to commit page
        "1:                            \n\t"
        "cmp    %rax, %rcx           \n\t" // Have we reached the target low address?
        "ja     0b                     \n\t" // If rcx > rax, continue looping
        "pop    %rcx                  \n\t"
        "pop    %rax                  \n\t"
        "ret                           \n\t"
    );
}

// On x64, __chkstk is an alias to ___chkstk_ms semantics.
__attribute__((used))

NAKED void __chkstk(void) {
    __asm__ volatile (
        "push   %rax                  \n\t"
        "push   %rcx                  \n\t"
        "mov    %gs:(0x10), %rcx     \n\t" 
        "neg    %rax                  \n\t" 
        "add    %rsp, %rax           \n\t" 
        "jb     1f                     \n\t" 
        "xor    %eax, %eax           \n\t" 
        "0:                            \n\t"
        "sub    $0x1000, %rcx         \n\t" 
        "test   %eax, (%rcx)         \n\t" 
        "1:                            \n\t"
        "cmp    %rax, %rcx           \n\t" 
        "ja     0b                     \n\t" 
        "pop    %rcx                  \n\t"
        "pop    %rax                  \n\t"
        "ret                           \n\t"
    );
}


#endif // ARCH_X64

#if defined(ARCH_X86)

/* * ----------------------------------------------------------------------------
 * x86 Implementation: ___chkstk_ms
 * * Behaves like the x64 version. Probes only. Does NOT adjust ESP.
 * * Input:  EAX = Frame size
 * Output: None (Preserves EAX, ECX)
 * ----------------------------------------------------------------------------
 */
__attribute__((used))
NAKED void ___chkstk_ms(void) {
    __asm__ volatile (
        "push   %eax                  \n\t"
        "push   %ecx                  \n\t"
        "mov    %fs:(0x08), %ecx     \n\t" // ecx = TIB->StackLimit
        "neg    %eax                  \n\t" // eax = -frame_size
        "add    %esp, %eax           \n\t" // eax = target frame low address
        "jb     1f                     \n\t" // Overflow check
        "xor    %eax, %eax           \n\t" // Clamp to 0 on overflow
        "0:                            \n\t"
        "sub    $0x1000, %ecx         \n\t" // Move down one page
        "test   %eax, (%ecx)         \n\t" // Probe
        "1:                            \n\t"
        "cmp    %eax, %ecx           \n\t"
        "ja     0b                     \n\t"
        "pop    %ecx                  \n\t"
        "pop    %eax                  \n\t"
        "ret                           \n\t"
    );
}

/* * ----------------------------------------------------------------------------
 * x86 Implementation: __chkstk
 * * Standard MSVC behavior. Probes AND allocates the stack frame.
 * * Input:  EAX = Frame size
 * Output: ESP is adjusted by EAX. EAX is clobbered.
 * Note:   This routine manipulates the return address to return correctly
 * despite modifying ESP.
 * ----------------------------------------------------------------------------
 */
 __attribute__((used))

NAKED void __chkstk(void) {
    __asm__ volatile (
        "push   %ecx                  \n\t" // Preserve ECX
        "mov    %fs:(0x08), %ecx     \n\t" // ecx = TIB->StackLimit
        "neg    %eax                  \n\t" // eax = -frame_size
        "lea    8(%esp,%eax), %eax  \n\t" // eax = target low addr (Adjust for RetAddr + Saved ECX)
        "cmp    %esp, %eax           \n\t" // Overflow check
        "jb     1f                     \n\t"
        "xor    %eax, %eax           \n\t"
        "0:                            \n\t"
        "sub    $0x1000, %ecx         \n\t"
        "test   %eax, (%ecx)         \n\t" // Probe
        "1:                            \n\t"
        "cmp    %eax, %ecx           \n\t"
        "ja     0b                     \n\t"
        "pop    %ecx                  \n\t" // Restore ECX
        "xchg   %eax, %esp           \n\t" // Update ESP to new stack bottom, EAX = Old Stack Top
        "jmp    *(%eax)               \n\t" // Jump to return address (stored at old stack top)
    );
}

#endif // ARCH_X86

int __wcsicmp(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ca = (*a >= L'A' && *a <= L'Z') ? (*a + 32) : *a;
        wchar_t cb = (*b >= L'A' && *b <= L'Z') ? (*b + 32) : *b;
        if (ca != cb) return (int)(ca - cb);
        a++; b++;
    }
    return (int)(*a - *b);
}

bool __starts_with(const char* string, const char* substring) {
    return __strncmp(string, substring, __strlen(substring)) == 0;
}

static int _fmt_uint(unsigned long long val, int base, int upper, char* buf) {
    static const char* lo = lcg_encrypt("0123456789abcdef");
    static const char* up = lcg_encrypt("0123456789ABCDEF");
    const char* digs = upper ? up : lo;
    char tmp[22];
    int n = 0;
    if (val == 0) { buf[0] = '0'; return 1; }
    while (val) { tmp[n++] = digs[val % base]; val /= base; }
    for (int i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    return n;
}

/* Core: write up to (limit-1) chars + null terminator into buf.
 * Pass limit=SIZE_MAX for unbounded (sprintf semantics).
 * Returns number of chars that would be written (excl. null), a la snprintf. */
int __vsnprintf(char* buf, size_t limit, const char* fmt, va_list args) {
    int measure_only = (buf == NULL || limit == 0);
    /* We write to buf up to limit-1 chars, always null-terminate if limit>0.
     * 'out' tracks logical position (may exceed limit for return value). */
    size_t pos = 0;
    
#define EMIT(c) do { \
    if (!measure_only && pos < limit - 1) buf[pos] = (c); \
    pos++; \
} while(0)

    const char* p = fmt;
    while (*p) {
        if (*p != '%') { EMIT(*p++); continue; }
        p++;
        if (*p == '\0') break;

        /* --- Flags --- */
        int fl_minus = 0, fl_zero = 0, fl_plus = 0, fl_space = 0;
        int parsing_flags = 1;
        while (parsing_flags) {
            switch (*p) {
                case '-': fl_minus = 1; p++; break;
                case '0': fl_zero  = 1; p++; break;
                case '+': fl_plus  = 1; p++; break;
                case ' ': fl_space = 1; p++; break;
                default:  parsing_flags = 0; break;
            }
        }
        if (fl_minus) fl_zero = 0; /* POSIX: '-' overrides '0' */

        /* --- Width --- */
        int width = 0;
        if (*p == '*') { width = va_arg(args, int); p++; }
        else while (*p >= '0' && *p <= '9') width = width * 10 + (*p++ - '0');

        /* --- Precision --- */
        int prec = -1;
        if (*p == '.') {
            p++; prec = 0;
            if (*p == '*') { prec = va_arg(args, int); p++; }
            else while (*p >= '0' && *p <= '9') prec = prec * 10 + (*p++ - '0');
        }

        /* --- Length modifier --- */
        int llen = 0; /* 1=l, 2=ll */
        int zmod = 0;
        while (*p == 'l') { llen++; p++; }
        if (*p == 'z') { zmod = 1; p++; }
        if (*p == 'h') { p++; } /* ignore h/hh for now */

        char spec = *p++;
        if (!spec) break;

        char  nbuf[24];
        int   nlen  = 0;
        char  sign  = 0;
        int   pad   = 0;
        char  pchar = ' ';

        switch (spec) {
        case '%':
            EMIT('%');
            break;

        case 'c': {
            char c = (char)va_arg(args, int);
            pad = (width > 1) ? width - 1 : 0;
            if (!fl_minus) for (int i = 0; i < pad; i++) EMIT(' ');
            EMIT(c);
            if ( fl_minus) for (int i = 0; i < pad; i++) EMIT(' ');
            break;
        }

        case 's': {
            const char* s = va_arg(args, const char*);
            if (!s) s = "(null)";
            int slen = 0;
            while (s[slen]) slen++;
            if (prec >= 0 && prec < slen) slen = prec;
            pad = (width > slen) ? width - slen : 0;
            if (!fl_minus) for (int i = 0; i < pad; i++) EMIT(' ');
            for (int i = 0; i < slen; i++) EMIT(s[i]);
            if ( fl_minus) for (int i = 0; i < pad; i++) EMIT(' ');
            break;
        }

        case 'd': case 'i': {
            long long val;
            if      (zmod)    val = (long long)(ssize_t)va_arg(args, size_t);
            else if (llen>=2) val = va_arg(args, long long);
            else if (llen==1) val = (long long)va_arg(args, long);
            else              val = (long long)va_arg(args, int);

            if      (val < 0)    { sign = '-'; val = -val; }
            else if (fl_plus)      sign = '+';
            else if (fl_space)     sign = ' ';

            nlen  = _fmt_uint((unsigned long long)val, 10, 0, nbuf);
            /* Apply precision (min digit count) */
            if (prec > nlen) {
                int extra = prec - nlen;
                for (int i = nlen-1; i >= 0; i--) nbuf[i+extra] = nbuf[i];
                for (int i = 0; i < extra; i++) nbuf[i] = '0';
                nlen = prec;
            }
            int total = nlen + (sign ? 1 : 0);
            pad   = (width > total) ? width - total : 0;
            pchar = (fl_zero && !fl_minus && prec < 0) ? '0' : ' ';

            if (!fl_minus && pchar == ' ') for (int i=0;i<pad;i++) EMIT(' ');
            if (sign) EMIT(sign);
            if (!fl_minus && pchar == '0') for (int i=0;i<pad;i++) EMIT('0');
            for (int i=0;i<nlen;i++) EMIT(nbuf[i]);
            if ( fl_minus)              for (int i=0;i<pad;i++) EMIT(' ');
            break;
        }

        case 'u': {
            unsigned long long val;
            if      (zmod)    val = (unsigned long long)va_arg(args, size_t);
            else if (llen>=2) val = va_arg(args, unsigned long long);
            else if (llen==1) val = (unsigned long long)va_arg(args, unsigned long);
            else              val = (unsigned long long)va_arg(args, unsigned int);

            nlen  = _fmt_uint(val, 10, 0, nbuf);
            if (prec > nlen) {
                int extra = prec - nlen;
                for (int i = nlen-1; i >= 0; i--) nbuf[i+extra] = nbuf[i];
                for (int i = 0; i < extra; i++) nbuf[i] = '0';
                nlen = prec;
            }
            pad   = (width > nlen) ? width - nlen : 0;
            pchar = (fl_zero && !fl_minus && prec < 0) ? '0' : ' ';
            if (!fl_minus) for (int i=0;i<pad;i++) EMIT(pchar);
            for (int i=0;i<nlen;i++) EMIT(nbuf[i]);
            if ( fl_minus) for (int i=0;i<pad;i++) EMIT(' ');
            break;
        }

        case 'x': case 'X': {
            unsigned long long val;
            if      (zmod)    val = (unsigned long long)va_arg(args, size_t);
            else if (llen>=2) val = va_arg(args, unsigned long long);
            else if (llen==1) val = (unsigned long long)va_arg(args, unsigned long);
            else              val = (unsigned long long)va_arg(args, unsigned int);

            nlen  = _fmt_uint(val, 16, spec=='X', nbuf);
            if (prec > nlen) {
                int extra = prec - nlen;
                for (int i = nlen-1; i >= 0; i--) nbuf[i+extra] = nbuf[i];
                for (int i = 0; i < extra; i++) nbuf[i] = '0';
                nlen = prec;
            }
            pad   = (width > nlen) ? width - nlen : 0;
            pchar = (fl_zero && !fl_minus && prec < 0) ? '0' : ' ';
            if (!fl_minus) for (int i=0;i<pad;i++) EMIT(pchar);
            for (int i=0;i<nlen;i++) EMIT(nbuf[i]);
            if ( fl_minus) for (int i=0;i<pad;i++) EMIT(' ');
            break;
        }

        case 'o': {
            unsigned long long val;
            if      (llen>=2) val = va_arg(args, unsigned long long);
            else if (llen==1) val = (unsigned long long)va_arg(args, unsigned long);
            else              val = (unsigned long long)va_arg(args, unsigned int);
            nlen  = _fmt_uint(val, 8, 0, nbuf);
            pad   = (width > nlen) ? width - nlen : 0;
            pchar = (fl_zero && !fl_minus) ? '0' : ' ';
            if (!fl_minus) for (int i=0;i<pad;i++) EMIT(pchar);
            for (int i=0;i<nlen;i++) EMIT(nbuf[i]);
            if ( fl_minus) for (int i=0;i<pad;i++) EMIT(' ');
            break;
        }

        case 'p': {
            void* val = va_arg(args, void*);
            nlen = _fmt_uint((unsigned long long)(uintptr_t)val, 16, 0, nbuf);
            int ptr_digits = (int)(sizeof(void*) * 2);
            EMIT('0'); EMIT('x');
            for (int i = nlen; i < ptr_digits; i++) EMIT('0');
            for (int i = 0; i < nlen; i++) EMIT(nbuf[i]);
            break;
        }

        default:
            EMIT('%'); EMIT(spec);
            break;
        }
    }

    if (limit > 0) buf[(pos < limit) ? pos : limit - 1] = '\0';
    return (int)pos;

#undef EMIT
}

int __vsprintf(char* buf, const char* fmt, va_list args) {
    /* Unbounded. caller guarantees buffer is large enough (sprintf semantics lol) */
    return __vsnprintf(buf, (size_t)-1, fmt, args);
}

int __sprintf(char* buf, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int n = __vsprintf(buf, fmt, args);
    va_end(args);
    return n;
}

int __snprintf(char* buf, size_t sz, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int n = __vsnprintf(buf, sz, fmt, args);
    va_end(args);
    return n;
}

/* WARNING THIS IS BLOCKING! */
void enterLock(volatile long* lock) {
    while (_InterlockedCompareExchange(lock, 1, 0) != 0) {
        // Busy wait with yield to reduce CPU usage
        _mm_pause();  // Yield to other threads
    }
}

void leaveLock(volatile long* lock) {
    _InterlockedExchange(lock, 0);
}

#include <atomic>

void enterLock(std::atomic_flag target) {
    while (target.test_and_set(std::memory_order_acquire)); // spin
}

void leaveLock(std::atomic_flag target) {
    target.clear(std::memory_order_release);
}

/* ============================================================================
 * Bounded string copy helpers
 * copy loops across the codebase.
 * ============================================================================ */

void safeWcsCopyBounded(wchar_t* dst, const wchar_t* src, size_t max_len) {
    size_t i = 0;
    while (i < max_len - 1 && src[i] != L'\0') { dst[i] = src[i]; ++i; }
    dst[i] = L'\0';
}

void safeStrCopyBounded(char* dst, const char* src, size_t max_len) {
    size_t i = 0;
    while (i < max_len - 1 && src[i] != '\0') { dst[i] = src[i]; ++i; }
    dst[i] = '\0';
}

void safeBoundedCopy(char* dst, const uint8_t* src, uint8_t src_len, size_t max_len) {
    if (max_len == 0) return;
    size_t copy_len = src_len;
    if (copy_len >= max_len) copy_len = max_len - 1;
    for (size_t i = 0; i < copy_len; i++) dst[i] = (char)src[i];
    dst[copy_len] = '\0';
}

void safeWcsCopyN(wchar_t* dst, const wchar_t* src, uint16_t n) {
    uint16_t i = 0;
    while (i < n && src[i] != L'\0') { dst[i] = src[i]; ++i; }
    dst[i] = L'\0';
}

// PKCS#7 Padding
// Adds padding to buf up to padded_len. buf must be large enough.
// Each padding byte is the length of the padding.
void pkcs7Pad(uint8_t* buf, size_t data_len, size_t padded_len) {
    if (padded_len <= data_len) return;
    uint8_t pad_val = static_cast<uint8_t>(padded_len - data_len);
    for (size_t i = data_len; i < padded_len; i++) {
        buf[i] = pad_val;
    }
}

// PKCS#7 Unpadding
// Returns the actual data length after removing padding.
// Returns (size_t)-1 if padding is invalid or absent.
size_t pkcs7Unpad(const uint8_t* buf, size_t padded_len) {
    if (padded_len == 0) return (size_t)-1;
    uint8_t pad_val = buf[padded_len - 1];
    // We pad to multiple of 16, so pad_val can be 1-16.
    if (pad_val == 0 || pad_val > 16 || pad_val > padded_len) return (size_t)-1;
    
    // Verify padding
    for (size_t i = padded_len - pad_val; i < padded_len; i++) {
        if (buf[i] != pad_val) return (size_t)-1;
    }
    
    return padded_len - pad_val;
}
