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

const wchar_t* __wcschr(const wchar_t* str, wchar_t ch) {
    while (*str) {
        if (*str == ch) return str;
        str++;
    }
    return NULL;
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
        uint32_t r = (uint32_t)___rdtsc();
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
        uint32_t r = (uint32_t)___rdtsc();
        dest[i] = url_safe[r % 62];
    }
    dest[len] = '\0';
}

/**
 * Convert unsigned long long to string (simple implementation)
 */
static char* ulltoa(uint32_t val, char* buf, size_t bufsize) {
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
                uint64_t ts = (uint64_t)(uint32_t)(___rdtsc() >> 20);  // Approximate timestamp
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
                uint32_t r = (uint32_t)___rdtsc();
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
        "neg    %rax                  \n\t" // rax = -frame_size
        "add    %rsp, %rax           \n\t" // rax = target = rsp - frame_size
        "mov    %gs:(0x10), %rcx     \n\t" // rcx = TIB->StackLimit
        "jmp    1f                     \n\t" // skip first sub/probe, go to cmp
        "0:                            \n\t"
        "sub    $0x1000, %rcx         \n\t" // rcx -= 4KB
        "test   %eax, (%rcx)         \n\t" // probe
        "1:                            \n\t"
        "cmp    %rax, %rcx           \n\t" // rcx > target?
        "ja     0b                     \n\t" // yes → keep probing
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
        "neg    %rax                  \n\t"
        "add    %rsp, %rax           \n\t"
        "mov    %gs:(0x10), %rcx     \n\t"
        "jmp    1f                     \n\t"
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

/*
 * Stack allocation function (_alloca)
 * Implemented in inline assembly for GCC/Clang (MinGW/LLVM).
 * These functions must be 'naked' because they directly manipulate the stack pointer
 * and the return address outside the normal C frame.
 */

// MinGW headers define _alloca(x) as __builtin_alloca(x) - undef to allow custom impl
#undef _alloca

#if defined(ARCH_X64)

/* * ----------------------------------------------------------------------------
 * x64 Implementation of _alloca
 *
 * Input:  RCX = size (bytes)
 * Output: RAX = pointer to allocated block (16‑byte aligned)
 *
 * Preserves all callee‑saved registers (RBX, RBP, RDI, RSI, R12–R15, XMM6–15).
 * ----------------------------------------------------------------------------
 */
extern "C"
__attribute__((used))
NAKED void* _alloca(size_t size) {
    __asm__ volatile (
        // --- Zero size ---
        "test   %rcx, %rcx             \n\t"
        "jz     .Lzero_x64             \n\t"

        // --- Align size to 16 ---
        "mov    %rcx, %rax             \n\t"
        "add    $15, %rax              \n\t"
        "and    $-16, %rax             \n\t"   // rax = aligned_size

        // --- Save original RSP and compute target pointer ---
        "mov    %rsp, %r9              \n\t"   // r9 = original RSP (return address)
        "mov    %r9, %rdx              \n\t"
        "sub    %rax, %rdx             \n\t"   // rdx = original RSP - aligned_size
        "cmp    %r9, %rdx              \n\t"   // overflow check (unsigned)
        "ja     .Loverflow_x64         \n\t"
        "and    $-16, %rdx             \n\t"   // rdx = target = 16‑byte aligned start of block

        // --- New RSP (target – 8) holds the return address ---
        "lea    -8(%rdx), %r8          \n\t"   // r8 = new_rsp

        // --- Stack limit check ---
        "mov    %gs:0x10, %rax         \n\t"   // rax = TIB->StackLimit
        "cmp    %r8, %rax              \n\t"
        "ja     .Loverflow_x64         \n\t"   // new_rsp below StackLimit?

        // --- Copy return address down to new_rsp ---
        "mov    (%rsp), %rcx           \n\t"   // rcx = original return address
        "mov    %rcx, (%r8)            \n\t"
        "mov    %r8, %rsp              \n\t"   // RSP ← new_rsp (now points to copy)

        // --- Probe each page from StackLimit down to new_rsp ---
        "1:                            \n\t"
        "sub    $0x1000, %rax          \n\t"
        "test   %rax, (%rax)           \n\t"   // touch the page
        "cmp    %r8, %rax              \n\t"
        "ja     1b                     \n\t"

        // --- Return value = target (rdx), then ret uses [rsp] ---
        "mov    %rdx, %rax             \n\t"
        "ret                            \n\t"

        // --- Zero size: return current RSP ---
        ".Lzero_x64:                   \n\t"
        "mov    %rsp, %rax             \n\t"
        "ret                            \n\t"

        // --- Overflow / error – debugging trap ---
        ".Loverflow_x64:               \n\t"
        "int3                           \n\t"
    );
}

#endif // ARCH_X64

#if defined(ARCH_X86)

/* * ----------------------------------------------------------------------------
 * x86 Implementation of _alloca
 *
 * Input:  [ESP+4] = size   (cdecl: caller pushes size)
 * Output: EAX = pointer to allocated block (16‑byte aligned)
 *
 * Preserves all callee‑saved registers (EBX, EBP, ESI, EDI).
 * ----------------------------------------------------------------------------
 */
extern "C"
__attribute__((used))
NAKED void* _alloca(size_t size) {
    __asm__ volatile (
        "push   %ecx                  \n\t"   // save ECX

        // --- Load size (ESP points to saved ECX, then return addr, then size) ---
        "mov    8(%esp), %eax         \n\t"   // eax = size
        "test   %eax, %eax            \n\t"
        "jz     .Lzero_x86            \n\t"

        // --- Align size to 16 ---
        "add    $15, %eax             \n\t"
        "and    $-16, %eax            \n\t"   // aligned_size

        // --- Save original ESP and compute target pointer ---
        "mov    %esp, %edx            \n\t"   // edx = original ESP (with pushed ECX)
        "mov    %edx, %ecx            \n\t"
        "sub    %eax, %ecx            \n\t"   // ecx = original ESP - aligned_size
        "cmp    %edx, %ecx            \n\t"   // overflow check (unsigned)
        "ja     .Loverflow_x86        \n\t"
        "and    $-16, %ecx            \n\t"   // ecx = target = 16‑byte aligned start of block

        // --- New ESP (target – 8) holds saved ECX and return address ---
        "lea    -8(%ecx), %edx        \n\t"   // edx = new_esp

        // --- Stack limit check ---
        "mov    %fs:0x08, %eax        \n\t"   // eax = TIB->StackLimit
        "cmp    %edx, %eax            \n\t"
        "ja     .Loverflow_x86        \n\t"

        // --- Copy saved ECX and return address down to new_esp ---
        "mov    (%esp), %eax          \n\t"   // original saved ECX
        "mov    %eax, (%edx)          \n\t"
        "mov    4(%esp), %eax         \n\t"   // original return address
        "mov    %eax, 4(%edx)         \n\t"

        // --- Set ESP to point to the copied return address ---
        "lea    4(%edx), %esp         \n\t"   // ESP ← new_esp+4

        // --- Reload StackLimit and probe pages down to new_esp ---
        "mov    %fs:0x08, %eax        \n\t"
        "1:                            \n\t"
        "sub    $0x1000, %eax         \n\t"
        "test   %eax, (%eax)          \n\t"
        "cmp    %edx, %eax            \n\t"
        "ja     1b                    \n\t"

        // --- Return value = target, restore ECX and return ---
        "mov    %ecx, %eax            \n\t"   // return target
        "lea    (%edx), %esp          \n\t"   // point ESP to saved ECX copy
        "pop    %ecx                  \n\t"   // restore ECX, ESP now points to ret addr
        "ret                          \n\t"

        // --- Zero size: return current ESP ---
        ".Lzero_x86:                  \n\t"
        "mov    %esp, %eax            \n\t"
        "pop    %ecx                  \n\t"
        "ret                          \n\t"

        // --- Overflow / error – debugging trap ---
        ".Loverflow_x86:              \n\t"
        "int3                         \n\t"
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


static int _fmt_uint(unsigned long long val, int base, int upper, char* buf) {
    static const char* digs_lo = lcg_encrypt("0123456789abcdef");
    static const char* digs_up = lcg_encrypt("0123456789ABCDEF");
    const char* digs = upper ? digs_up : digs_lo;
    char tmp[22];
    int n = 0;
    if (val == 0) { buf[0] = '0'; return 1; }
#ifdef __i386__
    while (val) {
        if (base == 16) {
            tmp[n++] = digs[val & 0xF];
            val >>= 4;
        } else if (base == 8) {
            tmp[n++] = digs[val & 7];
            val >>= 3;
        } else {
            // base == 10: use x86 DIVL (EDX:EAX / r/m32) to avoid __udivdi3/__umoddi3
            uint32_t hi32 = (uint32_t)(val >> 32);
            uint32_t lo32 = (uint32_t)val;
            uint32_t q1 = 0, r1 = 0, q2, r2;
            if (hi32 >= 10) {
                __asm__("divl %4" : "=a"(q1), "=d"(r1) : "d"(0U), "a"(hi32), "rm"(10U));
            } else {
                r1 = hi32;
            }
            __asm__("divl %4" : "=a"(q2), "=d"(r2) : "d"(r1), "a"(lo32), "rm"(10U));
            tmp[n++] = digs[r2];
            val = ((unsigned long long)q1 << 32) | q2;
        }
    }
#else
    while (val) { tmp[n++] = digs[val % base]; val /= base; }
#endif
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


int __snprintf(char* buf, size_t sz, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int n = __vsnprintf(buf, sz, fmt, args);
    va_end(args);
    return n;
}

/* WARNING THIS IS BLOCKING! */
void enterLock(volatile long* lock) {
    long expected = 0;
    while (!__atomic_compare_exchange_n(lock, &expected, 1, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        expected = 0;
        _mm_pause();
    }
}

void leaveLock(volatile long* lock) {
    __atomic_store_n(lock, 0, __ATOMIC_SEQ_CST);
}

#include <atomic>



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
