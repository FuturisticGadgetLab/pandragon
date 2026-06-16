#pragma once

#include <stdint.h>
#include <stddef.h>
#include "../../include/utils.h"
#include <immintrin.h>

#ifndef PRODUCTION
    #include <stdio.h>
    #include <assert.h>
    #include <wchar.h>
#endif


#ifdef __cplusplus
#ifndef BUILD_TIME_RANDOM_SEED
    #error("Build-time seed not specified. Cannot proceed.")
#endif

// ---------------------------------------------------------------------------
// wipe_on_exit<T>
// RAII zeroing wrapper. ready_flag is optional - when set, it is reset to
// false on destruction so the buffer is re-decrypted on next access.
// ---------------------------------------------------------------------------
template<typename T>
struct wipe_on_exit {
    T*     buf;
    size_t n;
    bool*  ready_flag;

    wipe_on_exit(T* p, size_t len, bool* flag = nullptr) noexcept
        : buf(p), n(len), ready_flag(flag) {}

    // Move constructor: transfer ownership so NRVO fallback doesn't double-wipe
    wipe_on_exit(wipe_on_exit&& o) noexcept
        : buf(o.buf), n(o.n), ready_flag(o.ready_flag) {
        o.buf        = nullptr;
        o.n          = 0;
        o.ready_flag = nullptr;
    }

    ~wipe_on_exit() {
        if (buf && n) {
            volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(buf);
            size_t bytes = n * sizeof(T);
            while (bytes--) *p++ = 0;
            asm volatile("" ::: "memory");
        }
        if (ready_flag) *ready_flag = false;   // reset so next call re-decrypts
    }

    operator T*()  noexcept { return buf; }
    T* get() const noexcept { return buf; }

    wipe_on_exit(const wipe_on_exit&)            = delete;
    wipe_on_exit& operator=(const wipe_on_exit&) = delete;
};

// ---------------------------------------------------------------------------
// lcg LCG constants - PER-BUILD DERIVED FROM BUILD_TIME_RANDOM_SEED
// Neutralizes static signature detection of Numerical Recipes/glibc constants.
// Both compile-time (ct_prng) and runtime (_lcg_resolve_*) use same derivation.
// ---------------------------------------------------------------------------
constexpr uint64_t MCLG_LCG_MUL = 
    (BUILD_TIME_RANDOM_SEED * 0x5851F42D4C957F2DULL) ^ 0x4C957F2D5851F42DULL;
constexpr uint64_t MCLG_LCG_ADD = 
    (BUILD_TIME_RANDOM_SEED * 0x14057B7EF767814FULL) ^ 0xF767814F14057B7EULL;

// ---------------------------------------------------------------------------
// ct_prng - compile-time LCG stream cipher
// ---------------------------------------------------------------------------
namespace ct_prng {
    constexpr uint64_t LCG_MULTIPLIER = MCLG_LCG_MUL;
    constexpr uint64_t LCG_INCREMENT  = MCLG_LCG_ADD;

    constexpr uint64_t next_state(uint64_t s) {
        return s * LCG_MULTIPLIER + LCG_INCREMENT;
    }

    template<typename T>
    constexpr T get_stream_value_at_index(uint64_t initial, uint32_t idx) {
        uint64_t state = initial;
        uint32_t blocks = (idx * sizeof(T)) / 8;
        for (uint32_t i = 0; i < blocks + 1; ++i)
            state = next_state(state);
        uint32_t off = (idx * sizeof(T)) % 8;
        if constexpr (sizeof(T) == 1)
            return static_cast<T>((state >> (off * 8)) & 0xFF);
        else
            return static_cast<T>((state >> (off * 8)) & 0xFFFF);
    }
}

// ---------------------------------------------------------------------------
// Index sequence (no STL)
// ---------------------------------------------------------------------------
template<size_t... Is> struct index_sequence {};
template<size_t N, size_t... Is>
struct make_index_sequence_impl : make_index_sequence_impl<N-1, N-1, Is...> {};
template<size_t... Is>
struct make_index_sequence_impl<0, Is...> : index_sequence<Is...> {};
template<size_t N> using make_index_sequence = make_index_sequence_impl<N>;

// ---------------------------------------------------------------------------
// obfuscated_data<N, T>
// XOR-obfuscated blob. Constructed entirely at compile time.
// Contains ONLY ciphertext - plaintext never materialises in .rodata.
// ---------------------------------------------------------------------------
template<size_t N, typename T>
struct obfuscated_data {
    T data[N];

    template<size_t... Is>
    constexpr obfuscated_data(const T (&src)[N], uint64_t seed, index_sequence<Is...>)
        : data{ static_cast<T>(src[Is] ^ ct_prng::get_stream_value_at_index<T>(seed, Is))... } {}

    constexpr obfuscated_data(const T (&src)[N], uint64_t seed)
        : obfuscated_data(src, seed, make_index_sequence<N>{}) {}
};

// ---------------------------------------------------------------------------
// Shared decrypt function; implemented once in bastia.cpp.
// Replicates ct_prng::get_stream_value_at_index at runtime.
// ---------------------------------------------------------------------------
void _lcg_resolve_str(const char* blob, size_t n, uint64_t seed, char* out);
void _lcg_resolve_wstr(const wchar_t* blob, size_t n, uint64_t seed, wchar_t* out);

// ---------------------------------------------------------------------------
// NTTP string wrappers - StrParam / WStrParam          (C++20 structural types)
//
// Baking the literal into a TYPE means it has no .rodata object identity.
// The compiler treats it as a compile-time constant with no address to emit.
// hash() is FNV-1a over the member array - never over an external pointer.
// ---------------------------------------------------------------------------
template<size_t N>
struct StrParam {
    char v[N]{};

    consteval StrParam(const char (&s)[N]) {
        for (size_t i = 0; i < N; i++) v[i] = s[i];
    }
    consteval size_t size() const { return N; }
    consteval uint64_t hash() const {
        uint64_t h = 0xcbf29ce484222325ULL;
        for (size_t i = 0; i < N; i++)
            h = (h ^ static_cast<uint64_t>(static_cast<unsigned char>(v[i]))) * 0x100000001b3ULL;
        return h;
    }
};

template<size_t N>
struct WStrParam {
    wchar_t v[N]{};

    consteval WStrParam(const wchar_t (&s)[N]) {
        for (size_t i = 0; i < N; i++) v[i] = s[i];
    }
    consteval size_t size() const { return N; }
    consteval uint64_t hash() const {
        uint64_t h = 0xcbf29ce484222325ULL;
        for (size_t i = 0; i < N; i++) {
            h = (h ^ static_cast<uint64_t>(v[i] & 0xFF))        * 0x100000001b3ULL;
            h = (h ^ static_cast<uint64_t>((v[i] >> 8) & 0xFF)) * 0x100000001b3ULL;
        }
        return h;
    }
};

// ---------------------------------------------------------------------------
// Compile-time resolution (CE)
// ---------------------------------------------------------------------------
template<StrParam S>
struct ConstexprStr {
    static constexpr size_t N = S.size();
    static constexpr uint64_t seed = BUILD_TIME_RANDOM_SEED ^ S.hash();
    char v[N]{};

    consteval ConstexprStr() {
        for (size_t i = 0; i < N; i++) {
            v[i] = static_cast<char>(S.v[i] ^ ct_prng::get_stream_value_at_index<char>(seed, i));
        }
    }
};

// ---------------------------------------------------------------------------
// Static initialization variant - for use in array initializers
// Creates per-string static storage that can be used in static arrays
// ---------------------------------------------------------------------------
template<StrParam S>
struct _StaticStr {
    static constexpr size_t N = S.size();
    static constexpr uint64_t seed = BUILD_TIME_RANDOM_SEED ^ S.hash();
    static constexpr obfuscated_data<N, char> blob{ S.v, seed };

    static const char* get() noexcept {
        static char buf[N + 1] = {0};
        static bool ready = false;
        if (!ready) {
            volatile uint64_t runtime_seed = seed;
            _lcg_resolve_str(blob.data, N, runtime_seed, buf);
            ready = true;
        }
        return buf;
    }
};

// ---------------------------------------------------------------------------
// ObfuscatedStr<S> / ObfuscatedWStr<S>
//
// One template instantiation per unique string literal.
// blob is static constexpr - it lives in .rodata as XOR'd bytes only.
// buf lives in .bss (zero-initialised by loader, no CRT needed).
//
// get()        - decrypt once, reuse. No wipe.
// get_secure() - decrypt, return wipe_on_exit. Buffer + ready reset on dtor.
// ---------------------------------------------------------------------------
template<StrParam S>
struct ObfuscatedStr {
    static constexpr size_t   N    = S.size();
    static constexpr uint64_t seed = BUILD_TIME_RANDOM_SEED ^ S.hash();
    static constexpr obfuscated_data<N, char> blob{ S.v, seed };

    static char* get() noexcept {
        static char buf[N];
        static bool ready = false;
        if (!ready) {
            volatile uint64_t runtime_seed = seed;
            _lcg_resolve_str(blob.data, N, runtime_seed, buf);
            ready = true;
        }
        return buf;
    }

    static wipe_on_exit<char> get_secure() noexcept {
        static char buf[N];
        static bool ready = false;
        if (!ready) {
            volatile uint64_t runtime_seed = seed;
            _lcg_resolve_str(blob.data, N, runtime_seed, buf);
            ready = true;
        }
        return wipe_on_exit<char>{ buf, N, &ready };
    }
};

template<WStrParam S>
struct ObfuscatedWStr {
    static constexpr size_t   N    = S.size();
    static constexpr uint64_t seed = BUILD_TIME_RANDOM_SEED ^ S.hash();
    static constexpr obfuscated_data<N, wchar_t> blob{ S.v, seed };

    static wchar_t* get() noexcept {
        static wchar_t buf[N];
        static bool    ready = false;
        if (!ready) {
            volatile uint64_t runtime_seed = seed;
            _lcg_resolve_wstr(blob.data, N, runtime_seed, buf);
            ready = true;
        }
        return buf;
    }

    static wipe_on_exit<wchar_t> get_secure() noexcept {
        static wchar_t buf[N];
        static bool    ready = false;
        if (!ready) {
            volatile uint64_t runtime_seed = seed;
            _lcg_resolve_wstr(blob.data, N, runtime_seed, buf);
            ready = true;
        }
        return wipe_on_exit<wchar_t>{ buf, N, &ready };
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
#define lcg_encrypt(s)          (ObfuscatedStr<StrParam{ s }>::get())
#define lcg_encryptw(s)         (ObfuscatedWStr<WStrParam{ s }>::get())
#define lcg_encrypt_secure(s)   (ObfuscatedStr<StrParam{ s }>::get_secure())
#define lcg_encryptw_secure(s)  (ObfuscatedWStr<WStrParam{ s }>::get_secure())
#define lcg_encrypt_ce(s)       (ConstexprStr<StrParam{ s }>().v) // needed for compile-time contexts (e.g. static_assert) where get() can't be called, and arrays
#define lcg_encrypt_array(s)    (_StaticStr<StrParam{ s }>::get()) // for use in static array initializers


 
#endif


// Force inline for speed critical sections
#if defined(__GNUC__)
    #  define ALWAYS_INLINE __attribute__((always_inline)) inline
#elif defined(_MSC_VER)
    #  define ALWAYS_INLINE __forceinline
#else
    #  define ALWAYS_INLINE inline
#endif

// Portable unaligned memory access
#define LOAD32_LE(SRC) ({ \
    uint32_t _tmp; \
    __memcpy(&_tmp, (SRC), sizeof(_tmp)); \
    _tmp; })

#define STORE32_LE(DST, VAL) ({ \
    uint32_t _val = (VAL); \
    __memcpy((DST), &_val, sizeof(_val)); })

#define ROTL32(a,b) (((a) << (b)) | ((a) >> (32 - (b))))

#define QR(a,b,c,d) \
    a += b; d ^= a; d = ROTL32(d,16); \
    c += d; b ^= c; b = ROTL32(b,12); \
    a += b; d ^= a; d = ROTL32(d,8); \
    c += d; b ^= c; b = ROTL32(b,7);


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Securely wipe sensitive data from memory
 * 
 * Uses volatile pointer writes to prevent compiler optimization.
 * Call this on all sensitive buffers (keys, nonces, intermediate state)
 * before they go out of scope.
 * 
 * @param ptr Pointer to buffer to wipe
 * @param size Size of buffer in bytes
 */
void crypto_wipe(void* ptr, size_t size);

/* Security Warnings --------------------------------------------------------*/

/**
 * @defgroup Warnings Critical Security Considerations
 * @{
 */

/**
 * @warning XChaCha20 Security:
 * - Never reuse (key, nonce) pairs - catastrophic security failure
 * - Monitor counter overflow - maximum 2^64 blocks per (key,nonce)
 * - 24-byte nonce recommended for random generation
 * 
 * @warning AES-CTR Security:
 * - Never reuse (key, nonce, counter) combinations
 * - Counter overflow breaks security for 32-bit counters
 * 
 * @warning AES-ECB Insecurity:
 * - ECB reveals plaintext patterns - use only for single-block encryption
 * - Never use ECB for bulk data or structured plaintexts
 * 
 * @warning Key Management:
 * - Store keys securely (HSM, TPM, or encrypted with memory protection)
 * - Rotate keys per organizational policy (NIST SP 800-57)
 */
/** @} */

/* XChaCha20 Interface ------------------------------------------------------*/

/**
 * @defgroup XChaCha20 XChaCha20 Stream Cipher
 * @{
 */

typedef struct {
    uint32_t state[16];      ///< ChaCha20 internal state
    uint8_t keystream[64];   ///< Current keystream block
    size_t keystream_used;   ///< Bytes consumed in current block
    uint64_t counter;        ///< 64-bit block counter
} xchacha20_ctx;

/**
 * @brief Initialize XChaCha20 context
 * @warning Nonce must NEVER be reused with the same key
 * @warning Counter overflow (beyond 2^64-1) breaks security
 */
void xchacha20_setup(xchacha20_ctx *ctx, const uint8_t *key,
                     const uint8_t *nonce, uint64_t counter);

/**
 * @brief Process data with XChaCha20
 * @warning Input/output buffers must not overlap unless identical
 */
void xchacha20_crypt(xchacha20_ctx *ctx, uint8_t *dst,
                     const uint8_t *src, size_t len);

/**
* @brief XChaCha20 self-tests
* @return Returns 0 on success. Non-zero otherwise.
*/

bool xchacha20_self_test(void);

/** @} */

/* AES Implementations ------------------------------------------------------*/
/**
 * @brief AES-128 context (AES-NI accelerated)
 */
typedef struct {
    __m128i rk[11]; ///< Round keys in SSE registers
} ni_aes128_ctx;
/* AES-NI Functions ---------------------------------------------------------*/

/**
 * @brief Expand AES-128 key (AES-NI)
 * @param key 16-byte encryption key
 * @return Initialized NI context
 */
ni_aes128_ctx ni_aes128_key_expansion(const uint8_t *key);


/**
 * @brief AES-128-ECB encryption (AES-NI)
 * @param ctx Initialized NI context
 * @param out Output buffer
 * @param in Input buffer
 * @param len Data length (multiple of 16)
 * @warning Use only for legacy compatibility - prefer CTR/XChaCha20
 */
void ni_aes128_ecb_encrypt(ni_aes128_ctx *ctx, uint8_t *out,
                           const uint8_t *in, size_t len);

/**
 * @brief AES-128-CTR encryption (AES-NI)
 * @param ctx Initialized context
 * @param out Output buffer
 * @param in Input buffer
 * @param len Data length
 * @param nonce 12-byte nonce
 * @param counter 64-bit initial counter
 * @warning Counter must never repeat for same (key, nonce)
 * @warning 32-bit counter limits to 256GB per (key,nonce). Create a new context every 255GB for assured security.
 */
void ni_aes128_ctr_encrypt(ni_aes128_ctx *ctx, uint8_t *out,
                           const uint8_t *in, size_t len,
                           const uint8_t nonce[12], uint64_t counter);

/** @} */


/**
 * @defgroup AES_Decryption AES Decryption Functions
 * @{
 */

/**
 * @brief AES-128 decryption context (AES-NI)
 * @note Required for AES-NI decryption operations
 */
typedef struct {
    __m128i rk[11]; ///< Inverse round keys for decryption
} ni_aes128_dec_ctx;

/**
 * @brief Generate AES-NI decryption key schedule
 * @param key 16-byte encryption key
 * @return Initialized decryption context
 */
ni_aes128_dec_ctx ni_aes128_key_expansion_decrypt(const uint8_t *key);

/**
 * @brief AES-128-ECB decryption (AES-NI)
 * @warning ECB mode should not be used for new designs
 */
void ni_aes128_ecb_decrypt(ni_aes128_dec_ctx *ctx, uint8_t *out,
                           const uint8_t *in, size_t len);


/**
 * @brief Self explanatory, no? Tests all ECB implementations.
 */

bool all_aes_128_tests(void);

bool test_ni_aes128_key_expansion();
bool test_ni_aes128_ecb();
bool test_ni_aes128_ctr();

/** @} */


/**
 * @warning AES-NI:
 * Make sure stack is aligned to 16 bytes:
 *      asm volatile (
 *          "and $-16, %%rsp\n"   // Align stack to 16 bytes
 *          : : : "rsp"
 *        );
 * This is crucial for hardware-accelerated intructions (SSE & AVX).
 * 
 * @warning Key Storage:
 * - Store encryption and decryption keys equally securely
 * - Compromise of decryption key equals compromise of encryption key
 */

/* Usage Examples ---------------------------------------------------------*/

/**
 * @example AES-128 ECB Decryption:
 * uint8_t cipher[16], plain[16];
 * aes128_ctx ctx;
 * aes128_key_expansion(&ctx, key);
 * aes128_ecb_decrypt(&ctx, plain, cipher, 16);
 * 
 * @example AES-NI Decryption:
 * ni_aes128_dec_ctx ni_dec = ni_aes128_key_expansion_decrypt(key);
 * ni_aes128_ecb_decrypt(&ni_dec, plain, cipher, 16);
 */


// Chacha20
// --------

// Specialised hash.
// Used to hash X25519 shared secrets.
void crypto_chacha20_h(uint8_t       out[32],
                       const uint8_t key[32],
                       const uint8_t in [16]);

// Unauthenticated stream cipher.
// Don't forget to add authentication.
uint64_t crypto_chacha20_djb(uint8_t       *cipher_text,
                             const uint8_t *plain_text,
                             size_t         text_size,
                             const uint8_t  key[32],
                             const uint8_t  nonce[8],
                             uint64_t       ctr);
uint32_t crypto_chacha20_ietf(uint8_t       *cipher_text,
                              const uint8_t *plain_text,
                              size_t         text_size,
                              const uint8_t  key[32],
                              const uint8_t  nonce[12],
                              uint32_t       ctr);
uint64_t crypto_chacha20_x(uint8_t       *cipher_text,
                           const uint8_t *plain_text,
                           size_t         text_size,
                           const uint8_t  key[32],
                           const uint8_t  nonce[24],
                           uint64_t       ctr);


// Poly 1305
// ---------

// This is a *one time* authenticator.
// Disclosing the mac reveals the key.

int xchacha20poly1305_self_test_vector(void);
int xchacha20poly1305_self_test_vector2(void);
// Incremental interface
typedef struct {
	// Do not rely on the size or contents of this type,
	// for they may change without notice.
	uint8_t  c[16];  // chunk of the message
	size_t   c_idx;  // How many bytes are there in the chunk.
	uint32_t r  [4]; // constant multiplier (from the secret key)
	uint32_t pad[4]; // random number added at the end (from the secret key)
	uint32_t h  [5]; // accumulated hash
} crypto_poly1305_ctx;

/*
 * Verify + decrypt.
 *
 * c        : ciphertext + tag (clen bytes total, clen >= 16).
 * mlen_out : set to clen - 16 on success.
 *
 * Returns  0 on success.
 *         -1 if clen < 16.
 *         -2 on authentication failure (tag mismatch). m is NOT written.
 */
int xchacha20poly1305_decrypt(
    uint8_t       *m,
    size_t        *mlen_out,
    const uint8_t *c,
    size_t         clen,
    const uint8_t *ad,
    size_t         adlen,
    const uint8_t  nonce[24],
    const uint8_t  key[32]);
/*
 * Encrypt + authenticate.
 *
 * c        : output buffer, must be at least mlen + 16 bytes.
 * clen_out : set to mlen + 16 on success.
 * Layout   : c[0..mlen-1] = ciphertext, c[mlen..mlen+15] = tag.
 *
 * Returns 0 on success.
 */
int xchacha20poly1305_encrypt(
    uint8_t       *c,
    size_t        *clen_out,
    const uint8_t *m,
    size_t         mlen,
    const uint8_t *ad,
    size_t         adlen,
    const uint8_t  nonce[24],
    const uint8_t  key[32]);

#ifdef __cplusplus
}
#endif
