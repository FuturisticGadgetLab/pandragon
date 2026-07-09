#include "bastia.h"
#include <cstdint>

/*
    Documentation:
    Warning:
    If using lcg_encrypt, seed is __TIME__ and __FILE__, which could,
    in theory, be used to trace back time of compilation by an expert
    reverse engineer well-veresd in cryptography. Though this is
    extremely unlikely, it is no harm to remind the developper using
    this library.
*/

/**
 * Securely wipe sensitive data from memory.
 * Uses volatile pointer to prevent compiler optimization.
 * This ensures sensitive material (keys, nonces, intermediate crypto state)
 * is actually zeroed and not optimized away.
 */
void crypto_wipe(void* ptr, size_t size) {
    if (!ptr || size == 0) return;
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (size--) {
        *p++ = 0;
    }
    // Compiler barrier: prevent the wipe loop from being optimized away
    asm volatile("" ::: "memory");
}

/*
 * xchacha20.h - Optimized XChaCha20 implementation
 *
 * Warning: Cryptography requires careful implementation. 
 *          This code is provided as-is; use in production after thorough review.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end)         FOR_T(size_t, i, start, end)
#define COPY(dst, src, size)       FOR(_i_, 0, size) (dst)[_i_] = (src)[_i_]
#define ZERO(buf, size)            FOR(_i_, 0, size) (buf)[_i_] = 0
#define WIPE_CTX(ctx)              crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)        crypto_wipe(buffer, sizeof(buffer))
#define MAX(a, b)                  ((a) >= (b) ? (a) : (b))

typedef int8_t   i8;
typedef uint8_t  u8;
typedef int16_t  i16;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;


// returns the smallest positive integer y such that
// (x + y) % pow_2  == 0
// Basically, y is the "gap" missing to align x.
// Only works when pow_2 is a power of 2.
static size_t gap(size_t x, size_t pow_2)
{
	return (~x + 1) & (pow_2 - 1);
}

static u32 load32_le(const u8 s[4])
{
	return
		((u32)s[0] <<  0) |
		((u32)s[1] <<  8) |
		((u32)s[2] << 16) |
		((u32)s[3] << 24);
}

[[maybe_unused]] static u64 load64_le(const u8 s[8])
{
	return load32_le(s) | ((u64)load32_le(s+4) << 32);
}

static void store32_le(u8 out[4], u32 in)
{
	out[0] =  in        & 0xff;
	out[1] = (in >>  8) & 0xff;
	out[2] = (in >> 16) & 0xff;
	out[3] = (in >> 24) & 0xff;
}

[[maybe_unused]] static void store64_le(u8 out[8], u64 in)
{
	store32_le(out    , (u32)in );
	store32_le(out + 4, in >> 32);
}

static void load32_le_buf (u32 *dst, const u8 *src, size_t size) {
	FOR(i, 0, size) { dst[i] = load32_le(src + i*4); }
}
static void store32_le_buf(u8 *dst, const u32 *src, size_t size) {
	FOR(i, 0, size) { store32_le(dst + i*4, src[i]); }
}

static u32 rotl32(u32 x, u32 n) { return (x << n) ^ (x >> (32 - n)); }

#define QUARTERROUND(a, b, c, d)	\
	a += b;  d = rotl32(d ^ a, 16); \
	c += d;  b = rotl32(b ^ c, 12); \
	a += b;  d = rotl32(d ^ a,  8); \
	c += d;  b = rotl32(b ^ c,  7)

static void chacha20_rounds(u32 out[16], const u32 in[16])
{
	// The temporary variables make Chacha20 10% faster.
	u32 t0  = in[ 0];  u32 t1  = in[ 1];  u32 t2  = in[ 2];  u32 t3  = in[ 3];
	u32 t4  = in[ 4];  u32 t5  = in[ 5];  u32 t6  = in[ 6];  u32 t7  = in[ 7];
	u32 t8  = in[ 8];  u32 t9  = in[ 9];  u32 t10 = in[10];  u32 t11 = in[11];
	u32 t12 = in[12];  u32 t13 = in[13];  u32 t14 = in[14];  u32 t15 = in[15];

	FOR (i, 0, 10) { // 20 rounds, 2 rounds per loop.
		QUARTERROUND(t0, t4, t8 , t12); // column 0
		QUARTERROUND(t1, t5, t9 , t13); // column 1
		QUARTERROUND(t2, t6, t10, t14); // column 2
		QUARTERROUND(t3, t7, t11, t15); // column 3
		QUARTERROUND(t0, t5, t10, t15); // diagonal 0
		QUARTERROUND(t1, t6, t11, t12); // diagonal 1
		QUARTERROUND(t2, t7, t8 , t13); // diagonal 2
		QUARTERROUND(t3, t4, t9 , t14); // diagonal 3
	}
	out[ 0] = t0;   out[ 1] = t1;   out[ 2] = t2;   out[ 3] = t3;
	out[ 4] = t4;   out[ 5] = t5;   out[ 6] = t6;   out[ 7] = t7;
	out[ 8] = t8;   out[ 9] = t9;   out[10] = t10;  out[11] = t11;
	out[12] = t12;  out[13] = t13;  out[14] = t14;  out[15] = t15;
}

/*
 * Function-local static for chacha20 constant.
 * Uses Meyer's singleton pattern because -nostartfiles bypasses C++ static initialization.
 * File-scope statics with dynamic initializers (lcg_encrypt) would remain NULL.
 */
static const u8* get_chacha20_constant(void) {
    static const u8* chacha20_constant = (const u8*)lcg_encrypt("expand 32-byte k"); // 16 bytes
    return chacha20_constant;
}

void crypto_chacha20_h(u8 out[32], const u8 key[32], const u8 in [16])
{
	u32 block[16];
	load32_le_buf(block     , get_chacha20_constant(), 4);
	load32_le_buf(block +  4, key              , 8);
	load32_le_buf(block + 12, in               , 4);

	chacha20_rounds(block, block);

	// prevent reversal of the rounds by revealing only half of the buffer.
	store32_le_buf(out   , block   , 4); // constant
	store32_le_buf(out+16, block+12, 4); // counter and nonce
	crypto_wipe(block, sizeof(block));
}

u64 crypto_chacha20_djb(u8 *cipher_text, const u8 *plain_text,
                        size_t text_size, const u8 key[32], const u8 nonce[8],
                        u64 ctr)
{
	u32 input[16];
	load32_le_buf(input     , get_chacha20_constant(), 4);
	load32_le_buf(input +  4, key              , 8);
	load32_le_buf(input + 14, nonce            , 2);
	input[12] = (u32) ctr;
	input[13] = (u32)(ctr >> 32);

	// Whole blocks
	u32    pool[16];
	size_t nb_blocks = text_size >> 6;
	FOR (i, 0, nb_blocks) {
		chacha20_rounds(pool, input);
		if (plain_text != NULL) {
			FOR (j, 0, 16) {
				u32 p = pool[j] + input[j];
				store32_le(cipher_text, p ^ load32_le(plain_text));
				cipher_text += 4;
				plain_text  += 4;
			}
		} else {
			FOR (j, 0, 16) {
				u32 p = pool[j] + input[j];
				store32_le(cipher_text, p);
				cipher_text += 4;
			}
		}
		input[12]++;
		if (input[12] == 0) {
			input[13]++;
		}
	}
	text_size &= 63;

	// Last (incomplete) block
	if (text_size > 0) {
		if (plain_text == NULL) {
			plain_text = 0;
		}
		chacha20_rounds(pool, input);
		u8 tmp[64];
		FOR (i, 0, 16) {
			store32_le(tmp + i*4, pool[i] + input[i]);
		}
		FOR (i, 0, text_size) {
			cipher_text[i] = tmp[i] ^ plain_text[i];
		}
		crypto_wipe(tmp, sizeof(tmp));
	}
	ctr = input[12] + ((u64)input[13] << 32) + (text_size > 0);

	crypto_wipe(pool, sizeof(pool));
	crypto_wipe(input, sizeof(input));
	return ctr;
}

u32 crypto_chacha20_ietf(u8 *cipher_text, const u8 *plain_text,
                         size_t text_size,
                         const u8 key[32], const u8 nonce[12], u32 ctr)
{
	u64 big_ctr = ctr + ((u64)load32_le(nonce) << 32);
	return (u32)crypto_chacha20_djb(cipher_text, plain_text, text_size,
	                                key, nonce + 4, big_ctr);
}

u64 crypto_chacha20_x(u8 *cipher_text, const u8 *plain_text,
                      size_t text_size,
                      const u8 key[32], const u8 nonce[24], u64 ctr)
{
	u8 sub_key[32];
	crypto_chacha20_h(sub_key, key, nonce);
	ctr = crypto_chacha20_djb(cipher_text, plain_text, text_size,
	                          sub_key, nonce + 16, ctr);
	crypto_wipe(sub_key, sizeof(sub_key));
	return ctr;
}

/* XChaCha20 context-based API --------------------------------------------*/

void xchacha20_setup(xchacha20_ctx *ctx, const uint8_t *key,
                     const uint8_t *nonce, uint64_t counter)
{
	/* Derive subkey using HChaCha20 */
	u8 sub_key[32];
	crypto_chacha20_h(sub_key, key, nonce);

	/* Initialize state with ChaCha20 constants "expand 32-byte k" */
	ctx->state[0]  = 0x61707865;
	ctx->state[1]  = 0x3320646e;
	ctx->state[2]  = 0x79622d32;
	ctx->state[3]  = 0x6b206574;

	/* Copy subkey into state words 4-11 */
	load32_le_buf(&ctx->state[4],  sub_key,      8);

	/* Set counter (words 12-13) and stream nonce (words 14-15) */
	ctx->state[12] = (u32)(counter & 0xFFFFFFFF);
	ctx->state[13] = (u32)((counter >> 32) & 0xFFFFFFFF);
	load32_le_buf(&ctx->state[14], nonce + 16, 2);

	/* Initialize keystream buffer */
	__memset(ctx->keystream, 0, sizeof(ctx->keystream));
	ctx->keystream_used = 64;  /* Force regeneration on first use */
	ctx->counter = counter;

	crypto_wipe(sub_key, sizeof(sub_key));
}

void xchacha20_crypt(xchacha20_ctx *ctx, uint8_t *dst,
                     const uint8_t *src, size_t len)
{
	size_t i = 0;

	while (i < len) {
		/* Generate new keystream block if needed */
		if (ctx->keystream_used >= 64) {
			/* Generate keystream using crypto_chacha20_djb */
			u8 zero_block[64] = {0};
			crypto_chacha20_djb(ctx->keystream, zero_block, 64,
			                    (const u8*)ctx->state,
			                    (const u8*)&ctx->state[12],
			                    ctx->counter);
			ctx->keystream_used = 0;
			ctx->counter++;
		}

		/* XOR with keystream */
		size_t block_size = 64 - ctx->keystream_used;
		if (block_size > len - i) {
			block_size = len - i;
		}

		FOR(j, 0, block_size) {
			dst[i + j] = src[i + j] ^ ctx->keystream[ctx->keystream_used + j];
		}

		ctx->keystream_used += block_size;
		i += block_size;
	}
}

/////////////////
/// Poly 1305 ///
/////////////////

// h = (h + c) * r
// preconditions:
//   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
//   ctx->r <=   0ffffffc_0ffffffc_0ffffffc_0fffffff
//   end    <= 1
// Postcondition:
//   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
static void poly_blocks(crypto_poly1305_ctx *ctx, const u8 *in,
                        size_t nb_blocks, unsigned end)
{
	// Local all the things!
	const u32 r0 = ctx->r[0];
	const u32 r1 = ctx->r[1];
	const u32 r2 = ctx->r[2];
	const u32 r3 = ctx->r[3];
	const u32 rr0 = (r0 >> 2) * 5;  // lose 2 bits...
	const u32 rr1 = (r1 >> 2) + r1; // rr1 == (r1 >> 2) * 5
	const u32 rr2 = (r2 >> 2) + r2; // rr1 == (r2 >> 2) * 5
	const u32 rr3 = (r3 >> 2) + r3; // rr1 == (r3 >> 2) * 5
	const u32 rr4 = r0 & 3;         // ...recover 2 bits
	u32 h0 = ctx->h[0];
	u32 h1 = ctx->h[1];
	u32 h2 = ctx->h[2];
	u32 h3 = ctx->h[3];
	u32 h4 = ctx->h[4];

	FOR (i, 0, nb_blocks) {
		// h + c, without carry propagation
		const u64 s0 = (u64)h0 + load32_le(in);  in += 4;
		const u64 s1 = (u64)h1 + load32_le(in);  in += 4;
		const u64 s2 = (u64)h2 + load32_le(in);  in += 4;
		const u64 s3 = (u64)h3 + load32_le(in);  in += 4;
		const u32 s4 =      h4 + end;

		// (h + c) * r, without carry propagation
		const u64 x0 = s0*r0+ s1*rr3+ s2*rr2+ s3*rr1+ s4*rr0;
		const u64 x1 = s0*r1+ s1*r0 + s2*rr3+ s3*rr2+ s4*rr1;
		const u64 x2 = s0*r2+ s1*r1 + s2*r0 + s3*rr3+ s4*rr2;
		const u64 x3 = s0*r3+ s1*r2 + s2*r1 + s3*r0 + s4*rr3;
		const u32 x4 =                                s4*rr4;

		// partial reduction modulo 2^130 - 5
		const u32 u5 = x4 + (x3 >> 32); // u5 <= 7ffffff5
		const u64 u0 = (u5 >>  2) * 5 + (x0 & 0xffffffff);
		const u64 u1 = (u0 >> 32)     + (x1 & 0xffffffff) + (x0 >> 32);
		const u64 u2 = (u1 >> 32)     + (x2 & 0xffffffff) + (x1 >> 32);
		const u64 u3 = (u2 >> 32)     + (x3 & 0xffffffff) + (x2 >> 32);
		const u32 u4 = (u3 >> 32)     + (u5 & 3); // u4 <= 4

		// Update the hash
		h0 = u0 & 0xffffffff;
		h1 = u1 & 0xffffffff;
		h2 = u2 & 0xffffffff;
		h3 = u3 & 0xffffffff;
		h4 = u4;
	}
	ctx->h[0] = h0;
	ctx->h[1] = h1;
	ctx->h[2] = h2;
	ctx->h[3] = h3;
	ctx->h[4] = h4;
}

void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const u8 key[32])
{
	ZERO(ctx->h, 5); // Initial hash is zero
	ctx->c_idx = 0;
	// load r and pad (r has some of its bits cleared)
	load32_le_buf(ctx->r  , key   , 4);
	load32_le_buf(ctx->pad, key+16, 4);
	FOR (i, 0, 1) { ctx->r[i] &= 0x0fffffff; }
	FOR (i, 1, 4) { ctx->r[i] &= 0x0ffffffc; }
}

void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const u8 *message, size_t message_size)
{
	// Avoid undefined NULL pointer increments with empty messages
	if (message_size == 0) {
		return;
	}

	// Align ourselves with block boundaries
	size_t aligned = MIN(gap(ctx->c_idx, 16), message_size);
	FOR (i, 0, aligned) {
		ctx->c[ctx->c_idx] = *message;
		ctx->c_idx++;
		message++;
		message_size--;
	}

	// If block is complete, process it
	if (ctx->c_idx == 16) {
		poly_blocks(ctx, ctx->c, 1, 1);
		ctx->c_idx = 0;
	}

	// Process the message block by block
	size_t nb_blocks = message_size >> 4;
	poly_blocks(ctx, message, nb_blocks, 1);
	message      += nb_blocks << 4;
	message_size &= 15;

	// remaining bytes (we never complete a block here)
	FOR (i, 0, message_size) {
		ctx->c[ctx->c_idx] = message[i];
		ctx->c_idx++;
	}
}

void crypto_poly1305_final(crypto_poly1305_ctx *ctx, u8 mac[16])
{
	// Process the last block (if any)
	// We move the final 1 according to remaining input length
	// (this will add less than 2^130 to the last input block)
	if (ctx->c_idx != 0) {
		ZERO(ctx->c + ctx->c_idx, 16 - ctx->c_idx);
		ctx->c[ctx->c_idx] = 1;
		poly_blocks(ctx, ctx->c, 1, 0);
	}

	// check if we should subtract 2^130-5 by performing the
	// corresponding carry propagation.
	u64 c = 5;
	FOR (i, 0, 4) {
		c  += ctx->h[i];
		c >>= 32;
	}
	c += ctx->h[4];
	c  = (c >> 2) * 5; // shift the carry back to the beginning
	// c now indicates how many times we should subtract 2^130-5 (0 or 1)
	FOR (i, 0, 4) {
		c += (u64)ctx->h[i] + ctx->pad[i];
		store32_le(mac + i*4, (u32)c);
		c = c >> 32;
	}
	crypto_wipe(ctx, sizeof(*(ctx)));
}

void crypto_poly1305(u8     mac[16],  const u8 *message,
                     size_t message_size, const u8  key[32])
{
	crypto_poly1305_ctx ctx;
	crypto_poly1305_init  (&ctx, key);
	crypto_poly1305_update(&ctx, message, message_size);
	crypto_poly1305_final (&ctx, mac);
}

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

static void xchacha20poly1305_keystream(
    uint8_t        otk[32],      /* out: one-time Poly1305 key        */
    uint8_t        subkey[32],   /* out: HChaCha20 subkey             */
    const uint8_t  nonce[24],
    const uint8_t  key[32])
{
    crypto_chacha20_h(subkey, key, nonce);           /* nonce[0..15]  */

    uint8_t block[64] = {0};
    crypto_chacha20_djb(block, block, 64,
                        subkey, nonce + 16, 0);      /* ctr=0, take [0..31] */
    __memcpy(otk, block, 32);
    crypto_wipe(block, sizeof(block));               /* wipe keystream block */
}

static void xchacha20poly1305_mac(
    uint8_t        tag[16],
    const uint8_t *ad,   size_t adlen,
    const uint8_t *c,    size_t clen,
    const uint8_t  otk[32])
{
    static const uint8_t zero[15] = {0};
    uint8_t lengths[16];
    uint64_t adlen64 = (uint64_t)adlen;
    uint64_t clen64  = (uint64_t)clen;
    __memcpy(lengths,     &adlen64, 8);
    __memcpy(lengths + 8, &clen64,  8);

    crypto_poly1305_ctx ctx;
    crypto_poly1305_init  (&ctx, otk);
    crypto_poly1305_update(&ctx, ad,    adlen);
    crypto_poly1305_update(&ctx, zero,  (16 - (adlen % 16)) % 16);
    crypto_poly1305_update(&ctx, c,     clen);
    crypto_poly1305_update(&ctx, zero,  (16 - (clen  % 16)) % 16);
    crypto_poly1305_update(&ctx, lengths, 16);
    crypto_poly1305_final (&ctx, tag);
}

/* Constant-time 16-byte compare. Returns 0 if equal, nonzero otherwise. */
static int xchacha20poly1305_verify16(const uint8_t *a, const uint8_t *b)
{
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= a[i] ^ b[i];
    return (int)diff;
}

int xchacha20poly1305_self_test_vector(void)
{
    /*
     * TEST VECTOR 1 - IETF XChaCha20-Poly1305 test vector
     *
     * Reference: https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03
     */
    
    static const uint8_t key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };

    /* FIXED TEST NONCE - DO NOT USE IN PRODUCTION */
    static const uint8_t nonce[24] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
        0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57
    };

    static const uint8_t ad[] = {
        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7
    };
    const size_t adlen = sizeof(ad);

    static const uint8_t plaintext[] = {
        0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,
        0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,
        0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
        0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,
        0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,
        0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
        0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,
        0x74,0x2e
    };
    const size_t mlen = sizeof(plaintext); /* 114 */

    static const uint8_t exp_cipher[] = {
        0xbd,0x6d,0x17,0x9d,0x3e,0x83,0xd4,0x3b,0x95,0x76,0x57,0x94,0x93,0xc0,0xe9,0x39,
        0x57,0x2a,0x17,0x00,0x25,0x2b,0xfa,0xcc,0xbe,0xd2,0x90,0x2c,0x21,0x39,0x6c,0xbb,
        0x73,0x1c,0x7f,0x1b,0x0b,0x4a,0xa6,0x44,0x0b,0xf3,0xa8,0x2f,0x4e,0xda,0x7e,0x39,
        0xae,0x64,0xc6,0x70,0x8c,0x54,0xc2,0x16,0xcb,0x96,0xb7,0x2e,0x12,0x13,0xb4,0x52,
        0x2f,0x8c,0x9b,0xa4,0x0d,0xb5,0xd9,0x45,0xb1,0x1b,0x69,0xb9,0x82,0xc1,0xbb,0x9e,
        0x3f,0x3f,0xac,0x2b,0xc3,0x69,0x48,0x8f,0x76,0xb2,0x38,0x35,0x65,0xd3,0xff,0xf9,
        0x21,0xf9,0x66,0x4c,0x97,0x63,0x7d,0xa9,0x76,0x88,0x12,0xf6,0x15,0xc6,0x8b,0x13,
        0xb5,0x2e
    };

    static const uint8_t exp_tag[16] = {
        0xc0,0x87,0x59,0x24,0xc1,0xc7,0x98,0x79,
        0x47,0xde,0xaf,0xd8,0x78,0x0a,0xcf,0x49
    };

    /* ------------------------------------------------------------------ */
    /* 1. Derive subkey: HChaCha20(key, nonce[0..15])                      */
    /* ------------------------------------------------------------------ */
    uint8_t subkey[32];
    crypto_chacha20_h(subkey, key, nonce);

    /* ------------------------------------------------------------------ */
    /* 2. Build the 8-byte chacha20_x nonce: nonce[16..23]                 */
    /*    crypto_chacha20_x takes a 24-byte nonce; it internally uses      */
    /*    [0..15] for HChaCha20 and [16..23] as the stream nonce.          */
    /*    Since we call the raw _x stream directly with the subkey, we     */
    /*    construct a 24-byte nonce whose first 16 bytes are zero and      */
    /*    last 8 bytes are nonce[16..23].                                  */
    /* ------------------------------------------------------------------ */
    uint8_t stream_nonce[24];
    __memset(stream_nonce, 0, 16);
    __memcpy(stream_nonce + 16, nonce + 16, 8);

    /* ------------------------------------------------------------------ */
    /* 3. Generate one-time Poly1305 key at ctr=0                          */
    /* ------------------------------------------------------------------ */
    uint8_t otk_stream[64];
    __memset(otk_stream, 0, sizeof(otk_stream));
    crypto_chacha20_djb(otk_stream, otk_stream, sizeof(otk_stream),
                        subkey, nonce + 16, 0);
    const uint8_t *otk = otk_stream;


    /* ------------------------------------------------------------------ */
    /* 4. Encrypt at ctr=1                                                 */
    /* ------------------------------------------------------------------ */
    uint8_t c[sizeof(plaintext)];
    crypto_chacha20_djb(c, plaintext, mlen,
                        subkey, nonce + 16, 1);

    /* ------------------------------------------------------------------ */
    /* 5. Build Poly1305 MAC input:                                        */
    /*    pad16(AAD) || pad16(ciphertext) || le64(adlen) || le64(clen)     */
    /* ------------------------------------------------------------------ */
    size_t adpad  = (16 - (adlen % 16)) % 16;
    size_t ctpad  = (16 - (mlen  % 16)) % 16;
    size_t mac_input_len = adlen + adpad + mlen + ctpad + 8 + 8;

    uint8_t *mac_input = (uint8_t *)__calloc(mac_input_len, 1);
    if (!mac_input) return -99;

    uint8_t *p = mac_input;
    __memcpy(p, ad, adlen);           p += adlen + adpad;
    __memcpy(p, c, mlen);             p += mlen  + ctpad;
    /* le64(adlen) */
    uint64_t adlen64 = (uint64_t)adlen;
    __memcpy(p, &adlen64, 8);         p += 8;
    /* le64(clen) */
    uint64_t clen64 = (uint64_t)mlen;
    __memcpy(p, &clen64, 8);

    uint8_t tag[16];
    crypto_poly1305(tag, mac_input, mac_input_len, otk);
    __free(mac_input);
    mac_input = NULL;  /* guard against use-after-free */

    /* ------------------------------------------------------------------ */
    /* 6. Verify against expected values                                   */
    /* ------------------------------------------------------------------ */
    if (__memcmp(c,   exp_cipher, mlen) != 0) return -3;
    if (__memcmp(tag, exp_tag,    16)   != 0) return -4;

    /* ------------------------------------------------------------------ */
    /* 7. Decrypt                                                           */
    /* ------------------------------------------------------------------ */
    /* Re-derive mac_input identically (same ciphertext = c) */
    mac_input = (uint8_t *)__calloc(mac_input_len, 1);
    if (!mac_input) return -99;
    p = mac_input;
    __memcpy(p, ad, adlen);   p += adlen + adpad;
    __memcpy(p, c, mlen);     p += mlen  + ctpad;
    __memcpy(p, &adlen64, 8); p += 8;
    __memcpy(p, &clen64,  8);

    uint8_t dec_tag[16];
    crypto_poly1305(dec_tag, mac_input, mac_input_len, otk);
    __free(mac_input);
    mac_input = NULL;  /* guard against use-after-free */

    if (__memcmp(dec_tag, tag, 16) != 0) return -5; /* auth failure */

    uint8_t m[sizeof(plaintext)];
    /* XChaCha20 is its own inverse - same call decrypts */
    crypto_chacha20_djb(m, c, mlen,
                        subkey, nonce + 16, 1);

    if (__memcmp(m, plaintext, mlen) != 0) return -7;

    return 0;
}

int xchacha20poly1305_self_test_vector2(void)
{
    /*
     * Test vectors derived from draft-arciszewski-xchacha-03 Appendix A.2.
     * Same key as vector2, different nonce (last byte 0x58 not 0x57).
     * AAD is empty.  The expected ciphertext bytes are taken directly from
     * the stream-cipher test in A.2 (counter=1, which is what our AEAD
     * wrapper uses for the actual plaintext encryption).
     *
     * Additionally exercises:
     *   clen < 16  -> -1
     *   tampered tag  -> -2
     *   tampered ciphertext  -> -2
     */

    static const uint8_t key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };

    /* A.2 nonce - last byte differs from vector2 (0x58 vs 0x57) */
    static const uint8_t nonce[24] = {
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
        0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
        0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x58
    };

    /* No AAD */
    const size_t adlen = 0;

    /* "The dhole (pronounced "dole") is also known as ..." - 293 bytes */
    static const uint8_t plaintext[] = {
        0x54,0x68,0x65,0x20,0x64,0x68,0x6f,0x6c,0x65,0x20,0x28,0x70,0x72,0x6f,0x6e,0x6f,
        0x75,0x6e,0x63,0x65,0x64,0x20,0x22,0x64,0x6f,0x6c,0x65,0x22,0x29,0x20,0x69,0x73,
        0x20,0x61,0x6c,0x73,0x6f,0x20,0x6b,0x6e,0x6f,0x77,0x6e,0x20,0x61,0x73,0x20,0x74,
        0x68,0x65,0x20,0x41,0x73,0x69,0x61,0x74,0x69,0x63,0x20,0x77,0x69,0x6c,0x64,0x20,
        0x64,0x6f,0x67,0x2c,0x20,0x72,0x65,0x64,0x20,0x64,0x6f,0x67,0x2c,0x20,0x61,0x6e,
        0x64,0x20,0x77,0x68,0x69,0x73,0x74,0x6c,0x69,0x6e,0x67,0x20,0x64,0x6f,0x67,0x2e,
        0x20,0x49,0x74,0x20,0x69,0x73,0x20,0x61,0x62,0x6f,0x75,0x74,0x20,0x74,0x68,0x65,
        0x20,0x73,0x69,0x7a,0x65,0x20,0x6f,0x66,0x20,0x61,0x20,0x47,0x65,0x72,0x6d,0x61,
        0x6e,0x20,0x73,0x68,0x65,0x70,0x68,0x65,0x72,0x64,0x20,0x62,0x75,0x74,0x20,0x6c,
        0x6f,0x6f,0x6b,0x73,0x20,0x6d,0x6f,0x72,0x65,0x20,0x6c,0x69,0x6b,0x65,0x20,0x61,
        0x20,0x6c,0x6f,0x6e,0x67,0x2d,0x6c,0x65,0x67,0x67,0x65,0x64,0x20,0x66,0x6f,0x78,
        0x2e,0x20,0x54,0x68,0x69,0x73,0x20,0x68,0x69,0x67,0x68,0x6c,0x79,0x20,0x65,0x6c,
        0x75,0x73,0x69,0x76,0x65,0x20,0x61,0x6e,0x64,0x20,0x73,0x6b,0x69,0x6c,0x6c,0x65,
        0x64,0x20,0x6a,0x75,0x6d,0x70,0x65,0x72,0x20,0x69,0x73,0x20,0x63,0x6c,0x61,0x73,
        0x73,0x69,0x66,0x69,0x65,0x64,0x20,0x77,0x69,0x74,0x68,0x20,0x77,0x6f,0x6c,0x76,
        0x65,0x73,0x2c,0x20,0x63,0x6f,0x79,0x6f,0x74,0x65,0x73,0x2c,0x20,0x6a,0x61,0x63,
        0x6b,0x61,0x6c,0x73,0x2c,0x20,0x61,0x6e,0x64,0x20,0x66,0x6f,0x78,0x65,0x73,0x20,
        0x69,0x6e,0x20,0x74,0x68,0x65,0x20,0x74,0x61,0x78,0x6f,0x6e,0x6f,0x6d,0x69,0x63,
        0x20,0x66,0x61,0x6d,0x69,0x6c,0x79,0x20,0x43,0x61,0x6e,0x69,0x64,0x61,0x65,0x2e
    };
    const size_t mlen = sizeof(plaintext); /* 293 */

    /*
     * Expected ciphertext from draft-arciszewski-xchacha-03, Appendix A.2.
     * This independently verifies the XChaCha20 stream (counter=1) portion
     * of our AEAD wrapper, since AAD is empty and the stream cipher output
     * is fully specified by that test vector.
     */
    static const uint8_t exp_cipher[] = {
        0x7d,0x0a,0x2e,0x6b,0x7f,0x7c,0x65,0xa2,0x36,0x54,0x26,0x30,0x29,0x4e,0x06,0x3b,
        0x7a,0xb9,0xb5,0x55,0xa5,0xd5,0x14,0x9a,0xa2,0x1e,0x4a,0xe1,0xe4,0xfb,0xce,0x87,
        0xec,0xc8,0xe0,0x8a,0x8b,0x5e,0x35,0x0a,0xbe,0x62,0x2b,0x2f,0xfa,0x61,0x7b,0x20,
        0x2c,0xfa,0xd7,0x20,0x32,0xa3,0x03,0x7e,0x76,0xff,0xdc,0xdc,0x43,0x76,0xee,0x05,
        0x3a,0x19,0x0d,0x7e,0x46,0xca,0x1d,0xe0,0x41,0x44,0x85,0x03,0x81,0xb9,0xcb,0x29,
        0xf0,0x51,0x91,0x53,0x86,0xb8,0xa7,0x10,0xb8,0xac,0x4d,0x02,0x7b,0x8b,0x05,0x0f,
        0x7c,0xba,0x58,0x54,0xe0,0x28,0xd5,0x64,0xe4,0x53,0xb8,0xa9,0x68,0x82,0x41,0x73,
        0xfc,0x16,0x48,0x8b,0x89,0x70,0xca,0xc8,0x28,0xf1,0x1a,0xe5,0x3c,0xab,0xd2,0x01,
        0x12,0xf8,0x71,0x07,0xdf,0x24,0xee,0x61,0x83,0xd2,0x27,0x4f,0xe4,0xc8,0xb1,0x48,
        0x55,0x34,0xef,0x2c,0x5f,0xbc,0x1e,0xc2,0x4b,0xfc,0x36,0x63,0xef,0xaa,0x08,0xbc,
        0x04,0x7d,0x29,0xd2,0x50,0x43,0x53,0x2d,0xb8,0x39,0x1a,0x8a,0x3d,0x77,0x6b,0xf4,
        0x37,0x2a,0x69,0x55,0x82,0x7c,0xcb,0x0c,0xdd,0x4a,0xf4,0x03,0xa7,0xce,0x4c,0x63,
        0xd5,0x95,0xc7,0x5a,0x43,0xe0,0x45,0xf0,0xcc,0xe1,0xf2,0x9c,0x8b,0x93,0xbd,0x65,
        0xaf,0xc5,0x97,0x49,0x22,0xf2,0x14,0xa4,0x0b,0x7c,0x40,0x2c,0xdb,0x91,0xae,0x73,
        0xc0,0xb6,0x36,0x15,0xcd,0xad,0x04,0x80,0x68,0x0f,0x16,0x51,0x5a,0x7a,0xce,0x9d,
        0x39,0x23,0x64,0x64,0x32,0x8a,0x37,0x74,0x3f,0xfc,0x28,0xf4,0xdd,0xb3,0x24,0xf4,
        0xd0,0xf5,0xbb,0xdc,0x27,0x0c,0x65,0xb1,0x74,0x9a,0x6e,0xff,0xf1,0xfb,0xaa,0x09,
        0x53,0x61,0x75,0xcc,0xd2,0x9f,0xb9,0xe6,0x05,0x7b,0x30,0x73,0x20,0xd3,0x16,0x83,
        0x8a,0x9c,0x71,0xf7,0x0b,0x5b,0x59,0x07,0xa6,0x6f,0x7e,0xa4,0x9a,0xad,0xc4,0x09
    };

    uint8_t c[sizeof(plaintext) + 16];
    uint8_t m[sizeof(plaintext)];
    size_t  clen = 0, dec_mlen = 0;

    /* ------------------------------------------------------------------ */
    /* 1. Encrypt via wrapper                                               */
    /* ------------------------------------------------------------------ */
    if (xchacha20poly1305_encrypt(c, &clen, plaintext, mlen,
                                  NULL, adlen, nonce, key) != 0) return -1;
    if (clen != mlen + 16) return -2;

    /* Verify the ciphertext bytes against the A.2 stream-cipher KAT */
    if (__memcmp(c, exp_cipher, mlen) != 0) return -3;

    /* ------------------------------------------------------------------ */
    /* 2. Decrypt via wrapper - happy path                                  */
    /* ------------------------------------------------------------------ */
    if (xchacha20poly1305_decrypt(m, &dec_mlen, c, clen,
                                  NULL, adlen, nonce, key) != 0) return -4;
    if (dec_mlen != mlen) return -5;
    if (__memcmp(m, plaintext, mlen) != 0) return -6;

    /* ------------------------------------------------------------------ */
    /* 3. clen < 16 must return -1                                          */
    /* ------------------------------------------------------------------ */
    if (xchacha20poly1305_decrypt(m, &dec_mlen, c, 15,
                                  NULL, adlen, nonce, key) != -1) return -7;

    /* ------------------------------------------------------------------ */
    /* 4. Tampered tag must return -2, plaintext must NOT be written        */
    /* ------------------------------------------------------------------ */
    uint8_t c_bad[sizeof(c)];
    __memcpy(c_bad, c, clen);
    c_bad[mlen] ^= 0x01;   /* flip one bit in the tag */

    __memset(m, 0xAB, mlen); /* sentinel */
    if (xchacha20poly1305_decrypt(m, &dec_mlen, c_bad, clen,
                                  NULL, adlen, nonce, key) != -2) return -8;
    /* m must be pristine - decrypt must not touch it on auth failure */
    for (size_t i = 0; i < mlen; i++)
        if (m[i] != 0xAB) return -9;

    /* ------------------------------------------------------------------ */
    /* 5. Tampered ciphertext must also return -2                           */
    /* ------------------------------------------------------------------ */
    __memcpy(c_bad, c, clen);
    c_bad[0] ^= 0xFF;   /* corrupt first ciphertext byte */

    if (xchacha20poly1305_decrypt(m, &dec_mlen, c_bad, clen,
                                  NULL, adlen, nonce, key) != -2) return -10;

    return 0;
}


/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

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
    const uint8_t  key[32])
{
    uint8_t subkey[32], otk[32];
    xchacha20poly1305_keystream(otk, subkey, nonce, key);

    crypto_chacha20_djb(c, m, mlen, subkey, nonce + 16, 1);
    xchacha20poly1305_mac(c + mlen, ad, adlen, c, mlen, otk);

    crypto_wipe(subkey, sizeof(subkey));
    crypto_wipe(otk,    sizeof(otk));

    if (clen_out) *clen_out = mlen + 16;
    return 0;
}

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
    const uint8_t  key[32])
{
    if (clen < 16) return -1;
    const size_t mlen = clen - 16;

    uint8_t subkey[32], otk[32];
    xchacha20poly1305_keystream(otk, subkey, nonce, key);

    /* Authenticate BEFORE decrypting */
    uint8_t tag[16];
    xchacha20poly1305_mac(tag, ad, adlen, c, mlen, otk);

    if (xchacha20poly1305_verify16(tag, c + mlen) != 0) {
        crypto_wipe(subkey, sizeof(subkey));
        crypto_wipe(otk,    sizeof(otk));
        return -2;
    }

    crypto_chacha20_djb(m, c, mlen, subkey, nonce + 16, 1);

    crypto_wipe(subkey, sizeof(subkey));
    crypto_wipe(otk,    sizeof(otk));

    if (mlen_out) *mlen_out = mlen;
    return 0;
}


#ifdef __cplusplus
}
#endif
/* ALL of the below is dead code and is only kept for reference purposes. We assume Bastia will be reused by other projects.
    - serexp.
*/

/* ************************************************************
 * AES-NI implementation
 * Depends on immintrin.h. Assumes CPU supports AES-NI.
 * ************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/* Macro to generate an inline function for a given rcon constant */
#define NI_AES_KEYGEN_ASSIST_FN(suffix, rcon_val)              \
    ALWAYS_INLINE __m128i ni_aes_keygen_assist_##suffix(__m128i key) { \
        __m128i t = _mm_aeskeygenassist_si128(key, (rcon_val));  \
        t = _mm_shuffle_epi32(t, 0xff);                          \
        return _mm_xor_si128(key, _mm_slli_si128(key, 4))         \
             ^ _mm_slli_si128(t, 4) ^ t;                         \
    }

/* Generate functions for each rcon value used in key expansion */
NI_AES_KEYGEN_ASSIST_FN(01, 0x01)
NI_AES_KEYGEN_ASSIST_FN(02, 0x02)
NI_AES_KEYGEN_ASSIST_FN(04, 0x04)
NI_AES_KEYGEN_ASSIST_FN(08, 0x08)
NI_AES_KEYGEN_ASSIST_FN(10, 0x10)
NI_AES_KEYGEN_ASSIST_FN(20, 0x20)
NI_AES_KEYGEN_ASSIST_FN(40, 0x40)
NI_AES_KEYGEN_ASSIST_FN(80, 0x80)
NI_AES_KEYGEN_ASSIST_FN(1B, 0x1B)
NI_AES_KEYGEN_ASSIST_FN(36, 0x36)

/* Key expansion function */
ni_aes128_ctx ni_aes128_key_expansion(const uint8_t *key) {
    ni_aes128_ctx ctx = {0};
    ctx.rk[0] = _mm_loadu_si128((const __m128i *)key);
    ctx.rk[1] = ni_aes_keygen_assist_01(ctx.rk[0]);
    ctx.rk[2] = ni_aes_keygen_assist_02(ctx.rk[1]);
    ctx.rk[3] = ni_aes_keygen_assist_04(ctx.rk[2]);
    ctx.rk[4] = ni_aes_keygen_assist_08(ctx.rk[3]);
    ctx.rk[5] = ni_aes_keygen_assist_10(ctx.rk[4]);
    ctx.rk[6] = ni_aes_keygen_assist_20(ctx.rk[5]);
    ctx.rk[7] = ni_aes_keygen_assist_40(ctx.rk[6]);
    ctx.rk[8] = ni_aes_keygen_assist_80(ctx.rk[7]);
    ctx.rk[9] = ni_aes_keygen_assist_1B(ctx.rk[8]);
    ctx.rk[10] = ni_aes_keygen_assist_36(ctx.rk[9]);
    return ctx;
}

/* AES-NI ECB encryption block */
ALWAYS_INLINE __m128i ni_aes128_encrypt_block(__m128i block, const __m128i *rk) {
    block = _mm_xor_si128(block, rk[0]);
    for (int i = 1; i < 10; ++i)
        block = _mm_aesenc_si128(block, rk[i]);
    return _mm_aesenclast_si128(block, rk[10]);
}

/* AES-NI ECB encryption of multiple blocks */
void ni_aes128_ecb_encrypt(ni_aes128_ctx *ctx, uint8_t *out, const uint8_t *in, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        __m128i block = _mm_loadu_si128((const __m128i *)(in + i));
        block = ni_aes128_encrypt_block(block, ctx->rk);
        _mm_storeu_si128((__m128i *)(out + i), block);
    }
}
/* --- AES-NI decryption ---
 * To perform decryption with AES-NI, we need to create a decryption key schedule.
 * The decryption key schedule d_rk is computed from the encryption schedule rk as:
 *   d_rk[0] = rk[10]
 *   d_rk[i] = _mm_aesimc_si128(rk[10-i]), for i=1..9
 *   d_rk[10] = rk[0]
 */


ni_aes128_dec_ctx ni_aes128_key_expansion_decrypt(const uint8_t *key) {
    ni_aes128_ctx enc = ni_aes128_key_expansion(key);
    ni_aes128_dec_ctx dec;
    dec.rk[0] = enc.rk[10];
    for (int i = 1; i < 10; i++)
        dec.rk[i] = _mm_aesimc_si128(enc.rk[10 - i]);
    dec.rk[10] = enc.rk[0];
    return dec;
}

ALWAYS_INLINE __m128i ni_aes128_decrypt_block(__m128i block, const __m128i *rk) {
    block = _mm_xor_si128(block, rk[0]);
    for (int i = 1; i < 10; ++i)
        block = _mm_aesdec_si128(block, rk[i]);
    return _mm_aesdeclast_si128(block, rk[10]);
}

void ni_aes128_ecb_decrypt(ni_aes128_dec_ctx *ctx, uint8_t *out, const uint8_t *in, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        __m128i block = _mm_loadu_si128((const __m128i*)(in + i));
        block = ni_aes128_decrypt_block(block, ctx->rk);
        _mm_storeu_si128((__m128i*)(out + i), block);
    }
}

/* CTR mode encryption/decryption (AES-NI) */
void ni_aes128_ctr_encrypt(ni_aes128_ctx *ctx, uint8_t *out, const uint8_t *in, size_t len,
                           const uint8_t nonce[12], uint64_t counter) {
    if(!is_avx_supported()) {
        return;
    }
    uint8_t ctr_block[16];
    __memcpy(ctr_block, nonce, 12);
    STORE32_LE(ctr_block + 12, (uint32_t)counter);
    __m128i ctr = _mm_loadu_si128((const __m128i*)ctr_block);

    for (size_t i = 0; i < len; i += 16) {
        __m128i keystream = ni_aes128_encrypt_block(ctr, ctx->rk);
        _mm_storeu_si128((__m128i*)(out + i),
            _mm_xor_si128(keystream, _mm_loadu_si128((const __m128i*)(in + i))));

        uint32_t lo = LOAD32_LE(ctr_block + 12);
        STORE32_LE(ctr_block + 12, lo + 1);
        ctr = _mm_loadu_si128((const __m128i*)ctr_block);
    }
}
#ifdef __cplusplus
}
#endif

/* ========================================================================
 * AES-128 Self-Tests
 *
 * Test vectors from NIST FIPS 197 Appendix B.
 * These verify both hardware-accelerated (NI) and software AES paths.
 * ======================================================================== */

/* NIST FIPS 197 Appendix B AES-128 test vector */
static const uint8_t aes128_test_key[16] = {
    0x2b,0x7e,0x15,0x16, 0x28,0xae,0xd2,0xa6,
    0xab,0xf7,0x15,0x88, 0x09,0xcf,0x4f,0x3c
};

static const uint8_t aes128_test_plain[16] = {
    0x32,0x43,0xf6,0xa8, 0x88,0x5a,0x30,0x8d,
    0x31,0x31,0x98,0xa2, 0xe0,0x37,0x07,0x34
};

static const uint8_t aes128_test_cipher[16] = {
    0x39,0x25,0x84,0x1d, 0x25,0xdc,0x11,0x6a,
    0x8d,0x7b,0x5a,0x55, 0x8a,0xfe,0x17,0xc1
};

/* Expected round keys for key-expansion verification (FIPS 197 App. B) */
static const uint8_t aes128_expected_rk1[16] = {
    0xa0,0xfa,0xfe,0x17, 0x88,0x54,0x2c,0xb1,
    0x23,0xa3,0x39,0x39, 0x2a,0x6c,0x76,0x05
};

static const uint8_t aes128_expected_rk10[16] = {
    0xd0,0xa6,0x6c,0x52, 0xf7,0x1a,0x1c,0x61,
    0x74,0x8c,0x98,0x04, 0x7d,0x43,0xd7,0x38
};

/* Helper: compare two buffers of known length */
static bool aes_mem_eq(const uint8_t* a, const uint8_t* b, size_t len) {
    return __memcmp(a, b, len) == 0;
}

/*
 * test_ni_aes128_key_expansion
 *   Verify AES-NI key expansion produces correct round keys.
 */
bool test_ni_aes128_key_expansion(void) {
    ni_aes128_ctx ctx = ni_aes128_key_expansion(aes128_test_key);

    /* Check round key 1 */
    uint8_t rk1_out[16];
    _mm_storeu_si128((__m128i*)rk1_out, ctx.rk[1]);
    if (!aes_mem_eq(rk1_out, aes128_expected_rk1, 16)) return false;

    /* Check round key 10 (final) */
    uint8_t rk10_out[16];
    _mm_storeu_si128((__m128i*)rk10_out, ctx.rk[10]);
    if (!aes_mem_eq(rk10_out, aes128_expected_rk10, 16)) return false;

    return true;
}

/*
 * test_ni_aes128_ecb
 *   Verify AES-NI ECB encrypt produces the NIST expected ciphertext,
 *   and that ECB decrypt round-trips back to plaintext.
 */
bool test_ni_aes128_ecb(void) {
    /* Encryption test */
    ni_aes128_ctx enc = ni_aes128_key_expansion(aes128_test_key);
    uint8_t cipher_out[16];
    ni_aes128_ecb_encrypt(&enc, cipher_out, aes128_test_plain, 16);
    if (!aes_mem_eq(cipher_out, aes128_test_cipher, 16)) return false;

    /* Decryption round-trip */
    ni_aes128_dec_ctx dec = ni_aes128_key_expansion_decrypt(aes128_test_key);
    uint8_t plain_out[16];
    ni_aes128_ecb_decrypt(&dec, plain_out, aes128_test_cipher, 16);
    if (!aes_mem_eq(plain_out, aes128_test_plain, 16)) return false;

    return true;
}

/*
 * test_ni_aes128_ctr
 *   Verify CTR mode: encrypt then decrypt matches.
 *   CTR is symmetric
 */
bool test_ni_aes128_ctr(void) {
    static const uint8_t nonce[12] = {
        0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b
    };
    static const uint8_t msg[] = "The quick brown fox jumps over the lazy dog";
    const size_t msg_len = sizeof(msg) - 1; /* without NUL */

    uint8_t encrypted[64];
    uint8_t decrypted[64];
    __memset(encrypted, 0, sizeof(encrypted));
    __memset(decrypted, 0, sizeof(decrypted));

    ni_aes128_ctx ctx = ni_aes128_key_expansion(aes128_test_key);
    ni_aes128_ctr_encrypt(&ctx, encrypted, (const uint8_t*)msg, msg_len, nonce, 0);

    /* Ciphertext must differ from plaintext */
    if (aes_mem_eq(encrypted, (const uint8_t*)msg, msg_len)) return false;

    /* Decrypt (CTR is symmetric) */
    ctx = ni_aes128_key_expansion(aes128_test_key);
    ni_aes128_ctr_encrypt(&ctx, decrypted, encrypted, msg_len, nonce, 0);

    if (!aes_mem_eq(decrypted, (const uint8_t*)msg, msg_len)) return false;
    return true;
}

/*
 * all_aes_128_tests
 *   Run all AES-128 self-tests. Called from main.cpp during startup
 *   self-test sequence (guarded by DEBUG).
 */
bool all_aes_128_tests(void) {
    if (!test_ni_aes128_key_expansion()) return false;
    if (!test_ni_aes128_ecb()) return false;
    if (!test_ni_aes128_ctr()) return false;
    return true;
}

/* ============================================================================
 * Shared decrypt functions — single copy in binary, called by ALL lcg_encrypt
 * instantiations.  lcg_mul/lcg_add are the per-TU LCG constants from the TU
 * that owns the string; they are passed as parameters so this one copy can
 * serve any TU.
 * ============================================================================ */

static uint64_t lcg_step(uint64_t s, uint64_t mul, uint64_t add) {
    return s * mul + add;
}

static uint8_t lcg_byte(uint64_t seed, uint32_t idx,
                        uint64_t mul, uint64_t add) {
    uint64_t state = seed;
    uint32_t blocks = idx / 8;
    for (uint32_t i = 0; i < blocks + 1; i++)
        state = lcg_step(state, mul, add);
    return (uint8_t)((state >> ((idx % 8) * 8)) & 0xFF);
}

static uint16_t lcg_word(uint64_t seed, uint32_t idx,
                         uint64_t mul, uint64_t add) {
    uint64_t state = seed;
    uint32_t blocks = (idx * 2) / 8;
    for (uint32_t i = 0; i < blocks + 1; i++)
        state = lcg_step(state, mul, add);
    return (uint16_t)((state >> ((idx * 2 % 8) * 8)) & 0xFFFF);
}

void _lcg_resolve_str(const char* blob, size_t n, uint64_t seed,
                      uint64_t lcg_mul, uint64_t lcg_add, char* out) {
    const uint8_t* b = (const uint8_t*)blob;
    for (size_t i = 0; i < n; i++)
        out[i] = (char)(b[i] ^ lcg_byte(seed, (uint32_t)i, lcg_mul, lcg_add));
}

void _lcg_resolve_wstr(const wchar_t* blob, size_t n, uint64_t seed,
                       uint64_t lcg_mul, uint64_t lcg_add, wchar_t* out) {
    const uint16_t* b = (const uint16_t*)blob;
    for (size_t i = 0; i < n; i++)
        out[i] = (wchar_t)(b[i] ^ lcg_word(seed, (uint32_t)i, lcg_mul, lcg_add));
}

#ifdef BASTIA_STANDALONE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Function declarations for file operations
static int read_file(const char* filename, uint8_t** buffer, size_t* size);
static int write_file(const char* filename, const uint8_t* buffer, size_t size);
static int read_key_file(const char* key_filename, uint8_t* key, size_t key_size);
static void generate_random_nonce(uint8_t* nonce, size_t size);
static void print_usage(const char* program_name);
static void print_version();

extern "C"
int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    char* input_file = NULL;
    char* output_file = NULL;
    char* key_file = NULL;
    int mode = 0;
    int encrypt = 1; // Default to encrypt

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            input_file = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            mode = __atoi(argv[++i]);
        } else if (strcmp(argv[i], "-e") == 0) {
            encrypt = 1;
        } else if (strcmp(argv[i], "-d") == 0) {
            encrypt = 0;
        } else {
            printf("Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    // Validate required arguments
    if (!input_file || !output_file || !key_file) {
        printf("Error: Missing required arguments\n");
        print_usage(argv[0]);
        return 1;
    }

    if (mode <= 0 || mode > 4) {
        printf("Error: Invalid mode. Use 1=XChaCha20, 2=AES-128 ECB, 3=AES-128 CTR, 4=AES-NI CTR\n");
        return 1;
    }

    // Read input file
    uint8_t* input_buffer = NULL;
    size_t input_size = 0;
    if (!read_file(input_file, &input_buffer, &input_size)) {
        printf("Error: Failed to read input file: %s\n", input_file);
        return 1;
    }

    // Read key file (32 bytes for XChaCha20/AES-128)
    uint8_t key[32] = {0};
    if (!read_key_file(key_file, key, 32)) {
        printf("Error: Failed to read key file: %s\n", key_file);
        __free(input_buffer);
        return 1;
    }

    // Allocate output buffer (larger to accommodate header data like nonce)
    size_t output_size = input_size + 32; // Extra space for nonce/header
    uint8_t* output_buffer = (uint8_t*)__malloc(output_size);
    if (!output_buffer) {
        printf("Error: Memory allocation failed\n");
        __free(input_buffer);
        return 1;
    }

    int success = 0;
    size_t final_output_size = 0;

    switch (mode) {
        case 1: // XChaCha20
        {
            if (encrypt) {
                // Generate random 24-byte nonce
                uint8_t nonce[24];
                generate_random_nonce(nonce, 24);
                
                // Copy nonce to beginning of output buffer
                __memcpy(output_buffer, nonce, 24);
                
                xchacha20_ctx ctx;
                xchacha20_setup(&ctx, key, nonce, 0);
                xchacha20_crypt(&ctx, output_buffer + 24, input_buffer, input_size);
                final_output_size = 24 + input_size;
                success = 1;
            } else {
                // For decryption, read nonce from first 24 bytes
                if (input_size < 24) {
                    printf("Error: Input file too small for XChaCha20 (needs 24-byte nonce)\n");
                    break;
                }
                
                uint8_t* encrypted_data = input_buffer + 24;
                size_t encrypted_size = input_size - 24;
                
                xchacha20_ctx ctx;
                xchacha20_setup(&ctx, key, input_buffer, 0); // Use first 24 bytes as nonce
                xchacha20_crypt(&ctx, output_buffer, encrypted_data, encrypted_size);
                final_output_size = encrypted_size;
                success = 1;
            }
            break;
        }
        case 2: // AES-128 ECB
        {            
            // Ensure input size is multiple of 16 for ECB
            if (input_size % 16 != 0 && encrypt) {
                printf("Error: Input size must be multiple of 16 for AES-128 ECB encryption\n");
                break;
            }
            
            if (input_size % 16 != 0 && !encrypt) {
                printf("Error: Input size must be multiple of 16 for AES-128 ECB decryption\n");
                break;
            }
            
            if (encrypt) {
                ni_aes128_ctx ctx = ni_aes128_key_expansion(key);
                ni_aes128_ecb_encrypt(&ctx, output_buffer, input_buffer, input_size);
                final_output_size = input_size;
                success = 1;
            } else {
                ni_aes128_dec_ctx ctx = ni_aes128_key_expansion_decrypt(key);
                ni_aes128_ecb_decrypt(&ctx, output_buffer, input_buffer, input_size);
                final_output_size = input_size;
                success = 1;
            }
            break;
        }
        case 3: // AES-128 CTR
        {
            if (encrypt) {
                // Generate random 12-byte nonce
                uint8_t nonce[12];
                generate_random_nonce(nonce, 12);
                
                // Copy nonce to beginning of output buffer
                __memcpy(output_buffer, nonce, 12);
                
                ni_aes128_ctx ctx = ni_aes128_key_expansion(key);
                ni_aes128_ctr_encrypt(&ctx, output_buffer + 12, input_buffer, input_size, nonce, 0);
                final_output_size = 12 + input_size;
                success = 1;
            } else {
                // For decryption, read nonce from first 12 bytes
                if (input_size < 12) {
                    printf("Error: Input file too small for AES-128 CTR (needs 12-byte nonce)\n");
                    break;
                }
                
                uint8_t* encrypted_data = input_buffer + 12;
                size_t encrypted_size = input_size - 12;

                ni_aes128_ctx ctx = ni_aes128_key_expansion(key);
                ni_aes128_ctr_encrypt(&ctx, output_buffer, encrypted_data, encrypted_size, input_buffer, 0);
                final_output_size = encrypted_size;
                success = 1;
            }
            break;
        }
        case 4: // AES-NI CTR
        {
            if (is_avx_supported()) {
                if (encrypt) {
                    // Generate random 12-byte nonce
                    uint8_t nonce[12];
                    generate_random_nonce(nonce, 12);
                    
                    // Copy nonce to beginning of output buffer
                    __memcpy(output_buffer, nonce, 12);
                    
                    ni_aes128_ctx ctx = ni_aes128_key_expansion(key);
                    ni_aes128_ctr_encrypt(&ctx, output_buffer + 12, input_buffer, input_size, nonce, 0);
                    final_output_size = 12 + input_size;
                    success = 1;
                } else {
                    // For decryption, read nonce from first 12 bytes
                    if (input_size < 12) {
                        printf("Error: Input file too small for AES-NI CTR (needs 12-byte nonce)\n");
                        break;
                    }
                    
                    uint8_t* encrypted_data = input_buffer + 12;
                    size_t encrypted_size = input_size - 12;
                    
                    ni_aes128_ctx ctx = ni_aes128_key_expansion(key);
                    ni_aes128_ctr_encrypt(&ctx, output_buffer, encrypted_data, encrypted_size, input_buffer, 0);
                    final_output_size = encrypted_size;
                    success = 1;
                }
            } else {
                printf("Error: AES-NI not supported on this system\n");
            }
            break;
        }
    }

    if (success) {
        if (write_file(output_file, output_buffer, final_output_size)) {
            printf("Success: %s completed using mode %d\n", 
                   encrypt ? "Encryption" : "Decryption", mode);
            printf("Input: %s (%zu bytes)\n", input_file, input_size);
            printf("Output: %s (%zu bytes)\n", output_file, final_output_size);
        } else {
            printf("Error: Failed to write output file: %s\n", output_file);
            success = 0;
        }
    } else {
        printf("Error: %s failed for mode %d\n", 
               encrypt ? "Encryption" : "Decryption", mode);
    }

    // Clean up
    if (input_buffer) __free(input_buffer);
    if (output_buffer) __free(output_buffer);
    
    // Wipe key from memory
    __memset(key, 0, 32);

    return success ? 0 : 1;
}

// Helper function to read file into buffer
static int read_file(const char* filename, uint8_t** buffer, size_t* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return 0;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate buffer
    *buffer = (uint8_t*)__malloc(*size);
    if (!*buffer) {
        fclose(file);
        return 0;
    }

    // Read file content
    size_t bytes_read = fread(*buffer, 1, *size, file);
    fclose(file);

    if (bytes_read != *size) {
        __free(*buffer);
        *buffer = NULL;
        return 0;
    }

    return 1;
}

// Helper function to write buffer to file
static int write_file(const char* filename, const uint8_t* buffer, size_t size) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        return 0;
    }

    size_t bytes_written = fwrite(buffer, 1, size, file);
    fclose(file);

    return bytes_written == size;
}

// Helper function to read key file
static int read_key_file(const char* key_filename, uint8_t* key, size_t key_size) {
    FILE* file = fopen(key_filename, "rb");
    if (!file) {
        return 0;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (file_size != (long)key_size) {
        printf("Warning: Key file size is %ld bytes, expected %zu bytes\n", file_size, key_size);
        if (file_size > (long)key_size) {
            file_size = key_size;
        }
    }

    // Read key
    size_t bytes_read = fread(key, 1, file_size, file);
    fclose(file);

    // Pad with zeros if key file is smaller than expected
    if (file_size < (long)key_size) {
        __memset(key + file_size, 0, key_size - file_size);
    }

    return bytes_read == (size_t)file_size;
}

// Helper function to generate random nonce
static void generate_random_nonce(uint8_t* nonce, size_t size) {
    srand((unsigned int)time(NULL) ^ (unsigned int)__rdtsc());
    for (size_t i = 0; i < size; i++) {
        nonce[i] = rand() & 0xFF;
    }
}

// Print usage information
static void print_usage(const char* program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\nOptions:\n");
    printf("  -i FILE       Input file to encrypt/decrypt\n");
    printf("  -o FILE       Output file name\n");
    printf("  -k FILE       Key file (32 bytes for XChaCha20/AES-128)\n");
    printf("  -m MODE       Encryption mode:\n");
    printf("                1 = XChaCha20 (recommended)\n");
    printf("                2 = AES-128 ECB\n");
    printf("                3 = AES-128 CTR\n");
    printf("                4 = AES-NI CTR (hardware accelerated)\n");
    printf("  -e            Encrypt (default)\n");
    printf("  -d            Decrypt\n");
    printf("  -h, --help    Show this help message\n");
    printf("  --version     Show version information\n");
    printf("\nExamples:\n");
    printf("  %s -i document.txt -o document.enc -k key.bin -m 1 -e\n", program_name);
    printf("  %s -i document.enc -o document.dec -k key.bin -m 1 -d\n", program_name);
}

// Print version information
static void print_version() {
    printf("Bastia Crypto CLI v1.0\n");
    printf("Built with XChaCha20, AES-128 (ECB/CTR), and AES-NI support\n");
}

#endif
