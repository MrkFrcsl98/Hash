#ifndef HASH_SINGLE_HEADER_H
#define HASH_SINGLE_HEADER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// ========== Attribute Macros ==========
#if defined(__GNUC__) || defined(__clang__)
#define __attr_nodiscard __attribute__((warn_unused_result))
#define __attr_malloc __attribute__((malloc))
#define __attr_hot __attribute__((hot))
#define __attr_cold __attribute__((cold))
#define __likely(x) __builtin_expect(!!(x), 1)
#define __unlikely(x) __builtin_expect(!!(x), 0)
#else
#define __attr_nodiscard
#define __attr_malloc
#define __attr_hot
#define __attr_cold
#define __likely(x) (x)
#define __unlikely(x) (x)
#endif

#ifdef __cplusplus
#define __restrict__ __restrict
#define __noexcept noexcept
#define __const_noexcept const noexcept
extern "C" {
#else
#define __restrict__ restrict
#define __noexcept
#define __const_noexcept
#endif

#ifndef HASH_ERROR_HANDLER
#include <stdio.h>
#define HASH_ERROR_HANDLER(msg) fprintf(stderr, "%s\n", msg)
#endif

// ========== SHA-1 ==========

#define SHA1_BLOCK_SIZE 20

typedef struct {
  uint8_t data[64];
  uint32_t datalen;
  uint64_t bitlen;
  uint32_t state[5];
} sha1_ctx;

__attr_hot static void sha1_transform(sha1_ctx *__restrict__ ctx, const uint8_t *__restrict__ data) __noexcept {
  uint32_t a, b, c, d, e, f, k, temp, m[80];
  size_t i, j;

  for (i = 0, j = 0; i < 16; ++i, j += 4)
    m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3];
  for (; i < 80; ++i)
    m[i] = ((m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]) << 1) | ((m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]) >> 31);

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];

  for (i = 0; i < 80; ++i) {
    if (i < 20) {
      f = (b & c) | ((~b) & d);
      k = 0x5A827999;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }
    temp = ((a << 5) | (a >> (32 - 5))) + f + e + k + m[i];
    e = d;
    d = c;
    c = ((b << 30) | (b >> (32 - 30)));
    b = a;
    a = temp;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
}

__attr_hot static void sha1_init(sha1_ctx *__restrict__ ctx) __noexcept {
  if (__unlikely(!ctx)) {
    HASH_ERROR_HANDLER("sha1_init: ctx is NULL");
    return;
  }
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xEFCDAB89;
  ctx->state[2] = 0x98BADCFE;
  ctx->state[3] = 0x10325476;
  ctx->state[4] = 0xC3D2E1F0;
}

__attr_hot static void sha1_update(sha1_ctx *__restrict__ ctx, const uint8_t *__restrict__ data, size_t len) __noexcept {
  if (__unlikely(!ctx || !data)) {
    HASH_ERROR_HANDLER("sha1_update: ctx or data is NULL");
    return;
  }
  for (size_t i = 0; i < len; ++i) {
    ctx->data[ctx->datalen] = data[i];
    ctx->datalen++;
    if (__unlikely(ctx->datalen == 64)) {
      sha1_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}

__attr_hot static void sha1_final(sha1_ctx *__restrict__ ctx, uint8_t *__restrict__ hash) __noexcept {
  if (__unlikely(!ctx || !hash)) {
    HASH_ERROR_HANDLER("sha1_final: ctx or hash is NULL");
    return;
  }
  uint32_t i = ctx->datalen;
  if (i < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56)
      ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64)
      ctx->data[i++] = 0x00;
    sha1_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }
  ctx->bitlen += ctx->datalen * 8;
  ctx->data[63] = ctx->bitlen;
  ctx->data[62] = ctx->bitlen >> 8;
  ctx->data[61] = ctx->bitlen >> 16;
  ctx->data[60] = ctx->bitlen >> 24;
  ctx->data[59] = ctx->bitlen >> 32;
  ctx->data[58] = ctx->bitlen >> 40;
  ctx->data[57] = ctx->bitlen >> 48;
  ctx->data[56] = ctx->bitlen >> 56;
  sha1_transform(ctx, ctx->data);
  for (i = 0; i < 4; ++i) {
    hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0xFF;
    hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xFF;
    hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xFF;
    hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xFF;
    hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xFF;
  }
}

// ========== SHA-224/SHA-256 ==========

#define SHA224_BLOCK_SIZE 28
#define SHA256_BLOCK_SIZE 32

typedef struct {
  uint8_t data[64];
  uint32_t datalen;
  uint64_t bitlen;
  uint32_t state[8];
} sha256_ctx;

static const uint32_t __sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74,
    0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d,
    0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
    0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define __sha256_rotr(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define __sha256_ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define __sha256_maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define __sha256_ep0(x) (__sha256_rotr(x, 2) ^ __sha256_rotr(x, 13) ^ __sha256_rotr(x, 22))
#define __sha256_ep1(x) (__sha256_rotr(x, 6) ^ __sha256_rotr(x, 11) ^ __sha256_rotr(x, 25))
#define __sha256_sig0(x) (__sha256_rotr(x, 7) ^ __sha256_rotr(x, 18) ^ ((x) >> 3))
#define __sha256_sig1(x) (__sha256_rotr(x, 17) ^ __sha256_rotr(x, 19) ^ ((x) >> 10))

__attr_hot static void sha256_transform(sha256_ctx *__restrict__ ctx, const uint8_t *__restrict__ data) __noexcept {
  uint32_t m[64], a, b, c, d, e, f, g, h, t1, t2;
  size_t i, j;
  for (i = 0, j = 0; i < 16; ++i, j += 4)
    m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3];
  for (; i < 64; ++i)
    m[i] = __sha256_sig1(m[i - 2]) + m[i - 7] + __sha256_sig0(m[i - 15]) + m[i - 16];
  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];
  for (i = 0; i < 64; ++i) {
    t1 = h + __sha256_ep1(e) + __sha256_ch(e, f, g) + __sha256_k[i] + m[i];
    t2 = __sha256_ep0(a) + __sha256_maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

__attr_hot static void sha224_init(sha256_ctx *__restrict__ ctx) __noexcept {
  if (__unlikely(!ctx)) {
    HASH_ERROR_HANDLER("sha224_init: ctx is NULL");
    return;
  }
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0xc1059ed8;
  ctx->state[1] = 0x367cd507;
  ctx->state[2] = 0x3070dd17;
  ctx->state[3] = 0xf70e5939;
  ctx->state[4] = 0xffc00b31;
  ctx->state[5] = 0x68581511;
  ctx->state[6] = 0x64f98fa7;
  ctx->state[7] = 0xbefa4fa4;
}
__attr_hot static void sha256_init(sha256_ctx *__restrict__ ctx) __noexcept {
  if (__unlikely(!ctx)) {
    HASH_ERROR_HANDLER("sha256_init: ctx is NULL");
    return;
  }
  ctx->datalen = 0;
  ctx->bitlen = 0;
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
}
__attr_hot static void sha256_update(sha256_ctx *__restrict__ ctx, const uint8_t *__restrict__ data, size_t len) __noexcept {
  if (__unlikely(!ctx || !data)) {
    HASH_ERROR_HANDLER("sha256_update: ctx or data is NULL");
    return;
  }
  for (size_t i = 0; i < len; ++i) {
    ctx->data[ctx->datalen] = data[i];
    ctx->datalen++;
    if (__unlikely(ctx->datalen == 64)) {
      sha256_transform(ctx, ctx->data);
      ctx->bitlen += 512;
      ctx->datalen = 0;
    }
  }
}
__attr_hot static void sha224_final(sha256_ctx *__restrict__ ctx, uint8_t *__restrict__ hash) __noexcept {
  if (__unlikely(!ctx || !hash)) {
    HASH_ERROR_HANDLER("sha224_final: ctx or hash is NULL");
    return;
  }
  uint32_t i = ctx->datalen;
  if (i < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56)
      ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64)
      ctx->data[i++] = 0x00;
    sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }
  ctx->bitlen += ctx->datalen * 8;
  ctx->data[63] = ctx->bitlen;
  ctx->data[62] = ctx->bitlen >> 8;
  ctx->data[61] = ctx->bitlen >> 16;
  ctx->data[60] = ctx->bitlen >> 24;
  ctx->data[59] = ctx->bitlen >> 32;
  ctx->data[58] = ctx->bitlen >> 40;
  ctx->data[57] = ctx->bitlen >> 48;
  ctx->data[56] = ctx->bitlen >> 56;
  sha256_transform(ctx, ctx->data);
  for (i = 0; i < 4; ++i) {
    hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0xFF;
    hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xFF;
    hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xFF;
    hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xFF;
    hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xFF;
    hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xFF;
    hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xFF;
  }
}
__attr_hot static void sha256_final(sha256_ctx *__restrict__ ctx, uint8_t *__restrict__ hash) __noexcept {
  if (__unlikely(!ctx || !hash)) {
    HASH_ERROR_HANDLER("sha256_final: ctx or hash is NULL");
    return;
  }
  uint32_t i = ctx->datalen;
  if (i < 56) {
    ctx->data[i++] = 0x80;
    while (i < 56)
      ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 64)
      ctx->data[i++] = 0x00;
    sha256_transform(ctx, ctx->data);
    memset(ctx->data, 0, 56);
  }
  ctx->bitlen += ctx->datalen * 8;
  ctx->data[63] = ctx->bitlen;
  ctx->data[62] = ctx->bitlen >> 8;
  ctx->data[61] = ctx->bitlen >> 16;
  ctx->data[60] = ctx->bitlen >> 24;
  ctx->data[59] = ctx->bitlen >> 32;
  ctx->data[58] = ctx->bitlen >> 40;
  ctx->data[57] = ctx->bitlen >> 48;
  ctx->data[56] = ctx->bitlen >> 56;
  sha256_transform(ctx, ctx->data);
  for (i = 0; i < 4; ++i) {
    hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0xFF;
    hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xFF;
    hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xFF;
    hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xFF;
    hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xFF;
    hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xFF;
    hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xFF;
    hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xFF;
  }
}

// ========== SHA-384/SHA-512 ==========

#define SHA384_BLOCK_SIZE 48
#define SHA512_BLOCK_SIZE 64

typedef struct {
  uint8_t data[128];
  uint32_t datalen;
  uint64_t bitlen[2];
  uint64_t state[8];
} sha512_ctx;

static const uint64_t __sha512_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL,
    0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
    0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL,
    0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL, 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL,
    0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

#define __sha512_rotr(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define __sha512_ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define __sha512_maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define __sha512_ep0(x) (__sha512_rotr(x, 28) ^ __sha512_rotr(x, 34) ^ __sha512_rotr(x, 39))
#define __sha512_ep1(x) (__sha512_rotr(x, 14) ^ __sha512_rotr(x, 18) ^ __sha512_rotr(x, 41))
#define __sha512_sig0(x) (__sha512_rotr(x, 1) ^ __sha512_rotr(x, 8) ^ ((x) >> 7))
#define __sha512_sig1(x) (__sha512_rotr(x, 19) ^ __sha512_rotr(x, 61) ^ ((x) >> 6))

__attr_hot static void sha512_transform(sha512_ctx *__restrict__ ctx, const uint8_t *__restrict__ data) __noexcept {
  uint64_t m[80], a, b, c, d, e, f, g, h, t1, t2;
  size_t i, j;
  for (i = 0, j = 0; i < 16; ++i, j += 8)
    m[i] = ((uint64_t)data[j] << 56) | ((uint64_t)data[j + 1] << 48) | ((uint64_t)data[j + 2] << 40) | ((uint64_t)data[j + 3] << 32) | ((uint64_t)data[j + 4] << 24) |
           ((uint64_t)data[j + 5] << 16) | ((uint64_t)data[j + 6] << 8) | ((uint64_t)data[j + 7]);
  for (; i < 80; ++i)
    m[i] = __sha512_sig1(m[i - 2]) + m[i - 7] + __sha512_sig0(m[i - 15]) + m[i - 16];
  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];
  for (i = 0; i < 80; ++i) {
    t1 = h + __sha512_ep1(e) + __sha512_ch(e, f, g) + __sha512_k[i] + m[i];
    t2 = __sha512_ep0(a) + __sha512_maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

__attr_hot static void sha384_init(sha512_ctx *__restrict__ ctx) __noexcept {
  if (__unlikely(!ctx)) {
    HASH_ERROR_HANDLER("sha384_init: ctx is NULL");
    return;
  }
  ctx->datalen = 0;
  ctx->bitlen[0] = 0;
  ctx->bitlen[1] = 0;
  ctx->state[0] = 0xcbbb9d5dc1059ed8ULL;
  ctx->state[1] = 0x629a292a367cd507ULL;
  ctx->state[2] = 0x9159015a3070dd17ULL;
  ctx->state[3] = 0x152fecd8f70e5939ULL;
  ctx->state[4] = 0x67332667ffc00b31ULL;
  ctx->state[5] = 0x8eb44a8768581511ULL;
  ctx->state[6] = 0xdb0c2e0d64f98fa7ULL;
  ctx->state[7] = 0x47b5481dbefa4fa4ULL;
}
__attr_hot static void sha512_init(sha512_ctx *__restrict__ ctx) __noexcept {
  if (__unlikely(!ctx)) {
    HASH_ERROR_HANDLER("sha512_init: ctx is NULL");
    return;
  }
  ctx->datalen = 0;
  ctx->bitlen[0] = 0;
  ctx->bitlen[1] = 0;
  ctx->state[0] = 0x6a09e667f3bcc908ULL;
  ctx->state[1] = 0xbb67ae8584caa73bULL;
  ctx->state[2] = 0x3c6ef372fe94f82bULL;
  ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
  ctx->state[4] = 0x510e527fade682d1ULL;
  ctx->state[5] = 0x9b05688c2b3e6c1fULL;
  ctx->state[6] = 0x1f83d9abfb41bd6bULL;
  ctx->state[7] = 0x5be0cd19137e2179ULL;
}
__attr_hot static void sha512_update(sha512_ctx *__restrict__ ctx, const uint8_t *__restrict__ data, size_t len) __noexcept {
  if (__unlikely(!ctx || !data)) {
    HASH_ERROR_HANDLER("sha512_update: ctx or data is NULL");
    return;
  }
  for (size_t i = 0; i < len; ++i) {
    ctx->data[ctx->datalen] = data[i];
    ctx->datalen++;
    if (__unlikely(ctx->datalen == 128)) {
      sha512_transform(ctx, ctx->data);
      if ((ctx->bitlen[1] += 1024) < 1024)
        ctx->bitlen[0]++;
      ctx->datalen = 0;
    }
  }
}
__attr_hot static void sha384_final(sha512_ctx *__restrict__ ctx, uint8_t *__restrict__ hash) __noexcept {
  if (__unlikely(!ctx || !hash)) {
    HASH_ERROR_HANDLER("sha384_final: ctx or hash is NULL");
    return;
  }
  uint32_t i = ctx->datalen;
  if (i < 112) {
    ctx->data[i++] = 0x80;
    while (i < 112)
      ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 128)
      ctx->data[i++] = 0x00;
    sha512_transform(ctx, ctx->data);
    memset(ctx->data, 0, 112);
  }
  if ((ctx->bitlen[1] += ctx->datalen * 8) < ctx->datalen * 8)
    ctx->bitlen[0]++;
  for (int j = 0; j < 8; j++)
    ctx->data[127 - j] = (uint8_t)((ctx->bitlen[1] >> (8 * j)) & 0xFF);
  for (int j = 0; j < 8; j++)
    ctx->data[119 - j] = (uint8_t)((ctx->bitlen[0] >> (8 * j)) & 0xFF);
  sha512_transform(ctx, ctx->data);
  for (i = 0; i < 6; ++i)
    for (uint32_t j = 0; j < 8; ++j)
      hash[i * 8 + j] = (uint8_t)((ctx->state[i] >> (56 - 8 * j)) & 0xFF);
}
__attr_hot static void sha512_final(sha512_ctx *__restrict__ ctx, uint8_t *__restrict__ hash) __noexcept {
  if (__unlikely(!ctx || !hash)) {
    HASH_ERROR_HANDLER("sha512_final: ctx or hash is NULL");
    return;
  }
  uint32_t i = ctx->datalen;
  if (i < 112) {
    ctx->data[i++] = 0x80;
    while (i < 112)
      ctx->data[i++] = 0x00;
  } else {
    ctx->data[i++] = 0x80;
    while (i < 128)
      ctx->data[i++] = 0x00;
    sha512_transform(ctx, ctx->data);
    memset(ctx->data, 0, 112);
  }
  if ((ctx->bitlen[1] += ctx->datalen * 8) < ctx->datalen * 8)
    ctx->bitlen[0]++;
  for (int j = 0; j < 8; j++)
    ctx->data[127 - j] = (uint8_t)((ctx->bitlen[1] >> (8 * j)) & 0xFF);
  for (int j = 0; j < 8; j++)
    ctx->data[119 - j] = (uint8_t)((ctx->bitlen[0] >> (8 * j)) & 0xFF);
  sha512_transform(ctx, ctx->data);
  for (i = 0; i < 8; ++i)
    for (uint32_t j = 0; j < 8; ++j)
      hash[i * 8 + j] = (uint8_t)((ctx->state[i] >> (56 - 8 * j)) & 0xFF);
}

#ifdef __cplusplus
}
#endif

#define MD5_BLOCK_SIZE 16

typedef struct {
  uint32_t state[4], count[2];
  uint8_t buffer[64];
} md5_ctx;

__attr_hot static void md5_transform(md5_ctx *__restrict__ ctx, const uint8_t *__restrict__ block) __noexcept {
  uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3], x[16], i;
  for (i = 0; i < 16; i++)
    x[i] = (uint32_t)block[i * 4] | ((uint32_t)block[i * 4 + 1] << 8) | ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))
#define ROTATE(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define STEP(f, a, b, c, d, x, t, s)                                                                                                                                     \
  a += f(b, c, d) + x + t;                                                                                                                                               \
  a = ROTATE(a, s) + b
  STEP(F, a, b, c, d, x[0], 0xd76aa478, 7);
  STEP(F, d, a, b, c, x[1], 0xe8c7b756, 12);
  STEP(F, c, d, a, b, x[2], 0x242070db, 17);
  STEP(F, b, c, d, a, x[3], 0xc1bdceee, 22);
  STEP(F, a, b, c, d, x[4], 0xf57c0faf, 7);
  STEP(F, d, a, b, c, x[5], 0x4787c62a, 12);
  STEP(F, c, d, a, b, x[6], 0xa8304613, 17);
  STEP(F, b, c, d, a, x[7], 0xfd469501, 22);
  STEP(F, a, b, c, d, x[8], 0x698098d8, 7);
  STEP(F, d, a, b, c, x[9], 0x8b44f7af, 12);
  STEP(F, c, d, a, b, x[10], 0xffff5bb1, 17);
  STEP(F, b, c, d, a, x[11], 0x895cd7be, 22);
  STEP(F, a, b, c, d, x[12], 0x6b901122, 7);
  STEP(F, d, a, b, c, x[13], 0xfd987193, 12);
  STEP(F, c, d, a, b, x[14], 0xa679438e, 17);
  STEP(F, b, c, d, a, x[15], 0x49b40821, 22);
  STEP(G, a, b, c, d, x[1], 0xf61e2562, 5);
  STEP(G, d, a, b, c, x[6], 0xc040b340, 9);
  STEP(G, c, d, a, b, x[11], 0x265e5a51, 14);
  STEP(G, b, c, d, a, x[0], 0xe9b6c7aa, 20);
  STEP(G, a, b, c, d, x[5], 0xd62f105d, 5);
  STEP(G, d, a, b, c, x[10], 0x02441453, 9);
  STEP(G, c, d, a, b, x[15], 0xd8a1e681, 14);
  STEP(G, b, c, d, a, x[4], 0xe7d3fbc8, 20);
  STEP(G, a, b, c, d, x[9], 0x21e1cde6, 5);
  STEP(G, d, a, b, c, x[14], 0xc33707d6, 9);
  STEP(G, c, d, a, b, x[3], 0xf4d50d87, 14);
  STEP(G, b, c, d, a, x[8], 0x455a14ed, 20);
  STEP(G, a, b, c, d, x[13], 0xa9e3e905, 5);
  STEP(G, d, a, b, c, x[2], 0xfcefa3f8, 9);
  STEP(G, c, d, a, b, x[7], 0x676f02d9, 14);
  STEP(G, b, c, d, a, x[12], 0x8d2a4c8a, 20);
  STEP(H, a, b, c, d, x[5], 0xfffa3942, 4);
  STEP(H, d, a, b, c, x[8], 0x8771f681, 11);
  STEP(H, c, d, a, b, x[11], 0x6d9d6122, 16);
  STEP(H, b, c, d, a, x[14], 0xfde5380c, 23);
  STEP(H, a, b, c, d, x[1], 0xa4beea44, 4);
  STEP(H, d, a, b, c, x[4], 0x4bdecfa9, 11);
  STEP(H, c, d, a, b, x[7], 0xf6bb4b60, 16);
  STEP(H, b, c, d, a, x[10], 0xbebfbc70, 23);
  STEP(H, a, b, c, d, x[13], 0x289b7ec6, 4);
  STEP(H, d, a, b, c, x[0], 0xeaa127fa, 11);
  STEP(H, c, d, a, b, x[3], 0xd4ef3085, 16);
  STEP(H, b, c, d, a, x[6], 0x04881d05, 23);
  STEP(H, a, b, c, d, x[9], 0xd9d4d039, 4);
  STEP(H, d, a, b, c, x[12], 0xe6db99e5, 11);
  STEP(H, c, d, a, b, x[15], 0x1fa27cf8, 16);
  STEP(H, b, c, d, a, x[2], 0xc4ac5665, 23);
  STEP(I, a, b, c, d, x[0], 0xf4292244, 6);
  STEP(I, d, a, b, c, x[7], 0x432aff97, 10);
  STEP(I, c, d, a, b, x[14], 0xab9423a7, 15);
  STEP(I, b, c, d, a, x[5], 0xfc93a039, 21);
  STEP(I, a, b, c, d, x[12], 0x655b59c3, 6);
  STEP(I, d, a, b, c, x[3], 0x8f0ccc92, 10);
  STEP(I, c, d, a, b, x[10], 0xffeff47d, 15);
  STEP(I, b, c, d, a, x[1], 0x85845dd1, 21);
  STEP(I, a, b, c, d, x[8], 0x6fa87e4f, 6);
  STEP(I, d, a, b, c, x[15], 0xfe2ce6e0, 10);
  STEP(I, c, d, a, b, x[6], 0xa3014314, 15);
  STEP(I, b, c, d, a, x[13], 0x4e0811a1, 21);
  STEP(I, a, b, c, d, x[4], 0xf7537e82, 6);
  STEP(I, d, a, b, c, x[11], 0xbd3af235, 10);
  STEP(I, c, d, a, b, x[2], 0x2ad7d2bb, 15);
  STEP(I, b, c, d, a, x[9], 0xeb86d391, 21);
  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
#undef F
#undef G
#undef H
#undef I
#undef ROTATE
#undef STEP
}
__attr_hot static void md5_init(md5_ctx *__restrict__ ctx) __noexcept {
  if (__unlikely(!ctx)) {
    HASH_ERROR_HANDLER("md5_init: ctx is NULL");
    return;
  }
  ctx->count[0] = ctx->count[1] = 0;
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
}
__attr_hot static void md5_update(md5_ctx *__restrict__ ctx, const uint8_t *__restrict__ input, size_t len) __noexcept {
  if (__unlikely(!ctx || !input)) {
    HASH_ERROR_HANDLER("md5_update: ctx or input is NULL");
    return;
  }
  uint32_t i, index, partlen;
  index = (uint32_t)((ctx->count[0] >> 3) & 0x3F);
  if ((ctx->count[0] += ((uint32_t)len << 3)) < ((uint32_t)len << 3))
    ctx->count[1]++;
  ctx->count[1] += ((uint32_t)len >> 29);
  partlen = 64 - index;
  if (len >= partlen) {
    memcpy(&ctx->buffer[index], input, partlen);
    md5_transform(ctx, ctx->buffer);
    for (i = partlen; i + 63 < len; i += 64)
      md5_transform(ctx, &input[i]);
    index = 0;
  } else
    i = 0;
  memcpy(&ctx->buffer[index], &input[i], len - i);
}
__attr_hot static void md5_final(md5_ctx *__restrict__ ctx, uint8_t *__restrict__ digest) __noexcept {
  if (__unlikely(!ctx || !digest)) {
    HASH_ERROR_HANDLER("md5_final: ctx or digest is NULL");
    return;
  }
  static const uint8_t pad[64] = {0x80};
  uint8_t bits[8];
  uint32_t index, padlen, i;
  for (i = 0; i < 4; i++) {
    bits[i] = (uint8_t)(ctx->count[0] >> (8 * i));
    bits[i + 4] = (uint8_t)(ctx->count[1] >> (8 * i));
  }
  index = (uint32_t)((ctx->count[0] >> 3) & 0x3f);
  padlen = (index < 56) ? (56 - index) : (120 - index);
  md5_update(ctx, pad, padlen);
  md5_update(ctx, bits, 8);
  for (i = 0; i < 4; i++) {
    digest[i] = (uint8_t)(ctx->state[0] >> (8 * i));
    digest[i + 4] = (uint8_t)(ctx->state[1] >> (8 * i));
    digest[i + 8] = (uint8_t)(ctx->state[2] >> (8 * i));
    digest[i + 12] = (uint8_t)(ctx->state[3] >> (8 * i));
  }
}

#define BLAKE2B_OUTBYTES 64
#define BLAKE2B_BLOCKBYTES 128

typedef struct {
  uint64_t h[8], t[2], f[2];
  uint8_t buf[128];
  size_t buflen, outlen;
} blake2b_ctx;

static const uint64_t blake2b_iv[8] = {0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
                                       0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL, 0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL};

static const uint8_t blake2b_sigma[12][16] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
                                              {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
                                              {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
                                              {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
                                              {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
                                              {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define G(a, b, c, d, x, y)                                                                                                                                              \
  do {                                                                                                                                                                   \
    a = a + b + x;                                                                                                                                                       \
    d = ROTR64(d ^ a, 32);                                                                                                                                               \
    c = c + d;                                                                                                                                                           \
    b = ROTR64(b ^ c, 24);                                                                                                                                               \
    a = a + b + y;                                                                                                                                                       \
    d = ROTR64(d ^ a, 16);                                                                                                                                               \
    c = c + d;                                                                                                                                                           \
    b = ROTR64(b ^ c, 63);                                                                                                                                               \
  } while (0)

static void blake2b_compress(blake2b_ctx *ctx, const uint8_t block[128], int last) {
  uint64_t m[16], v[16];
  for (size_t i = 0; i < 8; ++i)
    v[i] = ctx->h[i];
  for (size_t i = 0; i < 8; ++i)
    v[i + 8] = blake2b_iv[i];
  v[12] ^= ctx->t[0];
  v[13] ^= ctx->t[1];
  if (last)
    v[14] = ~v[14];
  for (size_t i = 0; i < 16; ++i)
    m[i] = ((uint64_t)block[i * 8 + 0]) | ((uint64_t)block[i * 8 + 1] << 8) | ((uint64_t)block[i * 8 + 2] << 16) | ((uint64_t)block[i * 8 + 3] << 24) |
           ((uint64_t)block[i * 8 + 4] << 32) | ((uint64_t)block[i * 8 + 5] << 40) | ((uint64_t)block[i * 8 + 6] << 48) | ((uint64_t)block[i * 8 + 7] << 56);
  for (size_t r = 0; r < 12; ++r) {
    G(v[0], v[4], v[8], v[12], m[blake2b_sigma[r][0]], m[blake2b_sigma[r][1]]);
    G(v[1], v[5], v[9], v[13], m[blake2b_sigma[r][2]], m[blake2b_sigma[r][3]]);
    G(v[2], v[6], v[10], v[14], m[blake2b_sigma[r][4]], m[blake2b_sigma[r][5]]);
    G(v[3], v[7], v[11], v[15], m[blake2b_sigma[r][6]], m[blake2b_sigma[r][7]]);
    G(v[0], v[5], v[10], v[15], m[blake2b_sigma[r][8]], m[blake2b_sigma[r][9]]);
    G(v[1], v[6], v[11], v[12], m[blake2b_sigma[r][10]], m[blake2b_sigma[r][11]]);
    G(v[2], v[7], v[8], v[13], m[blake2b_sigma[r][12]], m[blake2b_sigma[r][13]]);
    G(v[3], v[4], v[9], v[14], m[blake2b_sigma[r][14]], m[blake2b_sigma[r][15]]);
  }
  for (size_t i = 0; i < 8; ++i)
    ctx->h[i] ^= v[i] ^ v[i + 8];
}

static void blake2b_init(blake2b_ctx *ctx, size_t outlen) {
  ctx->outlen = outlen;
  ctx->buflen = 0;
  ctx->t[0] = ctx->t[1] = ctx->f[0] = ctx->f[1] = 0;
  for (size_t i = 0; i < 8; ++i)
    ctx->h[i] = blake2b_iv[i];
  ctx->h[0] ^= 0x01010000 ^ (uint8_t)outlen;
}

static void blake2b_update(blake2b_ctx *ctx, const uint8_t *in, size_t inlen) {
  size_t left = ctx->buflen;
  size_t fill = BLAKE2B_BLOCKBYTES - left;
  if (inlen > fill) {
    ctx->buflen = 0;
    memcpy(ctx->buf + left, in, fill);
    ctx->t[0] += BLAKE2B_BLOCKBYTES;
    if (ctx->t[0] < BLAKE2B_BLOCKBYTES)
      ctx->t[1]++;
    blake2b_compress(ctx, ctx->buf, 0);
    in += fill;
    inlen -= fill;
    while (inlen > BLAKE2B_BLOCKBYTES) {
      ctx->t[0] += BLAKE2B_BLOCKBYTES;
      if (ctx->t[0] < BLAKE2B_BLOCKBYTES)
        ctx->t[1]++;
      blake2b_compress(ctx, in, 0);
      in += BLAKE2B_BLOCKBYTES;
      inlen -= BLAKE2B_BLOCKBYTES;
    }
    left = 0;
  }
  memcpy(ctx->buf + left, in, inlen);
  ctx->buflen = left + inlen;
}

static void blake2b_final(blake2b_ctx *ctx, uint8_t *out) {
  ctx->t[0] += ctx->buflen;
  if (ctx->t[0] < ctx->buflen)
    ctx->t[1]++;
  while (ctx->buflen < BLAKE2B_BLOCKBYTES)
    ctx->buf[ctx->buflen++] = 0;
  blake2b_compress(ctx, ctx->buf, 1);
  for (size_t i = 0; i < ctx->outlen; ++i)
    out[i] = (ctx->h[i >> 3] >> (8 * (i & 7))) & 0xFF;
}

#define BLAKE2S_OUTBYTES 32
#define BLAKE2S_BLOCKBYTES 64

typedef struct {
  uint32_t h[8], t[2], f[2];
  uint8_t buf[64];
  size_t buflen, outlen;
} blake2s_ctx;

static const uint32_t blake2s_iv[8] = {0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU, 0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U};

static const uint8_t blake2s_sigma[10][16] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
                                              {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
                                              {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
                                              {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
                                              {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define G32(a, b, c, d, x, y)                                                                                                                                            \
  do {                                                                                                                                                                   \
    a = a + b + x;                                                                                                                                                       \
    d = ROTR32(d ^ a, 16);                                                                                                                                               \
    c = c + d;                                                                                                                                                           \
    b = ROTR32(b ^ c, 12);                                                                                                                                               \
    a = a + b + y;                                                                                                                                                       \
    d = ROTR32(d ^ a, 8);                                                                                                                                                \
    c = c + d;                                                                                                                                                           \
    b = ROTR32(b ^ c, 7);                                                                                                                                                \
  } while (0)

static void blake2s_compress(blake2s_ctx *ctx, const uint8_t block[64], int last) {
  uint32_t m[16], v[16];
  for (size_t i = 0; i < 8; ++i)
    v[i] = ctx->h[i];
  for (size_t i = 0; i < 8; ++i)
    v[i + 8] = blake2s_iv[i];
  v[12] ^= ctx->t[0];
  v[13] ^= ctx->t[1];
  if (last)
    v[14] = ~v[14];
  for (size_t i = 0; i < 16; ++i)
    m[i] = ((uint32_t)block[i * 4 + 0]) | ((uint32_t)block[i * 4 + 1] << 8) | ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);
  for (size_t r = 0; r < 10; ++r) {
    G32(v[0], v[4], v[8], v[12], m[blake2s_sigma[r][0]], m[blake2s_sigma[r][1]]);
    G32(v[1], v[5], v[9], v[13], m[blake2s_sigma[r][2]], m[blake2s_sigma[r][3]]);
    G32(v[2], v[6], v[10], v[14], m[blake2s_sigma[r][4]], m[blake2s_sigma[r][5]]);
    G32(v[3], v[7], v[11], v[15], m[blake2s_sigma[r][6]], m[blake2s_sigma[r][7]]);
    G32(v[0], v[5], v[10], v[15], m[blake2s_sigma[r][8]], m[blake2s_sigma[r][9]]);
    G32(v[1], v[6], v[11], v[12], m[blake2s_sigma[r][10]], m[blake2s_sigma[r][11]]);
    G32(v[2], v[7], v[8], v[13], m[blake2s_sigma[r][12]], m[blake2s_sigma[r][13]]);
    G32(v[3], v[4], v[9], v[14], m[blake2s_sigma[r][14]], m[blake2s_sigma[r][15]]);
  }
  for (size_t i = 0; i < 8; ++i)
    ctx->h[i] ^= v[i] ^ v[i + 8];
}

static void blake2s_init(blake2s_ctx *ctx, size_t outlen) {
  ctx->outlen = outlen;
  ctx->buflen = 0;
  ctx->t[0] = ctx->t[1] = ctx->f[0] = ctx->f[1] = 0;
  for (size_t i = 0; i < 8; ++i)
    ctx->h[i] = blake2s_iv[i];
  ctx->h[0] ^= 0x01010000 ^ (uint8_t)outlen;
}

static void blake2s_update(blake2s_ctx *ctx, const uint8_t *in, size_t inlen) {
  size_t left = ctx->buflen;
  size_t fill = BLAKE2S_BLOCKBYTES - left;
  if (inlen > fill) {
    ctx->buflen = 0;
    memcpy(ctx->buf + left, in, fill);
    ctx->t[0] += BLAKE2S_BLOCKBYTES;
    if (ctx->t[0] < BLAKE2S_BLOCKBYTES)
      ctx->t[1]++;
    blake2s_compress(ctx, ctx->buf, 0);
    in += fill;
    inlen -= fill;
    while (inlen > BLAKE2S_BLOCKBYTES) {
      ctx->t[0] += BLAKE2S_BLOCKBYTES;
      if (ctx->t[0] < BLAKE2S_BLOCKBYTES)
        ctx->t[1]++;
      blake2s_compress(ctx, in, 0);
      in += BLAKE2S_BLOCKBYTES;
      inlen -= BLAKE2S_BLOCKBYTES;
    }
    left = 0;
  }
  memcpy(ctx->buf + left, in, inlen);
  ctx->buflen = left + inlen;
}

static void blake2s_final(blake2s_ctx *ctx, uint8_t *out) {
  ctx->t[0] += ctx->buflen;
  if (ctx->t[0] < ctx->buflen)
    ctx->t[1]++;
  while (ctx->buflen < BLAKE2S_BLOCKBYTES)
    ctx->buf[ctx->buflen++] = 0;
  blake2s_compress(ctx, ctx->buf, 1);
  for (size_t i = 0; i < ctx->outlen; ++i)
    out[i] = (ctx->h[i >> 2] >> (8 * (i & 3))) & 0xFF;
}
typedef struct {
  uint64_t st[25];
  uint8_t dbuf[200];
  int pt, rsiz;
} shake_ctx;

// --- Keccak-f[1600] permutation ---
static void keccakf(uint64_t st[25]) {
  static const uint64_t RC[24] = {0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL, 0x000000000000808bULL,
                                  0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL, 0x0000000000000088ULL,
                                  0x0000000080008009ULL, 0x000000008000000aULL, 0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
                                  0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
                                  0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
  static const int r[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
  static const int p[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};
  int i, j, k, t;
  uint64_t bc[5], temp;
  for (i = 0; i < 24; i++) {
    // Theta
    for (j = 0; j < 5; j++)
      bc[j] = st[j] ^ st[j + 5] ^ st[j + 10] ^ st[j + 15] ^ st[j + 20];
    for (j = 0; j < 5; j++) {
      temp = bc[(j + 4) % 5] ^ ((bc[(j + 1) % 5] << 1) | (bc[(j + 1) % 5] >> (64 - 1)));
      for (k = 0; k < 25; k += 5)
        st[k + j] ^= temp;
    }
    // Rho and Pi
    temp = st[1];
    for (j = 0; j < 24; j++) {
      k = p[j];
      bc[0] = st[k];
      st[k] = (temp << r[j]) | (temp >> (64 - r[j]));
      temp = bc[0];
    }
    // Chi
    for (k = 0; k < 25; k += 5) {
      for (j = 0; j < 5; j++)
        bc[j] = st[k + j];
      for (j = 0; j < 5; j++)
        st[k + j] ^= (~bc[(j + 1) % 5]) & bc[(j + 2) % 5];
    }
    // Iota
    st[0] ^= RC[i];
  }
}

// --- SHAKE128/256 initialization ---
static void shake128_init(shake_ctx *c) {
  memset(c, 0, sizeof(*c));
  c->rsiz = 168;
}
static void shake256_init(shake_ctx *c) {
  memset(c, 0, sizeof(*c));
  c->rsiz = 136;
}

// --- SHAKE update ---
static void shake_update(shake_ctx *c, const void *data, size_t len) {
  const uint8_t *in = (const uint8_t *)data;
  size_t i;
  for (i = 0; i < len; i++) {
    c->dbuf[c->pt++] ^= in[i];
    if (c->pt >= c->rsiz) {
      for (int j = 0; j < (c->rsiz / 8); j++)
        c->st[j] ^= ((uint64_t *)c->dbuf)[j];
      keccakf(c->st);
      c->pt = 0;
      memset(c->dbuf, 0, c->rsiz);
    }
  }
}

// --- SHAKE finalization / XOF output (arbitrary outlen) ---
static void shake_xof(shake_ctx *c) {
  c->dbuf[c->pt] ^= 0x1F; // SHAKE padding
  c->dbuf[c->rsiz - 1] ^= 0x80;
  for (int j = 0; j < (c->rsiz / 8); j++)
    c->st[j] ^= ((uint64_t *)c->dbuf)[j];
  keccakf(c->st);
  c->pt = 0;
}

static void shake_out(shake_ctx *c, uint8_t *out, size_t outlen) {
  size_t i = 0, j;
  while (i < outlen) {
    if (c->pt >= c->rsiz) {
      keccakf(c->st);
      c->pt = 0;
    }
    for (j = c->pt; j < c->rsiz && i < outlen; j++, i++)
      out[i] = ((uint8_t *)c->st)[j];
    c->pt = j;
  }
}

#endif // HASH_SINGLE_HEADER_H
