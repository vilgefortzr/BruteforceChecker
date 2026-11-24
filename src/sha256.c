/* SHA-256 adapted from Edward Eldridge's implementation
   (https://github.com/EddieEldridge/SHA256-in-C, per FIPS 180-4). */
   
#include "sha256.h"
#include <string.h>
#include <stdlib.h>

#define byteSwap32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | \
                       (((x) & 0x0000FF00) << 8) | ((x) << 24))
#define byteSwap64(x)                                                       \
    ((((x) >> 56) & 0x00000000000000FFULL) | (((x) >> 40) & 0x000000000000FF00ULL) | \
     (((x) >> 24) & 0x0000000000FF0000ULL) | (((x) >> 8)  & 0x00000000FF000000ULL) | \
     (((x) << 8)  & 0x000000FF00000000ULL) | (((x) << 24) & 0x0000FF0000000000ULL) | \
     (((x) << 40) & 0x00FF000000000000ULL) | (((x) << 56) & 0xFF00000000000000ULL))

union messageBlock {
    uint8_t  e[64];
    uint32_t t[16];
    uint64_t s[8];
};

enum status { READ, PAD0, PAD1, FINISH };

static int is_little_endian(void) {
    int num = 1;
    return *(char *)&num == 1;
}

static uint32_t rotr(uint32_t x, uint16_t n) { return (x >> n) | (x << (32 - n)); }
static uint32_t shr(uint32_t x, uint16_t n)  { return x >> n; }

static uint32_t sig0(uint32_t x) { return rotr(x, 7)  ^ rotr(x, 18) ^ shr(x, 3); }
static uint32_t sig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10); }
static uint32_t SIG0(uint32_t x) { return rotr(x, 2)  ^ rotr(x, 13) ^ rotr(x, 22); }
static uint32_t SIG1(uint32_t x) { return rotr(x, 6)  ^ rotr(x, 11) ^ rotr(x, 25); }

static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)  { return (x & y) ^ (~x & z); }
static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Walks data as 64-byte blocks, emitting SHA-256 padding on the way out.
   Returns 1 while a block is available, 0 once finished. */
static int next_block(const uint8_t *data, size_t len, size_t *pos,
                      union messageBlock *mb, enum status *state, uint64_t *numBits) {
    if (*state == FINISH) return 0;

    if (*state == PAD0 || *state == PAD1) {
        for (size_t i = 0; i < 56; i++) mb->e[i] = 0x00;
        if (*state == PAD1) mb->e[0] = 0x80;
        mb->s[7] = is_little_endian() ? byteSwap64(*numBits) : *numBits;
        *state = FINISH;
        return 1;
    }

    size_t avail = len - *pos;
    size_t n = avail < 64 ? avail : 64;
    memcpy(mb->e, data + *pos, n);
    *pos += n;
    *numBits += (uint64_t)n * 8;

    if (n < 56) {
        mb->e[n] = 0x80;
        for (size_t i = n + 1; i < 56; i++) mb->e[i] = 0x00;
        mb->s[7] = is_little_endian() ? byteSwap64(*numBits) : *numBits;
        *state = FINISH;
    } else if (n < 64) {
        mb->e[n] = 0x80;
        for (size_t i = n + 1; i < 64; i++) mb->e[i] = 0x00;
        *state = PAD0;
    } else if (*pos == len) {
        *state = PAD1;   /* length is a multiple of 64; pad in a fresh block */
    }
    return 1;
}

static void sha256_compress(uint32_t H[8], const union messageBlock *mb) {
    uint32_t W[64], a, b, c, d, e, f, g, h, T1, T2;
    int j;

    for (j = 0; j < 16; j++)
        W[j] = is_little_endian() ? byteSwap32(mb->t[j]) : mb->t[j];
    for (j = 16; j < 64; j++)
        W[j] = sig1(W[j - 2]) + W[j - 7] + sig0(W[j - 15]) + W[j - 16];

    a = H[0]; b = H[1]; c = H[2]; d = H[3];
    e = H[4]; f = H[5]; g = H[6]; h = H[7];

    for (j = 0; j < 64; j++) {
        T1 = h + SIG1(e) + Ch(e, f, g) + K[j] + W[j];
        T2 = SIG0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

void bfc_sha256(const uint8_t *data, size_t len, uint8_t out[BFC_HASH_LEN]) {
    if (out == NULL || (data == NULL && len != 0)) return;

    uint32_t H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    union messageBlock mb;
    enum status state = READ;
    uint64_t numBits = 0;
    size_t pos = 0;

    while (next_block(data, len, &pos, &mb, &state, &numBits))
        sha256_compress(H, &mb);

    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(H[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(H[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(H[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(H[i]);
    }
}

void bfc_sha256_str(const char *str, uint8_t out[BFC_HASH_LEN]) {
    if (str == NULL || out == NULL) return;
    bfc_sha256((const uint8_t *)str, strlen(str), out);
}

void bfc_hex_encode(const uint8_t in[BFC_HASH_LEN], char out[BFC_HASH_HEX_LEN + 1]) {
    static const char digits[] = "0123456789abcdef";
    if (in == NULL || out == NULL) return;
    for (int i = 0; i < BFC_HASH_LEN; i++) {
        out[i * 2]     = digits[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = digits[in[i] & 0xF];
    }
    out[BFC_HASH_HEX_LEN] = '\0';
}

static int hex_nibble(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

int bfc_hex_decode(const char *hex, uint8_t out[BFC_HASH_LEN]) {
    if (hex == NULL || out == NULL || strlen(hex) != BFC_HASH_HEX_LEN) return 1;
    for (int i = 0; i < BFC_HASH_LEN; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

void bfc_sha256_stretch(const char *password, const char *salt,
                        uint32_t iterations, uint8_t out[BFC_HASH_LEN]) {
    if (password == NULL || out == NULL) return;
    if (iterations == 0) iterations = 1;

    size_t slen = (salt != NULL) ? strlen(salt) : 0;
    size_t plen = strlen(password);
    uint8_t digest[BFC_HASH_LEN];

    /* First round over salt||password, then iterate over the digest. */
    uint8_t *buf = (uint8_t *)malloc(slen + plen);
    if (buf == NULL) return;
    if (slen) memcpy(buf, salt, slen);
    memcpy(buf + slen, password, plen);
    bfc_sha256(buf, slen + plen, digest);
    free(buf);

    for (uint32_t i = 1; i < iterations; i++)
        bfc_sha256(digest, BFC_HASH_LEN, digest);

    memcpy(out, digest, BFC_HASH_LEN);
}
