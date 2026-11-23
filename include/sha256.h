#ifndef BFC_SHA256_H
#define BFC_SHA256_H
#include "common.h"

void bfc_sha256(const uint8_t *data, size_t len, uint8_t out[BFC_HASH_LEN]);
void bfc_sha256_str(const char *str, uint8_t out[BFC_HASH_LEN]);

void bfc_hex_encode(const uint8_t in[BFC_HASH_LEN], char out[BFC_HASH_HEX_LEN + 1]);
int  bfc_hex_decode(const char *hex, uint8_t out[BFC_HASH_LEN]);

/* SHA-256 iterated `iterations` times over salt||password (iterations >= 1). */
void bfc_sha256_stretch(const char *password, const char *salt,
                        uint32_t iterations, uint8_t out[BFC_HASH_LEN]);

#endif /* BFC_SHA256_H */
