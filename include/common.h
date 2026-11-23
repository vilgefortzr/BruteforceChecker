#ifndef BFC_COMMON_H
#define BFC_COMMON_H
#include <stdint.h>
#include <stddef.h>

#define BFC_HASH_LEN      32   /* SHA-256 digest size, bytes */
#define BFC_HASH_HEX_LEN  64   /* hex string length, excluding NUL */
#define BFC_MAX_PASSWORD  128

/* Character classes for brute / mask attacks (bit flags). */
typedef enum {
    BFC_CS_LOWER  = 1 << 0,
    BFC_CS_UPPER  = 1 << 1,
    BFC_CS_DIGIT  = 1 << 2,
    BFC_CS_SYMBOL = 1 << 3
} bfc_charset_t;

typedef struct {
    int      found;                       /* 1 if cracked */
    char     password[BFC_MAX_PASSWORD];  /* recovered password when found */
    uint64_t attempts;
    double   seconds;
} bfc_result_t;

#endif /* BFC_COMMON_H */
