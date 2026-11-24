#ifndef BFC_CLI_H
#define BFC_CLI_H
#include "common.h"
#include "analyze.h"

typedef enum {
    MODE_NONE, MODE_BRUTE, MODE_DICT, MODE_MASK,
    MODE_ANALYZE, MODE_DEFEND, MODE_HELP
} bfc_mode_t;

typedef struct {
    bfc_mode_t mode;
    char       target_hex[BFC_HASH_HEX_LEN + 1];
    char       password[BFC_MAX_PASSWORD];
    int        charset;
    int        min_len, max_len;
    char       mask[64];
    char       wordlist_path[256];
    char       leak_list_path[256];
    uint32_t   iterations;
    int        apply_rules;
} bfc_options_t;

/* Parses argv into opt. Returns 0 on success, !=0 on error. */
int  bfc_parse_args(int argc, char **argv, bfc_options_t *opt);

void bfc_print_result(const bfc_result_t *r);
void bfc_print_strength(const bfc_strength_t *s);
void bfc_print_usage(void);

#endif /* BFC_CLI_H */
