#ifndef BFC_ATTACK_H
#define BFC_ATTACK_H
#include "common.h"

/* Brute force: every charset combination of length min_len..max_len. */
bfc_result_t bfc_attack_brute(const uint8_t target[BFC_HASH_LEN],
                              int charset, int min_len, int max_len);

/* Dictionary attack; apply_rules adds leet / capitalization / digit-year suffixes. */
bfc_result_t bfc_attack_dict(const uint8_t target[BFC_HASH_LEN],
                             const char *wordlist_path, int apply_rules);

/* Mask attack over tokens ?l ?u ?d ?s, e.g. "?u?l?l?l?d?d". */
bfc_result_t bfc_attack_mask(const uint8_t target[BFC_HASH_LEN],
                             const char *mask);

#endif /* BFC_ATTACK_H */
