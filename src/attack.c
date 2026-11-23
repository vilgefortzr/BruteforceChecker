/* brute / dict / mask attacks. Stubs until implemented. */
#include "attack.h"

bfc_result_t bfc_attack_brute(const uint8_t target[BFC_HASH_LEN],
                              int charset, int min_len, int max_len) {
    (void)target; (void)charset; (void)min_len; (void)max_len;
    bfc_result_t r = {0};
    return r;
}

bfc_result_t bfc_attack_dict(const uint8_t target[BFC_HASH_LEN],
                             const char *wordlist_path, int apply_rules) {
    (void)target; (void)wordlist_path; (void)apply_rules;
    bfc_result_t r = {0};
    return r;
}

bfc_result_t bfc_attack_mask(const uint8_t target[BFC_HASH_LEN],
                             const char *mask) {
    (void)target; (void)mask;
    bfc_result_t r = {0};
    return r;
}
