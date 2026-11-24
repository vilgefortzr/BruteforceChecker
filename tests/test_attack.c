/* Tests for the attack module.
   Build: cc -std=c11 -Wall -Wextra -Iinclude -o t tests/test_attack.c \
              src/attack.c src/sha256.c && ./t */
#include "attack.h"
#include "sha256.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void target_of(const char *s, uint8_t out[BFC_HASH_LEN]) {
    bfc_sha256_str(s, out);
}

static void write_wordlist(const char *path, const char *const *words) {
    FILE *fp = fopen(path, "w");
    assert(fp != NULL);
    for (int i = 0; words[i]; i++) fprintf(fp, "%s\n", words[i]);
    fclose(fp);
}

int main(void) {
    uint8_t target[BFC_HASH_LEN];

    /* --- brute --- */
    target_of("ab", target);
    bfc_result_t r = bfc_attack_brute(target, BFC_CS_LOWER, 1, 3);
    assert(r.found && strcmp(r.password, "ab") == 0 && r.attempts > 0);
    printf("[ok] brute lower       -> %s (%llu tries)\n", r.password,
           (unsigned long long)r.attempts);

    target_of("x7", target);
    r = bfc_attack_brute(target, BFC_CS_LOWER | BFC_CS_DIGIT, 2, 2);
    assert(r.found && strcmp(r.password, "x7") == 0);
    printf("[ok] brute lower+digit -> %s\n", r.password);

    /* unknown charset / impossible range must not crash, just report not found */
    r = bfc_attack_brute(target, BFC_CS_UPPER, 2, 2);
    assert(!r.found);
    printf("[ok] brute miss        -> not found (%llu tries)\n",
           (unsigned long long)r.attempts);

    /* --- mask --- */
    target_of("Ab3", target);
    r = bfc_attack_mask(target, "?u?l?d");
    assert(r.found && strcmp(r.password, "Ab3") == 0);
    printf("[ok] mask ?u?l?d       -> %s\n", r.password);

    r = bfc_attack_mask(target, "?x?y");   /* bad tokens */
    assert(!r.found && r.attempts == 0);
    printf("[ok] mask bad token    -> rejected\n");

    /* --- dict --- */
    const char *words[] = {"admin", "monkey", "summer", "password", NULL};
    const char *wl = "./_test_wordlist.tmp";
    write_wordlist(wl, words);

    target_of("monkey", target);
    r = bfc_attack_dict(target, wl, 0);
    assert(r.found && strcmp(r.password, "monkey") == 0);
    printf("[ok] dict plain        -> %s\n", r.password);

    /* "Summer2024" must NOT fall without rules, but must WITH rules */
    target_of("Summer2024", target);
    r = bfc_attack_dict(target, wl, 0);
    assert(!r.found);
    r = bfc_attack_dict(target, wl, 1);
    assert(r.found && strcmp(r.password, "Summer2024") == 0);
    printf("[ok] dict +rules       -> %s (%llu tries)\n", r.password,
           (unsigned long long)r.attempts);

    /* leet form: full leet of "password" is "p@$$w0rd" */
    target_of("p@$$w0rd", target);
    r = bfc_attack_dict(target, wl, 1);
    assert(r.found && strcmp(r.password, "p@$$w0rd") == 0);
    printf("[ok] dict leet         -> %s\n", r.password);

    remove(wl);
    printf("All attack.c tests passed.\n");
    return 0;
}
