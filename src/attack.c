/* brute / dict / mask attacks.
   Each generates password candidates, hashes them with bfc_sha256 and
   compares against target; stops at the first match. */
#define _POSIX_C_SOURCE 199309L

#include "attack.h"
#include "sha256.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define BFC_CS_ALL_SYMBOLS " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

static const char CS_LOWER[]  = "abcdefghijklmnopqrstuvwxyz";
static const char CS_UPPER[]  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char CS_DIGIT[]  = "0123456789";
static const char CS_SYMBOL[] = BFC_CS_ALL_SYMBOLS;

static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

#define BFC_PROGRESS_STEP (1u << 22)   /* ~4.2M candidates between updates */

/* Live progress line on stderr; stdout stays clean for the final result. */
static void show_progress(const char *label, uint64_t attempts, double t0) {
    double elapsed = now_seconds() - t0;
    double mps = (elapsed > 0.0) ? (double)attempts / elapsed / 1e6 : 0.0;
    fprintf(stderr, "\r[%s] %llu candidates tried, %.2f M/s ...   ",
            label, (unsigned long long)attempts, mps);
    fflush(stderr);
}

/* Builds the working alphabet from a bfc_charset_t bitmask. Returns its size. */
static int build_alphabet(int charset, char *out) {
    int n = 0;
    if (charset & BFC_CS_LOWER)  for (const char *p = CS_LOWER;  *p; p++) out[n++] = *p;
    if (charset & BFC_CS_UPPER)  for (const char *p = CS_UPPER;  *p; p++) out[n++] = *p;
    if (charset & BFC_CS_DIGIT)  for (const char *p = CS_DIGIT;  *p; p++) out[n++] = *p;
    if (charset & BFC_CS_SYMBOL) for (const char *p = CS_SYMBOL; *p; p++) out[n++] = *p;
    return n;
}

/* Hashes one candidate and compares with target. Bumps *attempts.
   On match, fills result and returns 1. */
static int try_candidate(const uint8_t target[BFC_HASH_LEN], const char *candidate,
                         uint64_t *attempts, bfc_result_t *result) {
    uint8_t hash[BFC_HASH_LEN];
    bfc_sha256_str(candidate, hash);
    (*attempts)++;
    if (memcmp(hash, target, BFC_HASH_LEN) == 0) {
        result->found = 1;
        snprintf(result->password, sizeof(result->password), "%.*s",
                 (int)(sizeof(result->password) - 1), candidate);
        return 1;
    }
    return 0;
}

/* Odometer over per-position alphabets: tries every combination of the
   given length. positions[i] is the alphabet for column i, sizes[i] its
   length. Returns 1 if a match was found (result filled). */
static int sweep(const uint8_t target[BFC_HASH_LEN], const char *const *positions,
                 const int *sizes, int length, uint64_t *attempts,
                 double t0, const char *label, bfc_result_t *result) {
    int idx[BFC_MAX_PASSWORD];
    char candidate[BFC_MAX_PASSWORD];
    for (int i = 0; i < length; i++) idx[i] = 0;

    for (;;) {
        for (int i = 0; i < length; i++) candidate[i] = positions[i][idx[i]];
        candidate[length] = '\0';
        if (try_candidate(target, candidate, attempts, result)) return 1;
        if ((*attempts & (BFC_PROGRESS_STEP - 1)) == 0) show_progress(label, *attempts, t0);

        int pos = length - 1;
        while (pos >= 0) {
            if (++idx[pos] < sizes[pos]) break;
            idx[pos] = 0;
            pos--;
        }
        if (pos < 0) return 0;   /* wrapped around: whole space exhausted */
    }
}

bfc_result_t bfc_attack_brute(const uint8_t target[BFC_HASH_LEN],
                              int charset, int min_len, int max_len) {
    bfc_result_t r = {0};
    if (target == NULL) return r;

    char alphabet[128];
    int asize = build_alphabet(charset, alphabet);
    if (asize == 0) return r;

    if (min_len < 1) min_len = 1;
    if (max_len > BFC_MAX_PASSWORD - 1) max_len = BFC_MAX_PASSWORD - 1;

    /* Same alphabet on every column; sweep() reads it through pointers. */
    const char *positions[BFC_MAX_PASSWORD];
    int sizes[BFC_MAX_PASSWORD];
    for (int i = 0; i < BFC_MAX_PASSWORD; i++) { positions[i] = alphabet; sizes[i] = asize; }

    uint64_t attempts = 0;
    double t0 = now_seconds();
    for (int len = min_len; len <= max_len; len++) {
        if (sweep(target, positions, sizes, len, &attempts, t0, "brute", &r)) break;
    }
    if (attempts >= BFC_PROGRESS_STEP) fputc('\n', stderr);
    r.attempts = attempts;
    r.seconds = now_seconds() - t0;
    return r;
}

/* ---- dictionary rules ---------------------------------------------------- */

/* Single-pass leet map (a->@, o->0, s->$, i->1) over lowercase letters. */
static void leet(const char *in, char *out, size_t cap) {
    size_t i = 0;
    for (; in[i] && i + 1 < cap; i++) {
        switch (in[i]) {
            case 'a': out[i] = '@'; break;
            case 'o': out[i] = '0'; break;
            case 's': out[i] = '$'; break;
            case 'i': out[i] = '1'; break;
            default:  out[i] = in[i]; break;
        }
    }
    out[i] = '\0';
}

static void capitalize_first(const char *in, char *out, size_t cap) {
    snprintf(out, cap, "%s", in);
    if (out[0] >= 'a' && out[0] <= 'z') out[0] = (char)(out[0] - 'a' + 'A');
}

/* Base forms of a word: original, capitalized, and the leet of each.
   Duplicates are dropped. Returns the count written to forms[]. */
static int build_forms(const char *word, char forms[][BFC_MAX_PASSWORD]) {
    int n = 0;
    snprintf(forms[n++], BFC_MAX_PASSWORD, "%s", word);
    capitalize_first(word, forms[n], BFC_MAX_PASSWORD);
    if (strcmp(forms[n], forms[0]) != 0) n++;

    int base_count = n;
    for (int i = 0; i < base_count; i++) {
        char buf[BFC_MAX_PASSWORD];
        leet(forms[i], buf, sizeof(buf));
        if (strcmp(buf, forms[i]) == 0) continue;     /* leet changed nothing */
        int dup = 0;
        for (int j = 0; j < n; j++) if (strcmp(buf, forms[j]) == 0) { dup = 1; break; }
        if (!dup) snprintf(forms[n++], BFC_MAX_PASSWORD, "%s", buf);
    }
    return n;
}

/* Tries a form with every numeric suffix (none, 0-9, 00-99, 1990-2026). */
static int try_with_suffixes(const uint8_t target[BFC_HASH_LEN], const char *form,
                             uint64_t *attempts, bfc_result_t *result) {
    char cand[BFC_MAX_PASSWORD];
    const int cap = (int)(sizeof(cand) - 6);   /* leave room for a 4-digit suffix */

    if (try_candidate(target, form, attempts, result)) return 1;
    for (int d = 0; d <= 9; d++) {
        snprintf(cand, sizeof(cand), "%.*s%d", cap, form, d);
        if (try_candidate(target, cand, attempts, result)) return 1;
    }
    for (int d = 0; d <= 99; d++) {
        snprintf(cand, sizeof(cand), "%.*s%02d", cap, form, d);
        if (try_candidate(target, cand, attempts, result)) return 1;
    }
    for (int y = 1990; y <= 2026; y++) {
        snprintf(cand, sizeof(cand), "%.*s%d", cap, form, y);
        if (try_candidate(target, cand, attempts, result)) return 1;
    }
    return 0;
}

bfc_result_t bfc_attack_dict(const uint8_t target[BFC_HASH_LEN],
                             const char *wordlist_path, int apply_rules) {
    bfc_result_t r = {0};
    if (target == NULL || wordlist_path == NULL) return r;

    FILE *fp = fopen(wordlist_path, "r");
    if (fp == NULL) return r;

    uint64_t attempts = 0;
    double t0 = now_seconds();
    char line[BFC_MAX_PASSWORD];

    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;

        if (!apply_rules) {
            if (try_candidate(target, line, &attempts, &r)) break;
            continue;
        }

        char forms[4][BFC_MAX_PASSWORD];
        int nforms = build_forms(line, forms);
        int hit = 0;
        for (int i = 0; i < nforms && !hit; i++)
            hit = try_with_suffixes(target, forms[i], &attempts, &r);
        if (hit) break;
    }

    fclose(fp);
    r.attempts = attempts;
    r.seconds = now_seconds() - t0;
    return r;
}

bfc_result_t bfc_attack_mask(const uint8_t target[BFC_HASH_LEN], const char *mask) {
    bfc_result_t r = {0};
    if (target == NULL || mask == NULL) return r;

    const char *positions[BFC_MAX_PASSWORD];
    int sizes[BFC_MAX_PASSWORD];
    int length = 0;

    for (const char *p = mask; *p; ) {
        if (*p != '?' || p[1] == '\0' || length >= BFC_MAX_PASSWORD - 1) return r;
        switch (p[1]) {
            case 'l': positions[length] = CS_LOWER;  sizes[length] = 26; break;
            case 'u': positions[length] = CS_UPPER;  sizes[length] = 26; break;
            case 'd': positions[length] = CS_DIGIT;  sizes[length] = 10; break;
            case 's': positions[length] = CS_SYMBOL; sizes[length] = (int)(sizeof(CS_SYMBOL) - 1); break;
            default:  return r;   /* unknown token */
        }
        length++;
        p += 2;
    }
    if (length == 0) return r;

    uint64_t attempts = 0;
    double t0 = now_seconds();
    sweep(target, positions, sizes, length, &attempts, t0, "mask", &r);
    if (attempts >= BFC_PROGRESS_STEP) fputc('\n', stderr);
    r.attempts = attempts;
    r.seconds = now_seconds() - t0;
    return r;
}
