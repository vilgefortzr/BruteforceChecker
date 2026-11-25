/* Password strength analysis and SHA-256 hash-rate benchmarks. */
#define _POSIX_C_SOURCE 199309L

#include "analyze.h"
#include "sha256.h"

#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

/* Common base words used to penalize "looks complex but is a known word
 * in disguise" passwords (e.g. "P@ssw0rd"). Separate from the leak list. */
static const char *const BFC_COMMON_BASE_WORDS[] = {
    "password", "qwerty", "qwerty123", "admin", "welcome", "login",
    "dragon", "monkey", "master", "summer", "winter", "autumn", "spring",
    "football", "baseball", "superman", "letmein", "trustno1",
    "iloveyou", "princess", "sunshine", "shadow", "michael", "ninja",
    "azerty", "abc123", "123456", "passw0rd", "starwars", "freedom",
    "whatever", "hello", "charlie", "donald", "batman", "access",
    NULL
};

/* Monotonic-ish wall clock in seconds. */
static double bfc_now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Lowercase + de-leet a password into `out` (out must hold at least
 * BFC_MAX_PASSWORD bytes). Leet substitutions: a<-@/4, o<-0, i<-1/!,
 * e<-3, s<-$/5, t<-7. Everything else is copied as lowercase. */
static void bfc_deleet_lower(const char *in, char *out, size_t out_cap) {
    size_t i = 0;
    for (; in[i] != '\0' && i + 1 < out_cap; i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
            case '@': case '4': out[i] = 'a'; break;
            case '0':           out[i] = 'o'; break;
            case '1': case '!': out[i] = 'i'; break;
            case '3':           out[i] = 'e'; break;
            case '$': case '5': out[i] = 's'; break;
            case '7':           out[i] = 't'; break;
            default:            out[i] = (char)tolower(c); break;
        }
    }
    out[i] = '\0';
}

/* Strip leading/trailing characters that are not a-z, returning the
 * core substring bounds via start/len (used after de-leeting, to peel
 * off trailing digits/punctuation like "2024", "!!", etc.). */
static void bfc_alpha_core(const char *s, size_t *start, size_t *len) {
    size_t n = strlen(s);
    size_t b = 0, e = n;
    while (b < n && !(s[b] >= 'a' && s[b] <= 'z')) b++;
    while (e > b && !(s[e - 1] >= 'a' && s[e - 1] <= 'z')) e--;
    *start = b;
    *len = (e > b) ? (e - b) : 0;
}

/* Returns 1 if the de-leeted, de-suffixed core of `password` matches one
 * of BFC_COMMON_BASE_WORDS (a cheap "known word in disguise" check). */
static int bfc_looks_like_common_word(const char *password) {
    char deleeted[BFC_MAX_PASSWORD];
    bfc_deleet_lower(password, deleeted, sizeof(deleeted));

    size_t start, len;
    bfc_alpha_core(deleeted, &start, &len);
    if (len == 0) return 0;

    for (int i = 0; BFC_COMMON_BASE_WORDS[i] != NULL; i++) {
        size_t wl = strlen(BFC_COMMON_BASE_WORDS[i]);
        if (wl == len && strncmp(deleeted + start, BFC_COMMON_BASE_WORDS[i], wl) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Counts trailing ASCII digits in s. */
static size_t bfc_trailing_digit_count(const char *s) {
    size_t n = strlen(s);
    size_t count = 0;
    while (n > 0 && isdigit((unsigned char)s[n - 1])) {
        n--;
        count++;
    }
    return count;
}

/* Trims a trailing '\n' / '\r' (as read from a leak-list file line). */
static void bfc_trim_newline(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

/* Checks whether `password` appears, line-for-line, in the file at
 * leak_list_path. Returns 1 if found, 0 if not found or the file is
 * absent (a missing leak list is not a hard error here). Reads the
 * file line by line, never loading it fully into RAM. */
static int bfc_check_leak_list(const char *password, const char *leak_list_path) {
    if (leak_list_path == NULL) return 0;

    FILE *fp = fopen(leak_list_path, "r");
    if (fp == NULL) return 0;

    char line[BFC_MAX_PASSWORD];
    int found = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        bfc_trim_newline(line);
        if (strcmp(line, password) == 0) {
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found;
}

/* ------------------------------------------------------------------ */
/* Public API (include/analyze.h)                                      */
/* ------------------------------------------------------------------ */

bfc_strength_t bfc_analyze(const char *password, const char *leak_list_path) {
    bfc_strength_t result;
    memset(&result, 0, sizeof(result));

    if (password == NULL) {
        snprintf(result.verdict, sizeof(result.verdict), "very weak");
        return result;
    }

    size_t length = strlen(password);
    if (length == 0) {
        snprintf(result.verdict, sizeof(result.verdict), "very weak");
        return result;
    }

    /* 1. Which character classes are actually used? */
    int has_lower = 0, has_upper = 0, has_digit = 0, has_symbol = 0;
    for (size_t i = 0; i < length; i++) {
        unsigned char c = (unsigned char)password[i];
        if (islower(c))       has_lower = 1;
        else if (isupper(c))  has_upper = 1;
        else if (isdigit(c))  has_digit = 1;
        else                  has_symbol = 1;
    }

    int alphabet_size = 0;
    if (has_lower)  alphabet_size += 26;
    if (has_upper)  alphabet_size += 26;
    if (has_digit)  alphabet_size += 10;
    if (has_symbol) alphabet_size += 32; /* approx printable symbol set */
    if (alphabet_size == 0) alphabet_size = 1; /* defensive, avoids log2(0) */

    double raw_entropy_bits = (double)length * log2((double)alphabet_size);

    /* 2. Predictability penalties (still an *estimate*, not a proof). */
    double penalty_bits = 0.0;

    /* Only-lowercase, short password: classic weak pattern. */
    if (has_lower && !has_upper && !has_digit && !has_symbol && length <= 8) {
        penalty_bits += 8.0;
    }

    /* Digits bunched at the end (e.g. "word123", "word2024") carry far
     * less real entropy than their count * log2(10) suggests, because
     * the attacker tries common suffixes first (years, 0-99, 000-999). */
    size_t suffix_digits = bfc_trailing_digit_count(password);
    if (suffix_digits > 0 && suffix_digits < length) {
        double suffix_bits = (double)suffix_digits * log2(10.0);
        penalty_bits += suffix_bits * 0.7; /* keep a small residual */
    }

    /* Leet-spelled / capitalized known word (e.g. "P@ssw0rd"). */
    if (bfc_looks_like_common_word(password)) {
        penalty_bits += raw_entropy_bits * 0.6; /* heavy cut: it's a dictionary hit in disguise */
    }

    double entropy_bits = raw_entropy_bits - penalty_bits;
    if (entropy_bits < 0.0) entropy_bits = 0.0;
    result.entropy_bits = entropy_bits;

    /* 3. Keyspace: size of the brute-force space implied by what's used.
     * (double, since alphabet^length overflows any integer type quickly) */
    result.keyspace = pow((double)alphabet_size, (double)length);

    /* 4. Leak list membership. */
    result.in_leak_list = bfc_check_leak_list(password, leak_list_path);

    /* 5. Crack-time models. */
    result.crack_online = result.keyspace / 10.0; /* ~10 attempts/sec, rate-limited */

    double hashrate = bfc_bench_hashrate();
    if (hashrate <= 0.0) hashrate = 1.0; /* defensive floor, avoids div-by-zero */
    result.crack_cpu = result.keyspace / hashrate;

    result.crack_gpu = result.keyspace / 1e10; /* assumed ~10 GH/s commodity GPU, order-of-magnitude only */

    /* 6. Verdict from entropy, overridden by leak-list membership. */
    const char *verdict;
    if (result.in_leak_list) {
        verdict = "very weak";
    } else if (entropy_bits < 28.0) {
        verdict = "very weak";
    } else if (entropy_bits < 36.0) {
        verdict = "weak";
    } else if (entropy_bits < 60.0) {
        verdict = "moderate";
    } else {
        verdict = "strong";
    }
    snprintf(result.verdict, sizeof(result.verdict), "%s", verdict);

    return result;
}

double bfc_bench_hashrate(void) {
    const char *probe = "bfc-benchmark-probe";
    uint8_t out[BFC_HASH_LEN];

    const double budget_seconds = 0.25; /* keep --analyze snappy */
    uint64_t count = 0;

    double start = bfc_now_seconds();
    double elapsed;
    do {
        bfc_sha256_str(probe, out);
        count++;
        elapsed = bfc_now_seconds() - start;
    } while (elapsed < budget_seconds);

    if (elapsed <= 0.0) return 0.0;
    return (double)count / elapsed;
}

void bfc_bench_stretch(uint32_t iterations, double *raw_hps, double *stretched_hps) {
    if (raw_hps == NULL || stretched_hps == NULL) return;

    const char *password = "bfc-benchmark-probe";
    const char *salt = "bfc-benchmark-salt";
    uint8_t out[BFC_HASH_LEN];

    const double budget_seconds = 0.25;

    /* Raw SHA-256 throughput. */
    {
        uint64_t count = 0;
        double start = bfc_now_seconds();
        double elapsed;
        do {
            bfc_sha256_str(password, out);
            count++;
            elapsed = bfc_now_seconds() - start;
        } while (elapsed < budget_seconds);
        *raw_hps = (elapsed > 0.0) ? (double)count / elapsed : 0.0;
    }

    /* Stretched throughput: each "hash" here costs `iterations` SHA-256
     * rounds, so far fewer of them fit in the same time budget. */
    {
        if (iterations == 0) iterations = 1;
        uint64_t count = 0;
        double start = bfc_now_seconds();
        double elapsed;
        do {
            bfc_sha256_stretch(password, salt, iterations, out);
            count++;
            elapsed = bfc_now_seconds() - start;
        } while (elapsed < budget_seconds);
        *stretched_hps = (elapsed > 0.0) ? (double)count / elapsed : 0.0;
    }
}
