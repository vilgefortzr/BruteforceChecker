/* cli.c -- argument parsing and console output*/
#include "cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BFC_DEFAULT_WORDLIST   "data/wordlist.txt"
#define BFC_DEFAULT_LEAK_LIST  "data/leaks.txt"
#define BFC_DEFAULT_MIN_LEN    1
#define BFC_DEFAULT_MAX_LEN    6
#define BFC_DEFAULT_ITERATIONS 100000u

static int bfc_copy_bounded(char *dst, size_t dst_cap, const char *src) {
    size_t full_len = strlen(src);
    size_t len = full_len;
    if (len >= dst_cap) {
        len = dst_cap - 1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return (len < full_len) ? 1 : 0;
}

/* Returns 1 if every character of s is a valid hex digit and s is not
 * empty, 0 otherwise*/
static int bfc_is_hex_string(const char *s) {
    if (s == NULL || s[0] == '\0') return 0;
    for (size_t i = 0; s[i] != '\0'; i++) {
        char c = s[i];
        int is_hex = (c >= '0' && c <= '9') ||
                     (c >= 'a' && c <= 'f') ||
                     (c >= 'A' && c <= 'F');
        if (!is_hex) return 0;
    }
    return 1;
}

static int bfc_parse_charset(const char *value, int *out) {
    int mask = 0;
    for (size_t i = 0; value[i] != '\0'; i++) {
        switch (value[i]) {
            case 'l': mask |= BFC_CS_LOWER;  break;
            case 'u': mask |= BFC_CS_UPPER;  break;
            case 'd': mask |= BFC_CS_DIGIT;  break;
            case 's': mask |= BFC_CS_SYMBOL; break;
            default:
                fprintf(stderr,
                        "error: unknown charset character '%c' (use letters from \"luds\")\n",
                        value[i]);
                return 1;
        }
    }
    if (mask == 0) {
        fprintf(stderr, "error: --charset must not be empty\n");
        return 1;
    }
    *out = mask;
    return 0;
}

/* Parses a non-negative integer argument*/
static int bfc_parse_uint(const char *value, const char *flag_name, long *out) {
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == value || *end != '\0' || parsed < 0) {
        fprintf(stderr, "error: %s expects a non-negative number, got \"%s\"\n",
                flag_name, value);
        return 1;
    }
    *out = parsed;
    return 0;
}

/* Returns the next argv value for a flag that requires one, or NULL*/
static const char *bfc_next_value(int argc, char **argv, int i, const char *flag_name) {
    if (i + 1 >= argc) {
        fprintf(stderr, "error: %s requires a value\n", flag_name);
        return NULL;
    }
    return argv[i + 1];
}

/* Formats a duration in seconds into a short, human-readable string*/
static void bfc_format_duration(double seconds, char *buf, size_t cap) {
    if (seconds < 0.0) seconds = 0.0;

    const double SEC_PER_MIN  = 60.0;
    const double SEC_PER_HOUR = 60.0 * SEC_PER_MIN;
    const double SEC_PER_DAY  = 24.0 * SEC_PER_HOUR;
    const double SEC_PER_YEAR = 365.25 * SEC_PER_DAY;

    if (seconds < 1.0) {
        snprintf(buf, cap, "%.3f sec (practically instant)", seconds);
    } else if (seconds < SEC_PER_MIN) {
        snprintf(buf, cap, "%.1f sec", seconds);
    } else if (seconds < SEC_PER_HOUR) {
        snprintf(buf, cap, "%.1f min", seconds / SEC_PER_MIN);
    } else if (seconds < SEC_PER_DAY) {
        snprintf(buf, cap, "%.1f hours", seconds / SEC_PER_HOUR);
    } else if (seconds < SEC_PER_YEAR) {
        snprintf(buf, cap, "%.1f days", seconds / SEC_PER_DAY);
    } else {
        double years = seconds / SEC_PER_YEAR;
        if (years > 1e6) {
            snprintf(buf, cap, "%.2e years", years);
        } else {
            snprintf(buf, cap, "%.1f years", years);
        }
    }
}

int bfc_parse_args(int argc, char **argv, bfc_options_t *opt) {
    if (opt == NULL) {
        fprintf(stderr, "error: internal error (opt is NULL)\n");
        return 1;
    }

    memset(opt, 0, sizeof(*opt));
    opt->mode = MODE_NONE;
    opt->min_len = BFC_DEFAULT_MIN_LEN;
    opt->max_len = BFC_DEFAULT_MAX_LEN;
    opt->iterations = BFC_DEFAULT_ITERATIONS;
    opt->charset = BFC_CS_LOWER | BFC_CS_UPPER | BFC_CS_DIGIT | BFC_CS_SYMBOL;
    bfc_copy_bounded(opt->wordlist_path, sizeof(opt->wordlist_path), BFC_DEFAULT_WORDLIST);
    bfc_copy_bounded(opt->leak_list_path, sizeof(opt->leak_list_path), BFC_DEFAULT_LEAK_LIST);

    if (argc <= 1) {
        fprintf(stderr, "error: no mode given, see --help\n");
        return 1;
    }

    int mode_given = 0;
    int mask_flag_seen = 0;
    
    long tmp = 0;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--help") == 0) {
            opt->mode = MODE_HELP;
            return 0;
        } else if (strcmp(arg, "--brute") == 0) {
            opt->mode = MODE_BRUTE;
            mode_given = 1;
        } else if (strcmp(arg, "--dict") == 0) {
            opt->mode = MODE_DICT;
            mode_given = 1;
        } else if (strcmp(arg, "--mask") == 0) {
            if (!mask_flag_seen) {
                /* 1st occurrence: selects the mode, per §4 of the SPEC. */
                opt->mode = MODE_MASK;
                mode_given = 1;
                mask_flag_seen = 1;
            } else {
                /* 2nd occurrence: carries the mask pattern value. */
                const char *v = bfc_next_value(argc, argv, i, "--mask");
                if (v == NULL) return 1;
                i++;
                if (bfc_copy_bounded(opt->mask, sizeof(opt->mask), v)) {
                    fprintf(stderr, "error: --mask pattern is too long\n");
                    return 1;
                }
            }
        } else if (strcmp(arg, "--analyze") == 0) {
            opt->mode = MODE_ANALYZE;
            mode_given = 1;
        } else if (strcmp(arg, "--defend") == 0) {
            opt->mode = MODE_DEFEND;
            mode_given = 1;
        } else if (strcmp(arg, "--rules") == 0) {
            opt->apply_rules = 1;
        } else if (strcmp(arg, "--hash") == 0) {
            const char *v = bfc_next_value(argc, argv, i, "--hash");
            if (v == NULL) return 1;
            i++;
            if (strlen(v) != BFC_HASH_HEX_LEN || !bfc_is_hex_string(v)) {
                fprintf(stderr,
                        "error: --hash must be exactly %d hex characters, got \"%s\"\n",
                        BFC_HASH_HEX_LEN, v);
                return 1;
            }
            bfc_copy_bounded(opt->target_hex, sizeof(opt->target_hex), v);
        } else if (strcmp(arg, "--password") == 0) {
            const char *v = bfc_next_value(argc, argv, i, "--password");
            if (v == NULL) return 1;
            i++;
            if (bfc_copy_bounded(opt->password, sizeof(opt->password), v)) {
                fprintf(stderr, "error: --password is too long (max %d characters)\n",
                        BFC_MAX_PASSWORD - 1);
                return 1;
            }
        } else if (strcmp(arg, "--charset") == 0) {
            const char *v = bfc_next_value(argc, argv, i, "--charset");
            if (v == NULL) return 1;
            i++;
            if (bfc_parse_charset(v, &opt->charset) != 0) return 1;
        } else if (strcmp(arg, "--min") == 0) {
            const char *v = bfc_next_value(argc, argv, i, "--min");
            if (v == NULL) return 1;
            i++;
            if (bfc_parse_uint(v, "--min", &tmp) != 0) return 1;
            opt->min_len = (int)tmp;
        } else if (strcmp(arg, "--max") == 0) {
            const char *v = bfc_next_value(argc, argv, i, "--max");
            if (v == NULL) return 1;
            i++;
            if (bfc_parse_uint(v, "--max", &tmp) != 0) return 1;
            opt->max_len = (int)tmp;
        } else if (strcmp(arg, "--wordlist") == 0) {
            const char *v = bfc_next_value(argc, argv, i, "--wordlist");
            if (v == NULL) return 1;
            i++;
            if (bfc_copy_bounded(opt->wordlist_path, sizeof(opt->wordlist_path), v)) {
                fprintf(stderr, "error: --wordlist path is too long\n");
                return 1;
            }
        } else if (strcmp(arg, "--leak") == 0) {
            const char *v = bfc_next_value(argc, argv, i, "--leak");
            if (v == NULL) return 1;
            i++;
            if (bfc_copy_bounded(opt->leak_list_path, sizeof(opt->leak_list_path), v)) {
                fprintf(stderr, "error: --leak path is too long\n");
                return 1;
            }
        } else if (strcmp(arg, "--iter") == 0) {
            const char *v = bfc_next_value(argc, argv, i, "--iter");
            if (v == NULL) return 1;
            i++;
            if (bfc_parse_uint(v, "--iter", &tmp) != 0) return 1;
            opt->iterations = (uint32_t)tmp;
        } else {
            fprintf(stderr, "error: unknown argument \"%s\" (see --help)\n", arg);
            return 1;
        }
    }

    if (!mode_given) {
        fprintf(stderr, "error: no mode given, see --help\n");
        return 1;
    }

    /* Per-mode required-argument validation. */
    switch (opt->mode) {
        case MODE_BRUTE:
            if (opt->target_hex[0] == '\0') {
                fprintf(stderr, "error: --brute requires --hash <hex>\n");
                return 1;
            }
            if (opt->min_len < 1 || opt->max_len < opt->min_len) {
                fprintf(stderr, "error: invalid --min/--max range (%d..%d)\n",
                        opt->min_len, opt->max_len);
                return 1;
            }
            break;
        case MODE_DICT:
            if (opt->target_hex[0] == '\0') {
                fprintf(stderr, "error: --dict requires --hash <hex>\n");
                return 1;
            }
            break;
        case MODE_MASK:
            if (opt->target_hex[0] == '\0') {
                fprintf(stderr, "error: --mask requires --hash <hex>\n");
                return 1;
            }
            if (opt->mask[0] == '\0') {
                fprintf(stderr,
                        "error: --mask requires a pattern, e.g. --mask \"?u?l?l?l?d?d\"\n");
                return 1;
            }
            break;
        case MODE_ANALYZE:
            if (opt->password[0] == '\0') {
                fprintf(stderr, "error: --analyze requires --password <string>\n");
                return 1;
            }
            break;
        case MODE_DEFEND:
        case MODE_HELP:
        case MODE_NONE:
        default:
            break;
    }

    return 0;
}

void bfc_print_result(const bfc_result_t *r) {
    if (r == NULL) {
        fprintf(stderr, "error: bfc_print_result got NULL\n");
        return;
    }

    if (r->found) {
        printf("Status:    CRACKED\n");
        printf("Password:  %s\n", r->password);
    } else {
        printf("Status:    not found\n");
    }
    printf("Attempts:  %llu\n", (unsigned long long)r->attempts);
    printf("Time:      %.3f sec\n", r->seconds);
}

void bfc_print_strength(const bfc_strength_t *s) {
    if (s == NULL) {
        fprintf(stderr, "error: bfc_print_strength got NULL\n");
        return;
    }

    char online_buf[64], cpu_buf[64], gpu_buf[64];
    bfc_format_duration(s->crack_online, online_buf, sizeof(online_buf));
    bfc_format_duration(s->crack_cpu, cpu_buf, sizeof(cpu_buf));
    bfc_format_duration(s->crack_gpu, gpu_buf, sizeof(gpu_buf));

    printf("Verdict:        %s\n", s->verdict);
    printf("Entropy:        %.1f bits\n", s->entropy_bits);
    printf("Keyspace:       %.3e combinations\n", s->keyspace);
    printf("In leak list:   %s\n", s->in_leak_list ? "yes" : "no");
    printf("Crack time (online, ~10/sec): %s\n", online_buf);
    printf("Crack time (this CPU):        %s\n", cpu_buf);
    printf("Crack time (assumed GPU):     %s\n", gpu_buf);
}

void bfc_print_usage(void) {
    printf(
        "BruteforceChecker (bfc) -- SHA-256 cracking & password strength demo\n"
        "\n"
        "Usage:\n"
        "  bfc --brute   --hash <hex> [--charset luds] [--min 1] [--max 6]\n"
        "  bfc --dict    --hash <hex> [--wordlist data/wordlist.txt] [--rules]\n"
        "  bfc --mask    --hash <hex> --mask \"?u?l?l?l?d?d\"\n"
        "  bfc --analyze --password \"P@ssw0rd\" [--leak data/leaks.txt]\n"
        "  bfc --defend  [--iter 100000]\n"
        "  bfc --help\n"
        "\n"
        "Flags:\n"
        "  --hash <hex>      target SHA-256 hash, 64 hex characters\n"
        "  --charset <luds>  which classes to use: l=lower u=upper d=digit s=symbol\n"
        "  --min / --max <n> brute-force length range (default 1..6)\n"
        "  --wordlist <path> word list file for --dict (default data/wordlist.txt)\n"
        "  --rules           apply leet/capitalization/suffix mutations in --dict\n"
        "  --mask <pattern>  (2nd --mask) mask pattern, tokens ?l ?u ?d ?s\n"
        "  --password <str>  plaintext password to analyze\n"
        "  --leak <path>     leaked-password list for --analyze (default data/leaks.txt)\n"
        "  --iter <n>        key-stretching iterations for --defend (default 100000)\n"
        "\n"
        "Examples:\n"
        "  bfc --analyze --password \"qwerty\"\n"
        "  bfc --brute --hash <hash of \"ab12\"> --charset lds --max 4\n"
        "  bfc --dict --hash <hash of \"Summer2024\"> --wordlist data/wordlist.txt --rules\n"
        "  bfc --defend --iter 100000\n"
    );
}
