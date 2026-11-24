/* main.c -- entry point: parse args, dispatch to the right module,
 * print the result.
 *
 * Owner: Anastasia (CLI & parsing). This file only calls functions
 * already defined in attack.h / analyze.h / sha256.h / cli.h; it does
 * not reimplement any attack or analysis logic itself.
 *
 * Builds clean under -std=c11 -Wall -Wextra.
 */

#include "cli.h"
#include "attack.h"
#include "analyze.h"
#include "sha256.h"

#include <stdio.h>

static void print_defend_report(uint32_t iterations, double raw_hps, double stretched_hps) {
    printf("Key-stretching benchmark (SHA-256, %u iterations)\n", iterations);
    printf("Raw hash rate:        %.0f hashes/sec\n", raw_hps);
    printf("Stretched hash rate:  %.0f hashes/sec\n", stretched_hps);

    if (stretched_hps > 0.0) {
        double slowdown = raw_hps / stretched_hps;
        printf("Slowdown factor:      %.1fx\n", slowdown);
    }
    printf("This is why passwords are stored salted and stretched, not as plain SHA-256.\n");
}

int main(int argc, char **argv) {
    bfc_options_t opt;

    if (bfc_parse_args(argc, argv, &opt) != 0) {
        return 1;
    }

    switch (opt.mode) {
        case MODE_HELP: {
            bfc_print_usage();
            return 0;
        }

        case MODE_BRUTE: {
            uint8_t target[BFC_HASH_LEN];
            if (bfc_hex_decode(opt.target_hex, target) != 0) {
                fprintf(stderr, "error: --hash is not a valid SHA-256 hex digest\n");
                return 1;
            }
            bfc_result_t r = bfc_attack_brute(target, opt.charset, opt.min_len, opt.max_len);
            bfc_print_result(&r);
            return 0;
        }

        case MODE_DICT: {
            uint8_t target[BFC_HASH_LEN];
            if (bfc_hex_decode(opt.target_hex, target) != 0) {
                fprintf(stderr, "error: --hash is not a valid SHA-256 hex digest\n");
                return 1;
            }
            bfc_result_t r = bfc_attack_dict(target, opt.wordlist_path, opt.apply_rules);
            bfc_print_result(&r);
            return 0;
        }

        case MODE_MASK: {
            uint8_t target[BFC_HASH_LEN];
            if (bfc_hex_decode(opt.target_hex, target) != 0) {
                fprintf(stderr, "error: --hash is not a valid SHA-256 hex digest\n");
                return 1;
            }
            bfc_result_t r = bfc_attack_mask(target, opt.mask);
            bfc_print_result(&r);
            return 0;
        }

        case MODE_ANALYZE: {
            bfc_strength_t s = bfc_analyze(opt.password, opt.leak_list_path);
            bfc_print_strength(&s);
            return 0;
        }

        case MODE_DEFEND: {
            double raw_hps = 0.0, stretched_hps = 0.0;
            bfc_bench_stretch(opt.iterations, &raw_hps, &stretched_hps);
            print_defend_report(opt.iterations, raw_hps, stretched_hps);
            return 0;
        }

        case MODE_NONE:
        default:
        
            fprintf(stderr, "error: no mode selected, see --help\n");
            return 1;
    }
}
