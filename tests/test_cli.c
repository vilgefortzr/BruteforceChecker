/* test_cli.c -- owner: Anastasia. Basic sanity checks for cli.c.
 *
 * Not wired into the main Makefile target (the project builds a single
 * `bfc` binary straight from all of src), so compile and run it by hand:
 *   cc -std=c11 -Wall -Wextra -Iinclude \
 *      tests/test_cli.c src/cli.c src/analyze.c -o /tmp/test_cli -lm
 *   /tmp/test_cli
 */

#include "cli.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *HASH64 =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

int main(void) {
    /* 1. --help short-circuits everything else. */
    {
        char *argv[] = {"bfc", "--help"};
        bfc_options_t opt;
        int rc = bfc_parse_args(2, argv, &opt);
        assert(rc == 0);
        assert(opt.mode == MODE_HELP);
        printf("[ok] --help sets MODE_HELP\n");
    }

    /* 2. No arguments at all is an error. */
    {
        char *argv[] = {"bfc"};
        bfc_options_t opt;
        int rc = bfc_parse_args(1, argv, &opt);
        assert(rc != 0);
        printf("[ok] no args -> error\n");
    }

    /* 3. --brute with a valid hash and defaults. */
    {
        char *argv[] = {"bfc", "--brute", "--hash", (char *)HASH64};
        bfc_options_t opt;
        int rc = bfc_parse_args(4, argv, &opt);
        assert(rc == 0);
        assert(opt.mode == MODE_BRUTE);
        assert(strcmp(opt.target_hex, HASH64) == 0);
        assert(opt.min_len == 1 && opt.max_len == 6); /* defaults */
        printf("[ok] --brute --hash <64 hex> parses with defaults\n");
    }

    /* 4. --brute with a malformed hash is rejected. */
    {
        char *argv[] = {"bfc", "--brute", "--hash", "not-a-hash"};
        bfc_options_t opt;
        int rc = bfc_parse_args(4, argv, &opt);
        assert(rc != 0);
        printf("[ok] invalid --hash -> error\n");
    }

    /* 5. --charset "lds" sets exactly lower|digit|symbol. */
    {
        char *argv[] = {"bfc", "--brute", "--hash", (char *)HASH64, "--charset", "lds"};
        bfc_options_t opt;
        int rc = bfc_parse_args(6, argv, &opt);
        assert(rc == 0);
        assert(opt.charset == (BFC_CS_LOWER | BFC_CS_DIGIT | BFC_CS_SYMBOL));
        printf("[ok] --charset lds -> correct bit mask\n");
    }

    /* 6. --mask mode: first --mask selects the mode, second carries the pattern. */
    {
        char *argv[] = {"bfc", "--mask", "--hash", (char *)HASH64,
                         "--mask", "?u?l?l?l?d?d"};
        bfc_options_t opt;
        int rc = bfc_parse_args(6, argv, &opt);
        assert(rc == 0);
        assert(opt.mode == MODE_MASK);
        assert(strcmp(opt.mask, "?u?l?l?l?d?d") == 0);
        printf("[ok] --mask ... --mask <pattern> parses correctly\n");
    }

    /* 7. --analyze requires --password. */
    {
        char *argv[] = {"bfc", "--analyze"};
        bfc_options_t opt;
        int rc = bfc_parse_args(2, argv, &opt);
        assert(rc != 0);
        printf("[ok] --analyze without --password -> error\n");
    }

    /* 8. --analyze with --password and default leak path. */
    {
        char *argv[] = {"bfc", "--analyze", "--password", "qwerty"};
        bfc_options_t opt;
        int rc = bfc_parse_args(4, argv, &opt);
        assert(rc == 0);
        assert(opt.mode == MODE_ANALYZE);
        assert(strcmp(opt.password, "qwerty") == 0);
        assert(strcmp(opt.leak_list_path, "data/leaks.txt") == 0);
        printf("[ok] --analyze --password parses with default leak path\n");
    }

    /* 9. --defend with default iterations. */
    {
        char *argv[] = {"bfc", "--defend"};
        bfc_options_t opt;
        int rc = bfc_parse_args(2, argv, &opt);
        assert(rc == 0);
        assert(opt.mode == MODE_DEFEND);
        assert(opt.iterations == 100000u);
        printf("[ok] --defend parses with default --iter\n");
    }

    /* 10. Unknown argument is rejected. */
    {
        char *argv[] = {"bfc", "--brute", "--hash", (char *)HASH64, "--nope"};
        bfc_options_t opt;
        int rc = bfc_parse_args(5, argv, &opt);
        assert(rc != 0);
        printf("[ok] unknown flag -> error\n");
    }

    printf("All cli.c tests passed.\n");
    return 0;
}
