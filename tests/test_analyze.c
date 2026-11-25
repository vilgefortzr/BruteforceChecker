/* Sanity checks for analyze.c. */
#include "analyze.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void write_leak_file(const char *path) {
    FILE *fp = fopen(path, "w");
    fprintf(fp, "qwerty\n123456\npassword\n");
    fclose(fp);
}

int main(void) {
    const char *leak_path = "/tmp/bfc_test_leaks.txt";
    write_leak_file(leak_path);

    /* 1. Known-leaked, very weak password. */
    bfc_strength_t s1 = bfc_analyze("qwerty", leak_path);
    assert(s1.in_leak_list == 1);
    assert(strcmp(s1.verdict, "very weak") == 0);
    printf("[ok] qwerty -> verdict=%s entropy=%.1f in_leak=%d\n",
           s1.verdict, s1.entropy_bits, s1.in_leak_list);

    /* 2. "Looks complex" but is a leet-spelled dictionary word: should
     *    score much lower than its raw length*log2(alphabet) would say. */
    bfc_strength_t s2 = bfc_analyze("P@ssw0rd", leak_path);
    double naive_bits = 8.0 * 3.169925; /* length * log2(94-ish) rough upper bound */
    printf("[ok] P@ssw0rd -> verdict=%s entropy=%.1f (naive upper bound ~%.1f)\n",
           s2.verdict, s2.entropy_bits, naive_bits);
    assert(s2.entropy_bits < naive_bits);

    /* 3. Long random-looking password should score as stronger. */
    bfc_strength_t s3 = bfc_analyze("xQ7#mK2!vL9$pR4z", leak_path);
    printf("[ok] long random -> verdict=%s entropy=%.1f\n", s3.verdict, s3.entropy_bits);
    assert(s3.entropy_bits > s2.entropy_bits);
    assert(strcmp(s3.verdict, "very weak") != 0);

    /* 4. NULL safety. */
    bfc_strength_t s4 = bfc_analyze(NULL, leak_path);
    assert(strcmp(s4.verdict, "very weak") == 0);

    /* 5. bfc_bench_hashrate returns something positive. */
    double hps = bfc_bench_hashrate();
    printf("[ok] bfc_bench_hashrate -> %.0f hashes/sec\n", hps);
    assert(hps > 0.0);

    /* 6. bfc_bench_stretch: stretched throughput must be well below raw. */
    double raw = 0.0, stretched = 0.0;
    bfc_bench_stretch(50000, &raw, &stretched);
    printf("[ok] bfc_bench_stretch -> raw=%.0f/s stretched=%.0f/s\n", raw, stretched);
    assert(raw > 0.0 && stretched > 0.0);
    assert(stretched < raw);

    printf("All analyze.c tests passed.\n");
    return 0;
}