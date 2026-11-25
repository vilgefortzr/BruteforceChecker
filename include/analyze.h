#ifndef BFC_ANALYZE_H
#define BFC_ANALYZE_H
#include "common.h"

typedef struct {
    double   entropy_bits;    /* estimated entropy, in bits */
    double   keyspace;        /* size of the brute-force space (double: can get huge) */
    int      in_leak_list;    /* 1 if the password was found in the leak list */
    double   crack_online;    /* seconds, rate-limited online attack (~10 attempts/sec) */
    double   crack_cpu;       /* seconds, based on this machine's measured hash rate */
    double   crack_gpu;       /* seconds, based on an assumed GPU hash rate */
    char     verdict[32];     /* "very weak" .. "strong" */
} bfc_strength_t;

/* Analyzes the strength of a plaintext password (no cracking involved). */
bfc_strength_t bfc_analyze(const char *password, const char *leak_list_path);

/* Measures this machine's SHA-256 throughput (hashes/sec). */
double bfc_bench_hashrate(void);

/* Benchmark: plain hash vs. stretched hash. Fills hps for each. */
void bfc_bench_stretch(uint32_t iterations, double *raw_hps, double *stretched_hps);

#endif /* BFC_ANALYZE_H */
