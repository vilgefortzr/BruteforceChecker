# BruteforceChecker (bfc)

Offline C-based SHA-256 password strength analyzer and brute-force
benchmark tool. Given a SHA-256 hash, `bfc` shows how long the password
behind it actually survives — by brute force, dictionary, or mask attack —
and it can also rate a plaintext password's strength and demonstrate why
key stretching matters.

The point it makes: what falls to an attacker is not "the short password"
but "the predictable one". The real defense is salting and key stretching,
not merely a longer password.

Written in C11, procedural, no dependencies beyond libc and libm.
Course project in Cybersecurity, NaUKMA.

**Team**
- **Антоній** — core & brute-force (`sha256.c`, `attack.c`)
- **Дар'я** — statistics & analysis (`analyze.c`)
- **Анастасія** — CLI, parsing & output (`cli.c`, `main.c`)

## Build

Requirements: a C11 compiler (`cc` / `gcc` / `clang`) and `make`.

```sh
make         # builds the ./bfc binary from everything in src/*.c
make clean   # removes src/*.o and bfc
```

## Getting a hash to test with

The cracking modes take a ready-made SHA-256 hash, not a raw password —
the same way real systems store credentials. Produce one with:

```sh
printf '%s' 'yourpassword' | sha256sum        # shell
python3 -c "import hashlib; print(hashlib.sha256(b'yourpassword').hexdigest())"
```

## Usage

```
bfc --brute   --hash <hex> [--charset luds] [--min 1] [--max 6]
bfc --dict    --hash <hex> [--wordlist data/wordlist.txt] [--rules]
bfc --mask    --hash <hex> --mask "?u?l?l?l?d?d"
bfc --analyze --password "P@ssw0rd" [--leak data/leaks.txt]
bfc --defend  [--iter 100000]
bfc --help
```

| Flag                | Meaning                                                           |
|---------------------|-------------------------------------------------------------------|
| `--hash <hex>`      | target SHA-256 hash, 64 hex characters                            |
| `--charset <luds>`  | classes for `--brute`: `l`ower `u`pper `d`igit `s`ymbol           |
| `--min` / `--max`   | brute-force length range (default `1..6`)                         |
| `--wordlist <path>` | word list for `--dict` (default `data/wordlist.txt`)              |
| `--rules`           | apply leet / capitalization / year-suffix mutations in `--dict`   |
| `--mask <pattern>`  | mask pattern for `--mask`, tokens `?l ?u ?d ?s`                   |
| `--password <str>`  | plaintext password to analyze                                     |
| `--leak <path>`     | leaked-password list for `--analyze` (default `data/leaks.txt`)   |
| `--iter <n>`        | key-stretching iterations for `--defend` (default `100000`)       |

Note: `--mask` appears twice — once to select the mode, once to carry the
pattern — exactly as in the usage line.

## Modes

- **`--brute`** — tries every combination of the chosen character classes
  from `--min` to `--max` length. Shows how cheaply short passwords fall.
- **`--dict`** — hashes each word from the list. With `--rules` it also
  tries mutations (leet `a→@ o→0 s→$ i→1`, capitalized first letter, and
  numeric/year suffixes), so a "complex-looking" word like `Summer2024`
  falls even though brute force would not reach it.
- **`--mask`** — brute force constrained to a known structure, e.g.
  `?u?l?l?l?d?d` = upper + three lower + two digits. Knowing the shape
  collapses the search space.
- **`--analyze`** — rates a plaintext password: entropy, keyspace,
  presence in the leak list, and estimated crack time under three models
  (rate-limited online, this CPU, an assumed GPU). No cracking involved.
- **`--defend`** — benchmarks raw SHA-256 vs. an iterated (stretched) hash
  and reports the slowdown factor, illustrating why passwords are stored
  salted and stretched rather than as a bare SHA-256.

## Demo walkthrough

```sh
# 1. Classic weak password: flagged in the leak list immediately.
./bfc --analyze --password "qwerty"

# 2. Looks complex, but it is a known word in disguise and still leaked.
./bfc --analyze --password "P@ssw0rd"

# 3. Pure brute force takes a short password fast.
H=$(printf '%s' 'ab12' | sha256sum | cut -d' ' -f1)
./bfc --brute --hash "$H" --charset lds --max 4

# 4. A "complex-looking" password falls instantly to dictionary + rules.
H=$(printf '%s' 'Summer2024' | sha256sum | cut -d' ' -f1)
./bfc --dict --hash "$H" --wordlist data/wordlist.txt --rules

# 5. Key stretching collapses brute-force throughput.
./bfc --defend --iter 100000
```

## Project layout

```
include/   common.h sha256.h attack.h analyze.h cli.h   — shared API (headers)
src/       sha256.c    SHA-256, hex, key stretching
           attack.c    brute / dictionary / mask attacks
           analyze.c   entropy, crack-time models, defender benchmark
           cli.c       argument parsing and output formatting
           main.c      entry point and mode dispatch
data/      wordlist.txt, leaks.txt   — short demo lists (swap in larger ones
                                        via --wordlist / --leak)
tests/     test_attack.c test_analyze.c test_cli.c
```

Modules communicate only through the headers in `include/`; the result and
option structs live in `common.h`.

## Tests

Each module has a standalone sanity-check program under `tests/`, not part
of `make bfc`. Build and run by hand:

```sh
cc -std=c11 -Wall -Wextra -Iinclude tests/test_attack.c  src/attack.c  src/sha256.c -o /tmp/t_attack       && /tmp/t_attack
cc -std=c11 -Wall -Wextra -Iinclude tests/test_analyze.c src/analyze.c src/sha256.c -o /tmp/t_analyze -lm   && /tmp/t_analyze
cc -std=c11 -Wall -Wextra -Iinclude tests/test_cli.c     src/cli.c                  -o /tmp/t_cli           && /tmp/t_cli
```

## Notes

- SHA-256 lives in `src/sha256.c`, adapted from a public FIPS 180-4
  reference implementation.
- `--defend` uses plain iterated SHA-256 to illustrate the principle; real
  systems use purpose-built KDFs (bcrypt, scrypt, Argon2, PBKDF2).
