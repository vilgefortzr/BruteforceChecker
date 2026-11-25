# BruteforceChecker

Offline C-based SHA-256 password strength analyzer and brute-force
benchmark tool. Given a SHA-256 hash, `bfc` shows how long the password
behind it actually survives - by brute force, dictionary, or mask attack -
and it can also rate a plaintext password's strength and demonstrate why
key stretching matters.

The point it makes: what falls to an attacker is not "the short password"
but "the predictable one". The real defense is salting and key stretching,
not merely a longer password.

Written in C11, procedural, no dependencies beyond libc and libm.
Course project in Cybersecurity, NaUKMA.

**Team**
- **Antonii** - core & brute-force
- **Daria** - statistics & analysis
- **Anastasiia** - CLI, parsing & output

## Build

Requirements: a C11 compiler (`cc` / `gcc` / `clang`) and `make`.

```sh
make         # builds the ./bfc binary from everything in src/*.c
make clean   # removes src/*.o and bfc
```

## Getting a hash to test with

The cracking modes take a ready-made SHA-256 hash, not a raw password -
the same way real systems store credentials. Produce one with:

```sh
printf '%s' 'yourpassword' | sha256sum
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

Note: `--mask` appears twice - once to select the mode, once to carry the
pattern - exactly as in the usage line.

## Modes

- **`--brute`** - tries every combination of the chosen character classes
  from `--min` to `--max` length. Shows how cheaply short passwords fall.
- **`--dict`** - hashes each word from the list. With `--rules` it also
  tries mutations (leet `a→@ o→0 s→$ i→1`, capitalized first letter, and
  numeric/year suffixes), so a "complex-looking" word like `Summer2024`
  falls even though brute force would not reach it.
- **`--mask`** - brute force constrained to a known structure, e.g.
  `?u?l?l?l?d?d` = upper + three lower + two digits. Knowing the shape
  collapses the search space.
- **`--analyze`** - rates a plaintext password: entropy, keyspace,
  presence in the leak list, and estimated crack time under three models
  (rate-limited online, this CPU, an assumed GPU). No cracking involved.
- **`--defend`** - benchmarks raw SHA-256 vs. an iterated (stretched) hash
  and reports the slowdown factor, illustrating why passwords are stored
  salted and stretched rather than as a bare SHA-256.

## Demo walkthrough

A run-through that answers "why bother, my password is complex enough".

### Analyze (no cracking, just rating)

```sh
# Classic weak password: tiny entropy and flagged in the leak list.
./bfc --analyze --password "qwerty"

# Looks complex, but it is a known word in disguise and still leaked.
./bfc --analyze --password "P@ssw0rd"

# A generated leak entry (word + year) - also flagged as leaked.
./bfc --analyze --password "jennifer2024"

# A genuinely unpredictable password: high entropy, not in the leak list.
./bfc --analyze --password "xQ7#mK2!vL9\$pR4z"
```

### Brute force (pure enumeration)

```sh
# Short password, narrow charset -> cracked in well under a second.
H=$(printf '%s' 'ab12' | sha256sum | cut -d' ' -f1)
./bfc --brute --hash "$H" --charset lds --max 4
```

Note: the default charset is all four classes (`luds`, 94 symbols); with
`--max 6` that is ~10^11 candidates and takes hours single-threaded. Brute
force is the wrong tool for a word - that is what `--dict` is for. On long
runs `bfc` prints a live progress line to stderr, e.g.
`[brute] 8388608 candidates tried, 4.05 M/s`.

### Dictionary (with and without mutation rules)

```sh
# Plain dictionary: a bare word straight from the list.
H=$(printf '%s' 'dragon' | sha256sum | cut -d' ' -f1)
./bfc --dict --hash "$H"

# Same word list, but "Summer2024" only falls once --rules is on
# (capitalization + year suffix). Pure brute force would not reach it.
H=$(printf '%s' 'Summer2024' | sha256sum | cut -d' ' -f1)
./bfc --dict --hash "$H" --rules            # cracked
./bfc --dict --hash "$H"                    # not found without --rules
```

### Mask (structure is known)

```sh
# "Test12" = upper + three lower + two digits. This sweeps ~34M
# candidates (a few seconds) and shows the live progress line.
H=$(printf '%s' 'Test12' | sha256sum | cut -d' ' -f1)
./bfc --mask --hash "$H" --mask "?u?l?l?l?d?d"
```

### Defend (why bare SHA-256 is never used)

```sh
# Key stretching collapses brute-force throughput; the slowdown scales
# with the iteration count.
./bfc --defend --iter 1000
./bfc --defend --iter 100000
```
## Tests

Each module has a standalone sanity-check program under `tests/`, separate
from the `bfc` binary. Build and run them all with:

```sh
make tests
```
