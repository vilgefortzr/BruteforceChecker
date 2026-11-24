# BruteforceChecker (bfc)

Offline command-line tool in C (C11, procedural, no dependencies besides
libc and libm). Given a SHA-256 hash, it shows how long it actually
takes to crack the password behind it — by brute force, dictionary, or
mask attack — and it can also analyze a plaintext password's strength
or demonstrate why key stretching matters.

Project for the Cybersecurity course at NaUKMA. Team: Антоній (core &
brute-force), Дар'я (stats & analysis), Анастасія (CLI & output).

## Build

Requirements: a C11 compiler (`cc`/`gcc`/`clang`) and `make`.

```sh
make
```

This produces a single binary, `./bfc`, from everything in `src/*.c`.

```sh
make clean
```

removes build artifacts (`src/*.o`, `bfc`).

## Getting a hash to test with

The tool takes a ready-made SHA-256 hash, not a raw password — this is
also how passwords are stored in most real systems. You can produce one
with:

- An online SHA-256 converter.
- Python: `python3 -c "import hashlib; print(hashlib.sha256(b'yourpassword').hexdigest())"`
- The shell: `printf '%s' 'yourpassword' | sha256sum`

## Usage

```
bfc --brute   --hash <hex> [--charset luds] [--min 1] [--max 6]
bfc --dict    --hash <hex> [--wordlist data/wordlist.txt] [--rules]
bfc --mask    --hash <hex> --mask "?u?l?l?l?d?d"
bfc --analyze --password "P@ssw0rd" [--leak data/leaks.txt]
bfc --defend  [--iter 100000]
bfc --help
```

Flags:

| Flag               | Meaning                                                            |
|--------------------|---------------------------------------------------------------------|
| `--hash <hex>`     | target SHA-256 hash, 64 hex characters                             |
| `--charset <luds>` | character classes for `--brute`: `l`ower `u`pper `d`igit `s`ymbol   |
| `--min / --max <n>`| brute-force length range (default `1..6`)                          |
| `--wordlist <path>`| word list for `--dict` (default `data/wordlist.txt`)                |
| `--rules`          | apply leet / capitalization / year-suffix mutations in `--dict`    |
| `--mask <pattern>` | mask pattern for `--mask` mode, tokens `?l ?u ?d ?s`                |
| `--password <str>` | plaintext password to analyze                                      |
| `--leak <path>`    | leaked-password list for `--analyze` (default `data/leaks.txt`)     |
| `--iter <n>`       | key-stretching iterations for `--defend` (default `100000`)        |

Note on `--mask`: the flag appears twice — once to select the mode,
once to carry the pattern — exactly as shown in the usage line above.

## Data files

- `data/wordlist.txt` — a small list of common words for the
  dictionary attack (`--dict`).
- `data/leaks.txt` — a small list of commonly leaked passwords, used
  by `--analyze` to flag passwords that show up in real breaches.

Both are intentionally short demo lists, not full real-world leak
corpora — swap in a bigger list with `--wordlist` / `--leak` if needed.

## Demo walkthrough

A single run-through that answers "why bother, my password is
complex enough":

```sh
# 1. A classic weak password: found in the leak list immediately.
./bfc --analyze --password "qwerty"

# 2. Looks complex, but it is a known word in disguise + still leaked.
./bfc --analyze --password "P@ssw0rd"

# 3. Pure brute force takes a short password fast.
H=$(printf '%s' 'ab12' | sha256sum | cut -d' ' -f1)
./bfc --brute --hash "$H" --charset lds --max 4

# 4. A "complex-looking" password falls instantly to a dictionary +
#    rules attack, where pure brute force would not have reached it.
H=$(printf '%s' 'Summer2024' | sha256sum | cut -d' ' -f1)
./bfc --dict --hash "$H" --wordlist data/wordlist.txt --rules

# 5. Key stretching: show how salting + iterating the hash collapses
#    brute-force throughput — this is why real systems never store a
#    bare SHA-256 of a password.
./bfc --defend --iter 100000
```

Takeaway: what falls is not "the short password" but "the predictable
one" — the defense is salt + key stretching, not just a longer
password.

## Tests

Each module has its own sanity-check program under `tests/`, built and
run by hand (not part of `make bfc`):

```sh
cc -std=c11 -Wall -Wextra -Iinclude \
   tests/test_cli.c src/cli.c src/analyze.c -o /tmp/test_cli -lm
/tmp/test_cli
```
