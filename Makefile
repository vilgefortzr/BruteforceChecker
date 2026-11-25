CC      := cc
CFLAGS  := -std=c11 -Wall -Wextra -O2 -Iinclude
LDLIBS  := -lm
SRC     := $(wildcard src/*.c)
OBJ     := $(SRC:.c=.o)

bfc: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

tests:
	$(CC) $(CFLAGS) tests/test_attack.c  src/attack.c  src/sha256.c -o tests/test_attack.out  $(LDLIBS) && ./tests/test_attack.out
	$(CC) $(CFLAGS) tests/test_analyze.c src/analyze.c src/sha256.c -o tests/test_analyze.out $(LDLIBS) && ./tests/test_analyze.out
	$(CC) $(CFLAGS) tests/test_cli.c     src/cli.c                  -o tests/test_cli.out     $(LDLIBS) && ./tests/test_cli.out
	rm -f tests/*.out

clean:
	rm -f src/*.o bfc tests/*.out

.PHONY: clean tests
