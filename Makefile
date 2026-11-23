CC      := cc
CFLAGS  := -std=c11 -Wall -Wextra -O2 -Iinclude
SRC     := $(wildcard src/*.c)
OBJ     := $(SRC:.c=.o)

bfc: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o bfc

.PHONY: clean
