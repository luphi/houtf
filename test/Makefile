CC := gcc
CFLAGS := -I.. -g -Wall -Wextra -Wpedantic -ansi

ifeq ($(OS),Windows_NT)
	EXEC := houtf-test.exe
else
	EXEC := houtf-test.bin
endif

.PHONY: clean all

all: houtf-test.c
	$(CC) $(CFLAGS) houtf-test.c -o $(EXEC)

clean:
	rm -f $(EXEC)