CC:=gcc
CFLAGS:=-I.. -g -O1 -s -Wall -std=c89

ifeq ($(OS),Windows_NT)
	EXEC:=houtf-test.exe
else
	EXEC:=houtf-test.bin
endif

.PHONY: clean all

all:
	$(CC) $(CFLAGS) houtf-test.c -o $(EXEC)

clean:
	rm -f $(EXEC)