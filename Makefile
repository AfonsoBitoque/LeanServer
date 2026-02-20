# Makefile for Linux
# Compiles the minimal POSIX FFI bridge (Network.c) needed by Lean executables.
LEAN_PATH = $(shell lean --print-prefix)
CFLAGS = -I $(LEAN_PATH)/include -fPIC
CC = cc

all: Network.o

Network.o: src/Network.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f Network.o