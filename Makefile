# Makefile for Linux
# Compiles the POSIX FFI bridge and C stubs needed by Lean executables.
LEAN_PATH = $(shell lean --print-prefix)
CFLAGS = -I $(LEAN_PATH)/include -I src -fPIC
CC = cc

all: Network.o db_stubs.o crypto_ffi.o sqlite_ffi.o

Network.o: src/Network.c
	$(CC) $(CFLAGS) -c $< -o $@

db_stubs.o: src/db_stubs.c
	$(CC) $(CFLAGS) -c $< -o $@

crypto_ffi.o: src/crypto_ffi.c
	$(CC) $(CFLAGS) -c $< -o $@

sqlite_ffi.o: src/sqlite_ffi.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f Network.o db_stubs.o crypto_ffi.o sqlite_ffi.o