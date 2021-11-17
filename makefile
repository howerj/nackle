CFLAGS=-std=c99 -D_POSIX_C_SOURCE=1 -Wall -Wextra -pedantic -O2 -DCRYPTO_VERSION="\"0.0.1\""
TARGETS=random decrypt encrypt keypair sign signpair verify brain hash
EXE=.exe
.PHONY: all test run clean install

all: ${TARGETS}

test: ${TARGETS}

run: ${TARGETS}

random: random.c tweetnacl.o util.o

decrypt: decrypt.c tweetnacl.o util.o

encrypt: encrypt.c tweetnacl.o util.o

keypair: keypair.c tweetnacl.o util.o

sign: sign.c tweetnacl.o util.o

signpair: signpair.c tweetnacl.o util.o

verify: verify.c tweetnacl.o util.o

brain: brain.c tweetnacl.o util.o

hash: hash.c tweetnacl.o util.o

install: ${TARGETS}

clean:
	rm -rv *.a *.o *.so *.dll *.exe *.pub *.pri *.sec ${TARGETS}
