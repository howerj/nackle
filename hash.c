#include "util.h"
#include "tweetnacl.h"
#include <string.h>

int main(int argc, char **argv) {
	init();
	/* TODO: This should be on a file, not an argument! */
	if (argc != 2)
		return msg(1, "Usage: %s message", argv[0]);
	unsigned char hash[crypto_hash_BYTES] = { 0, };
	if (crypto_hash(hash, (unsigned char*)argv[1], strlen(argv[1])) < 0)
		return msg(1, "Hash failed");

	char hex_hash[(crypto_hash_BYTES * 2) + 1] = { 0, };
	if (bytes_to_hex(hash, sizeof (hash), hex_hash, sizeof (hex_hash)) < 0)
		return msg(1, "Hex conversion failed");
	if (printf("%s\n", hex_hash) != ((crypto_hash_BYTES * 2) + 1))
		return msg(1, "Printing hash failed");
	return 0;
}
