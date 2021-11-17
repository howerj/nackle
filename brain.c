#include "util.h"
#include "tweetnacl.h"
#include <string.h>

#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

int main(int argc, char **argv) {
	init();
	if (argc != 4)
		return msg(1, "Usage: %s enc.pub enc.pri phrase", argv[0]);
	/* Hash phrase -> generate keys, optionally generate signing keys
	 *
	 * Notes:
	 * - https://en.bitcoin.it/wiki/Brainwallet
	 * - https://en.wikipedia.org/wiki/Key_stretching
	 * - https://filippo.io/brainwallets-from-the-password-to-the-address/ 
	 *
	 * The first algorithm will just be to use sha256 on the password, to
	 * get the machinery working, then the algorithm will be hardened.
	 */

	if (file_exists(argv[1])) 
		return msg(1, "File <%s> exists", argv[1]);
	if (file_exists(argv[2])) 
		return msg(1, "File <%s> exists", argv[2]);

	unsigned char hash[crypto_hash_BYTES] = { 0, };
	if (crypto_hash(hash, (unsigned char*)argv[3], strlen(argv[3])) < 0)
		return msg(1, "Hash failed");

	char hex_hash[(crypto_hash_BYTES * 2) + 1] = { 0, };
	if (bytes_to_hex(hash, sizeof (hash), hex_hash, sizeof (hex_hash)) < 0)
		return msg(1, "Hex conversion failed");

	unsigned char public_key[crypto_box_PUBLICKEYBYTES] = { 0, };
	unsigned char secret_key[crypto_box_SECRETKEYBYTES] = { 0, };

	memcpy(secret_key, hash, MIN(crypto_hash_BYTES, crypto_box_SECRETKEYBYTES));

	if (crypto_scalarmult_base(public_key, secret_key) < 0)
		return msg(1, "Key generation failed");
	if (key_output(argv[1], public_key, crypto_box_PUBLICKEYBYTES) < 0)
		return msg(1, "Public key output <%s> failed", argv[1]);
	if (key_output(argv[2], secret_key, crypto_box_SECRETKEYBYTES) < 0)
		return msg(1, "Secret key output <%s> failed", argv[2]);
	return 0;
}
