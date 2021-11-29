#include "util.h"
#include "tweetnacl.h"
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
	init();
	if (argc != 5)
		return msg(1, "Usage: %s send-key.pri recv-key.pub text.txt text.enc", argv[0]);
	if (file_exists(argv[4]))
		return msg(1, "File <%s> exists", argv[4]);

	/* TODO: It is possible to do encryption, unauthenticated, with
	 * just a public key as well, although perhaps not with TweetNaCl,
	 * encrypting the hash of the message would provide *some* resistance
	 * to tampering. The scheme would need thinking about... 
	 *
	 * Also, the way encryption works will need to be reworked, it
	 * has to load everything into memory first, yuck. */

	/* Alice is sending to Bob, not surprisingly */
	unsigned char a_secret_key[crypto_box_SECRETKEYBYTES] = { 0, };
	unsigned char b_public_key[crypto_box_PUBLICKEYBYTES] = { 0, };

	if (key_read(argv[1], a_secret_key, crypto_box_SECRETKEYBYTES) < 0)
		return 1;
	if (key_read(argv[2], b_public_key, crypto_box_PUBLICKEYBYTES) < 0)
		return 1;

	unsigned char nonce[crypto_box_NONCEBYTES] = { 0, };
	randombytes(nonce, sizeof(nonce));

	FILE *out = create_file(argv[4]);
	if (!out)
		return msg(1,"File creation failed");
	if (fwrite(nonce, 1, sizeof (nonce), out) != sizeof (nonce))
		return msg(1, "Writing nonce to file failed");

	/* Input */
	content_s c = slurp(argv[3]); /* TODO: Error handling */
	if (c.error)
		return 1;
	long psize = crypto_box_ZEROBYTES + c.size;
	unsigned char *padded = malloc(psize);
	if (!padded) 
		return msg(1, "Malloc failed of %ld bytes", (long)psize);
	memset(padded, 0, crypto_box_ZEROBYTES);
	memcpy(padded + crypto_box_ZEROBYTES, c.bytes, c.size);
	free(c.bytes);

	/* Output */
	unsigned char *encrypted = calloc(psize, sizeof(unsigned char));
	if (encrypted == NULL) 
		return msg(1, "calloc failed of %ld bytes", (long)psize);

	/* Encrypt */
	if (crypto_box(encrypted, padded, psize, nonce, b_public_key, a_secret_key) < 0)
		return msg(1, "Encryption failed");
	free(padded);
	const size_t write_size = psize - crypto_box_BOXZEROBYTES;
	if (fwrite(encrypted + crypto_box_BOXZEROBYTES, 1, write_size, out) != write_size)
		return msg(1, "Failed to write main data body to file");
	free(encrypted);
	return 0;
}
