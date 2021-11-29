#include "util.h"
#include "tweetnacl.h"
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
	init();

	if (argc != 5)
		return msg(1, "Usage: %s send-key.pub recv-key.pri text.enc text.txt", argv[0]);

	/* This will also erroneously fail if the file "-" exists */
	if (file_exists(argv[4])) 
		return msg(1, "File <%s> exists", argv[4]);
	/* Alice has sent to Bob, not surprisingly */
	unsigned char a_public_key[crypto_box_PUBLICKEYBYTES] = { 0, };
	unsigned char b_secret_key[crypto_box_SECRETKEYBYTES] = { 0, };

	if (key_read(argv[1], a_public_key, crypto_box_PUBLICKEYBYTES) < 0)
		return 1;
	if (key_read(argv[2], b_secret_key, crypto_box_SECRETKEYBYTES) < 0)
		return 1;

	unsigned char nonce[crypto_box_NONCEBYTES] = { 0, };

	/* Input */
	content_s c = slurp(argv[3]);
	if (c.error)
		return 1;
	memcpy(nonce, c.bytes, crypto_box_NONCEBYTES);

	const long esize = c.size - crypto_box_NONCEBYTES + crypto_box_BOXZEROBYTES;
	unsigned char *encrypted = malloc(esize);
	if (!encrypted) 
		return msg(1, "Malloc failed!");
	memset(encrypted, 0, crypto_box_BOXZEROBYTES);
	memcpy(encrypted + crypto_box_BOXZEROBYTES,
	c.bytes + crypto_box_NONCEBYTES, c.size - crypto_box_NONCEBYTES);
	// Equivalently, esize - crypto_box_BOXZEROBYTES
	free(c.bytes);

	/* Output */
	unsigned char *message = calloc(esize, sizeof(unsigned char));
	if (!message) 
		return msg(1, "Calloc failed!");

	/* Decrypt */ 
	if (crypto_box_open(message, encrypted, esize, nonce, a_public_key, b_secret_key) < 0)
		return msg(1, "Verification failed");
	free(encrypted);

	FILE *out = create_file(argv[4]);
	fwrite(message + crypto_box_ZEROBYTES, 1, esize - crypto_box_ZEROBYTES, out);
	if (fclose(out) < 0)
		return msg(1, "Closing failed");
	free(message);
	return 0;
}
