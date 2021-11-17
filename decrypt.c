#include "util.h"
#include "tweetnacl.h"

int main(int argc, char **argv) {
	init();

	if (argc != 5)
		return msg(1, "Usage: %s send-key.pub recv-key.pri text.enc text.txt", argv[0]);

	/* This will also erroneously fail if the file "-" exists */
	if (file_exists(argv[4])) 
		return msg(1, "File <%s> exists", argv[4]);
#if 0
	/* Alice has sent to Bob, not surprisingly */
	unsigned char a_public_key[crypto_box_PUBLICKEYBYTES] = { 0, };
	unsigned char b_secret_key[crypto_box_SECRETKEYBYTES] = { 0, };

	read_key(argv[1], a_public_key, crypto_box_PUBLICKEYBYTES);
	read_key(argv[2], b_secret_key, crypto_box_SECRETKEYBYTES);

	unsigned char nonce[crypto_box_NONCEBYTES];

	/* Input */
	Content c = read_file(argv[3]);
	memcpy(nonce, c.bytes, crypto_box_NONCEBYTES);

	long esize = c.size - crypto_box_NONCEBYTES + crypto_box_BOXZEROBYTES;
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
	crypto_box_open(message, encrypted, esize, nonce, a_public_key, b_secret_key);
	free(encrypted);

	if (strcmp(argv[4], "-") != 0) {
		FILE *out = create_file(argv[4]);
		fwrite(message + crypto_box_ZEROBYTES, esize - crypto_box_ZEROBYTES, 1, out);
		fclose(out);
	} else {
		fwrite(message + crypto_box_ZEROBYTES, esize - crypto_box_ZEROBYTES, 1, stdout);
	}
	free(message);
#endif
	return 0;
}
