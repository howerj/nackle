#include "util.h"
#include "tweetnacl.h"

int main(int argc, char **argv) {
	init();
	if (argc != 5)
		return msg(1, "Usage: %s send-key.pri recv-key.pub text.txt text.enc", argv[0]);

	/* This will also erroneously fail if the file "-" exists if that is implemented */
	if (file_exists(argv[4]))
		return msg(1, "File <%s> exists", argv[4]);
#if 0
	/* Alice is sending to Bob, not surprisingly */
	unsigned char a_secret_key[crypto_box_SECRETKEYBYTES] = { 0, };
	unsigned char b_public_key[crypto_box_PUBLICKEYBYTES] = { 0, };

	read_key(argv[1], a_secret_key, crypto_box_SECRETKEYBYTES);
	read_key(argv[2], b_public_key, crypto_box_PUBLICKEYBYTES);

	unsigned char nonce[crypto_box_NONCEBYTES] = { 0, };
	randombytes(nonce, sizeof(nonce));

	FILE *out = NULL;
	if (strcmp(argv[4], "-") != 0) {
		out = create_file(argv[4]);
		fwrite(nonce, sizeof(nonce), 1, out);
	} else {
		out = stdout;
		fwrite(bytes_to_hex(nonce, sizeof(nonce)), sizeof(nonce) * 2, 1, out);
		fputs("\n", out);
	}

	/* Input
	// unsigned char *message = read_file(argv[3]); */
	Content c = read_file(argv[3]);
	long psize = crypto_box_ZEROBYTES + c.size;
	unsigned char *padded = malloc(psize);
	if (!padded) 
		return msg(1, "Malloc failed!");
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

	if (out != stdout) {
		fwrite(encrypted + crypto_box_BOXZEROBYTES, psize - crypto_box_BOXZEROBYTES, 1, out);
	} else {
		fwrite(bytes_to_hex(encrypted + crypto_box_BOXZEROBYTES, psize - crypto_box_BOXZEROBYTES), (psize - crypto_box_BOXZEROBYTES) * 2, 1, out);
		fputs("\n", out);
	}
	free(encrypted);
#endif
	return 0;
}
