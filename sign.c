#include "util.h"
#include "tweetnacl.h"

int main(int argc, char **argv) {
	init();
	if (argc != 4)
		return msg(1, "Usage: %s sign.pri message.txt message.signed", argv[0]);
#if 0
	if (file_exists(argv[3])) 
		return msg(1, "File <%s> exists", argv[3]);

	unsigned char secret_key[crypto_sign_SECRETKEYBYTES] = { 0, };
	read_key(argv[1], secret_key, crypto_sign_SECRETKEYBYTES);

	Content c = read_file(argv[2]);
	unsigned char *sm = malloc(c.size + crypto_sign_BYTES);
	unsigned long long ssize = 0;
	if (crypto_sign(sm, &ssize, c.bytes, c.size, secret_key) < 0)
		return msg(1, "Signing failed");
	free(c.bytes);

	if (strcmp(argv[3], "-") != 0) {
		FILE *out = create_file(argv[3]);
		fwrite(sm, ssize, 1, out);
		fclose(out);
	} else {
		fwrite(bytes_to_hex(sm, ssize - c.size), (ssize - c.size) * 2, 1, stdout);
		fputs("\n", stdout);
	}

	free(sm);
#endif
	return 0;
}
