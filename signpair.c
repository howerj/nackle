#include "util.h"
#include "tweetnacl.h"

int main(int argc, char **argv) {
	init();
	if (argc != 3)
		return msg(1, "Usage: %s key.pub key.sec", argv[0]);
	if (file_exists(argv[1])) 
		return msg(1, "File <%s> exists", argv[1]);
	if (file_exists(argv[2])) 
		return msg(1, "File <%s> exists", argv[2]);
	unsigned char public_key[crypto_sign_PUBLICKEYBYTES] = { 0, };
	unsigned char secret_key[crypto_sign_SECRETKEYBYTES] = { 0, };
	if (crypto_sign_keypair(public_key, secret_key) < 0)
		return msg(1, "Signing Keypair generation failed");
	if (key_output(argv[1], public_key, crypto_sign_PUBLICKEYBYTES) < 0)
		return msg(1, "Public key output <%s> failed", argv[1]);
	if (key_output(argv[2], secret_key, crypto_sign_SECRETKEYBYTES) < 0)
		return msg(1, "Secret key output <%s> failed", argv[2]);
	return 0;
}
