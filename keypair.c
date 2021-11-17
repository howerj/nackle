#include "util.h"
#include "tweetnacl.h"

int main(int argc, char **argv) {
	init();
	/* TODO: Change the argument order for this utility so
	 * the secret key is first, if the public key argument
	 * is not present then instead of generating a new keypair
	 * we can derive a public key from the private key pair,
	 * as with: 
	 * <https://github.com/sbp/tweetnacl-tools/pull/1/files>
	 *
	 * The "brain.c" file could be included in this one, if
	 * three arguments are present we instead derive a keypair
	 * from a phrase. That would be pretty neat and keep things
	 * small. 
	 *
	 * The same could be done for the signing keys. */
	if (argc != 3)
		return msg(1, "Usage: %s key.pub key.sec", argv[0]);
	if (file_exists(argv[1])) 
		return msg(1, "File <%s> exists", argv[1]);
	if (file_exists(argv[2])) 
		return msg(1, "File <%s> exists", argv[2]);
	unsigned char public_key[crypto_box_PUBLICKEYBYTES] = { 0, };
	unsigned char secret_key[crypto_box_SECRETKEYBYTES] = { 0, };
	if (crypto_box_keypair(public_key, secret_key) < 0)
		return msg(1, "Keypair generation failed");
	if (key_output(argv[1], public_key, crypto_box_PUBLICKEYBYTES) < 0)
		return msg(1, "Public key output <%s> failed", argv[1]);
	if (key_output(argv[2], secret_key, crypto_box_SECRETKEYBYTES) < 0)
		return msg(1, "Secret key output <%s> failed", argv[2]);
	return 0;
}
