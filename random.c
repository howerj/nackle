#include "util.h"
#include "tweetnacl.h"

int main(int argc, char **argv) {
	init();
	if (argc != 1)
		return msg(1, "Usage: %s", argv[0]);
	while (1) {
		unsigned char x[256];
		randombytes(x, sizeof x);
		if (fwrite(x, 1, sizeof x, stdout) != sizeof (x))
			return msg(1, "Failed to write random bytes");
	}
	return 0;
}
