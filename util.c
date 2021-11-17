#define PROJECT "Cryptographic Tool-set"
#define AUTHOR "Richard James Howe"
#define EMAIL "howe.r.j.89@gmail.com"
#define VERSION CRYPTO_VERSION
#define LICENSE "Public Domain"
#define REPO "https://github.com/howerj/crypto"
/* TODO:
 * - Library prefix on all functions
 * - Return error codes instead of blowing up
 * - Come up with a better name than just "crypto".  */
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "util.h"
#include "tweetnacl.h"

#if defined(__unix__)
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
static inline void binary(FILE *f) { UNUSED(f); }
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <io.h>
#include <fcntl.h>
/* Used to unfuck file mode for "Win"dows. Text mode is for losers. */
static void binary(FILE *f) { _setmode(_fileno(f), _O_BINARY); }
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif
#else
#error "Unknown Platform"
static inline void binary(FILE *f) { UNUSED(f); }
#endif

#ifdef __unix__
/* It's really stupid that there isn't a syscall for this */

static int fd = -1;

void randombytes(unsigned char *x,unsigned long long xlen) {
	//assert((!x && xlen == 0) || x);
	if (fd == -1) {
		for (;;) {
			fd = open("/dev/urandom",O_RDONLY);
			if (fd != -1) break;
			sleep(1);
		}
	}

	for (int i = 0;xlen > 0;) {
		if (xlen < 1048576) i = xlen; else i = 1048576;
		i = read(fd, x, i);
		if (i < 1) {
			sleep(1);
			continue;
		}
		x += i;
		xlen -= i;
	}
}
#elif defined(_WIN32)
void randombytes(unsigned char *x, unsigned long long xlen) {
	assert(x);
#if 0
	/* TODO: Test on Vista / Windows XP (BCRYPT_USE_SYSTEM_PREFERRED_RNG is not supported on Vista) */
	NTSTATUS Status = BCryptGenRandom(NULL, x, xlen, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!NT_SUCCESS(Status))
		die("Could not get random bytes");
#else
	/* NB. Deprecated */
	HCRYPTPROV hCryptProv;
	if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		if (CryptGenRandom(hCryptProv, xlen, x) == 0) {
			die("Could not get random bytes (Acquiring bytes failed)");
		}
		if (CryptReleaseContext(hCryptProv, 0) == 0)
			die("Could not get random bytes (Releasing failed)");
	} else {
		die("Could not get random bytes (Acquiring context failed)");
	}
#endif
}
#else
void randombytes(unsigned char *x, unsigned long long xlen) {
	assert(x);
	abort();
	/* Read seed file, and try to update it, use tweetnacl hash to make new
	 * seed, if a seed file does not exist try to get entropy from:
	 * - System variables and Time
	 * - Keyboard mashing / Time
	 * The system variables and Time are are *really*, *really* poor
	 * source of entropy but should help, and not hinder. Another source
	 * of entropy could be hashing various system files.
	 *
	 * NB. Updating the seed atomically might be a (security) problem. */
}
#endif

const char *get_project_info(void) {
	static const char *info ="\
Project: " PROJECT "\n\
Author:  " AUTHOR "\n\
Email:   " EMAIL "\n\
Version: " VERSION "\n\
License: " LICENSE "\n\
Repo:    " REPO "\n\
\n\
This project uses the TweetNaCl <https://tweetnacl.cr.yp.to/> library to perform\n\
various cryptographic functions such as key generation, encryption, signing and\n\
the like. This tool is part of a series of tools, consult the project repository\n\
or manual pages for more information. The tools are related to the ones available\n\
at <https://github.com/sbp/tweetnacl-tools/>.\n\
\n\
This program returns zero on success and non-zero on failure.\n\n\
";
	return info;
}

int msg(const int ret, const char *fmt, ...) {
	assert(fmt);
	FILE *out = stderr;
	va_list ap;
	va_start(ap, fmt);
	const int r = vfprintf(out, fmt, ap);
	va_end(ap);
	if (r < 0)
		return -1;
	if (fputc('\n', out) != '\n')
		return -1;
	if (fflush(out) < 0)
		return -1;
	return ret;
}

void die(char *fmt, ...) {
	assert(fmt);
	FILE *out = stderr;
	va_list ap;
	va_start(ap, fmt);
	if (vfprintf(out, fmt, ap) < 0)
		abort();
	va_end(ap);
	if (fputc('\n', out) != '\n')
		abort();
	if (fflush(out) < 0)
		abort();
	exit(EXIT_FAILURE);
}

int file_exists(const char *filename) {
	assert(filename);
#if defined(__unix__)
	/* http://stackoverflow.com/a/230068 Not perfect, because e.g. it won't allow the use of /dev/stdout */
	if (access(filename, F_OK) != -1) 
		return 1;
	return 0;
#elif defined(_WIN32)
	/* https://stackoverflow.com/questions/3828835 */
  	DWORD dwAttrib = GetFileAttributes(filename);
	return dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
#else
	return -1;
#endif
}

int bytes_to_hex(const unsigned char *in, size_t in_size, char *out, size_t out_size) {
	assert(in);
	assert(out);
	if (out_size < ((in_size * 2ull) + 1ull))
		return -1;
	size_t i = 0;
	/* TODO: Remove sprintf dependency */
	for (i = 0; i < in_size; i++) {
		const int r = sprintf(&out[i * 2ull], "%02x", in[i]);
		if (r != 2)
			return -1;
	}
	out[i * 2ull] = '\0';
	return 0;
}

FILE *create_file(const char *filename) {
	assert(filename);
#if defined(__unix__)
	/* http://stackoverflow.com/a/230581 */
	const int fd = open(filename, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		(void)msg(-1, "Could not create file %s", filename);
		return NULL;
	}
	/* http://stackoverflow.com/a/1941472 */
	return fdopen(fd, "wb");
#else
	return fopen(filename, "wb");
#endif
}

int key_read(const char *filename, unsigned char *key, const size_t key_size) {
	assert(filename);
	FILE *f = fopen(filename, "rb");
	int r = 0;
	if (!f)
		return msg(-2, "Could open file <%s>", filename);
	if (fread(key, 1, key_size, f) != key_size)
		r = msg(-2, "Could not read the key from <%s>", filename);
	if (fclose(f) < 0)
		r = msg(-2, "Closing failed");
	return r;
}

int key_output(const char *filename, unsigned char *key, const size_t key_size) {
	assert(filename);
	assert(key);
	if (!strcmp(filename, "-")) {
		/* TODO: Should this be implemented? Or should
		 * there be a utility for converting keys and
		 * messages to their ASCII equivalents? */
		return msg(-2, "Unimplemented");
#if 0
		char hx[(256 * 2) + 1];
		for (size_t i = 0; i < key_size; i += 256) {
			bytes_to_hex();
			fwrite();
		}
		if (fputc('\n', stdout) != '\n')
			die("Could not output the key to <stdout>");
#endif
	}
	FILE *out = create_file(filename);
	int r = 0;
	if (!out)
		return msg(-2, "Key file creation failed <%s>: %s", filename, strerror(errno));
	if (fwrite(key, 1, key_size, out) != key_size)
		r = msg(-2, "Could not write all key bytes");
	if (fclose(out) < 0)
		r = msg(-2, "Closing failed");
	return r;
}

/* TODO/NOTES:
 * - Will not work on stdin (if seeking fails, we could read stdin until
 *   it returns EOF, we can also check isatty()).
 * - File size may be limited to 4GiB on some, but not all, platforms.
 * - I could just borrow another version of my slurp from elsewhere
 * - Error codes could be returned instead of dying */
content_s slurp(const char *filename) {
	assert(filename);
	content_s c = { 0, NULL, };
	FILE *f = fopen(filename, "rb");
	if (!f) 
		die("Could not read <%s>", filename);
	if (fseek(f, 0, SEEK_END) < 0)
		die("Failed to seek");
	const long size = ftell(f);
	if (size < 0)
		die("Could not read <%s>", filename);
	c.size = (size_t)size;
	if (fseek(f, 0, SEEK_SET) < 0)
		die("Failed to seek");
	c.bytes = malloc(c.size);
	if (c.bytes == NULL) 
		die("Malloc failed!");
	if (fread(c.bytes, c.size, 1, f) != c.size)
		die("Read size mismatch");
	if (fclose(f) < 0)
		die("Closing failed");
	return c;
}

int init(void) {
	binary(stdin);
	binary(stdout);
	binary(stderr);
	return 0;
}
