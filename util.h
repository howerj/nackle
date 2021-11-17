#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdio.h>

typedef struct {
	size_t size;
	unsigned char *bytes;
} content_s;

int init(void);
void randombytes(unsigned char *, unsigned long long);
int msg(int ret, const char *fmt, ...);
void die(char *fmt, ...);
int file_exists(const char *filename);
int bytes_to_hex(const unsigned char *in, size_t in_size, char *out, size_t out_size);
FILE *create_file(const char *filename);
int key_read(const char *filename, unsigned char *key, size_t key_size);
int key_output(const char *filename, unsigned char *key, size_t key_size);
content_s slurp(const char *filename);
const char *get_project_info(void);

#endif
