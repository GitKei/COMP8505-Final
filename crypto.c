#include <string.h>
#include <openssl/des.h>

#include "defs.h"

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
