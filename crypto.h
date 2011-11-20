#ifndef CRYPTO_H
#define CRYPTO_H

/*
SOURCE FILE: crypto.h

PROGRAM: Backdoor - A simple two in one backdoor client/server using libpcap

DATE: October 23, 2011

REVISIONS:
	1.0 - October 23

DESIGNERS:
	Credit to unknown contributor, see:
http://www.codealias.info/technotes/des_encryption_using_openssl_a_simple_example
	Modified by Steve Stanisic

PROGRAMMERS:

NOTES: This file contains a pair of routines to encrypt/decrypt an
	arbitrary block of data using DES.
*/

/*
FUNCTION: encrypt

PARAMS:
	char *key: The key to encrypt with.
	char *msg: The message to encrypt.
	int size: The size of the message.

RETURN: A pointer to the encrypted data block.

NOTES: Note the return value is allocated on the heap and must be freed
	by the caller unless you enjoy memory leaks.
*/
char* encrypt(char *key, char *msg, int size);
/*
FUNCTION: decrypt

PARAMS:
	char *key: The key to decrypt with.
	char *msg: The message to decrypt.
	int size: The length of the message.

RETURN: A pointer to the decrypted data block.

NOTES: Note the return value is allocated on the heap and must be freed
	by the caller.
*/
char* decrypt(char *key, char *msg, int size);

#endif
