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
FILE* open_file(char* fname, uint8 isClient);

#endif
