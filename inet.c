#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "defs.h"
#include "util.h"
#include "inet.h"
#include "ntp.h"

#define IPHDR_LEN 5
#define IP_VER    4
#define UDPHDR_B  8
#define PSDHDR_B  12
#define MAX_IFACE 8
#define TTL       64

struct udp_dgram
{
	struct iphdr ip;
	struct udphdr udp;
	char data[NTP_SIZ];
};

struct pseudo_hdr
{
	uint32 saddr;
	uint32 daddr;
	uint8 zero;
	uint8 proto;
	uint16 udp_len;
	struct udphdr udp;
	char data[NTP_SIZ];
};

uint getaddr(int sock, uint dst_addr)
{
	struct ifconf ifconf;
	struct ifreq ifr[MAX_IFACE];
	int ifs;

	ifconf.ifc_buf = (char *) ifr;
	ifconf.ifc_len = sizeof(ifr);

	if (ioctl(sock, SIOCGIFCONF, &ifconf) < 0)
	{
		perror("ioctl");
		return 0;
	}

	ifs = ifconf.ifc_len / sizeof(struct ifreq);

	for (int i = 0; i < ifs; i++)
	{
		struct sockaddr_in *s_in = (struct sockaddr_in *) &(ifr[i].ifr_addr);

		// If source == dest, we're likely doing a local test
		if (s_in->sin_addr.s_addr == dst_addr)
			return s_in->sin_addr.s_addr;
		// Don't use localhost for outgoing packets, suspicious
		else if (s_in->sin_addr.s_addr == LOCALHOST)
			continue;
		// Found a valid IP hopefully
		else if (s_in->sin_addr.s_addr != 0)
			return s_in->sin_addr.s_addr;
	}

	// No interface found? Oh well, use LOCALHOST anyway
	return LOCALHOST;
}

void _send(uint32 dst_addr, uint16 src_port, uint16 dst_port, uint8 isReq)
{
	struct sockaddr_in sin;
	struct udp_dgram packet;
	struct pseudo_hdr pseudo;
	int sock;
	int one = 1;
	int size = sizeof(struct udp_dgram);
	int check_len;

	srand(getpid() * getsec());

	// Set up socket
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sock < 0)
		error("Unable to open sending socket.");

	// Tell kernel not to help us out
	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
		error("Kernel won't allow IP header override.");

	// Get an address we can use
	sin.sin_addr.s_addr = getaddr(sock, dst_addr);
	memset(&packet, 0, sizeof(packet));

	packet.ip.ihl = IPHDR_LEN;
	packet.ip.version = IP_VER;
	packet.ip.tot_len = htons(size);
	packet.ip.id = htonl(rand());
	packet.ip.ttl = TTL;
	packet.ip.protocol = IPPROTO_UDP;
	packet.ip.saddr = sin.sin_addr.s_addr;
	packet.ip.daddr = dst_addr;
	
	check_len = IPHDR_LEN * 2;
	packet.ip.check = ip_csum((uint16*) &packet, check_len);

	packet.udp.dest = htons(dst_port);
	packet.udp.source = htons(src_port);
	packet.udp.len = htons(UDPHDR_B + NTP_SIZ);

	if (isReq)
		make_req(packet.data);
	else
		make_rsp(packet.data);

	memset(&pseudo, 0, sizeof(pseudo));

	pseudo.saddr = packet.ip.saddr;
	pseudo.daddr = packet.ip.daddr;
	pseudo.proto = packet.ip.protocol;
	pseudo.udp_len = packet.udp.len;
	pseudo.udp = packet.udp;
	memcpy(pseudo.data, &packet.data, NTP_SIZ);

	check_len = (PSDHDR_B + UDPHDR_B + NTP_SIZ) / 2;
	packet.udp.check = udp_csum((uint16*) &pseudo, check_len);

	sin.sin_family = AF_INET;
	sin.sin_port = packet.udp.dest;
	sin.sin_addr.s_addr = packet.ip.daddr;

	sendto(sock, &packet, size, 0, (struct sockaddr *) &sin, sizeof(sin));
	close(sock);
}

char* extract_udp(uint32 src_addr, char* data, int length)
{
	struct udp_dgram *packet = (struct udp_dgram*) data;
	char *buf = malloc(3);

	if (packet->ip.saddr == src_addr && packet->udp.dest == htons(PORT_NTP))
	{
		if (isReq(packet->data))
		{
			char *dec;

			// Output data
			buf[0] = ntohs(packet->udp.source) >> 8;
			buf[1] = ntohs(packet->udp.source);
			buf[2] = 0;

			dec = decrypt(SEKRET, buf, 2);
			memcpy(buf, dec, 2);
			free(dec);

			return buf;
		}
	}
	return NULL;
}

void buildPacket(int offset, char data)
{

}

void readPacket()
{

}

void srv_recv(uint32 src_addr, FILE* file, uint8 keepPort)
{
	struct udp_dgram packet;
	int sock;
	char buf[3];

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if(sock < 0)
	{
		perror("receive socket cannot be open. Are you root?");
		exit(1);
	}

	while (1)
	{
		read(sock, &packet, sizeof(struct udp_dgram));
		if (packet.ip.saddr == src_addr && packet.udp.dest == htons(PORT_NTP))
		{
			if (isReq(packet.data))
			{
				char *dec;
				uint16 src_port;
				uint16 dst_port;

				// Output data
				buf[0] = ntohs(packet.udp.source) >> 8;
				buf[1] = ntohs(packet.udp.source);
				buf[2] = 0;

				dec = decrypt(SEKRET, buf, 2);
				memcpy(buf, dec, 2);
				free(dec);

				fprintf(file, "%s", buf);
				fflush(file);

				src_port = PORT_NTP;
				if (keepPort)
					dst_port = ntohs(packet.udp.source);
				else
					dst_port = PORT_NTP;

				// Respond with fake NTP
				_send(src_addr, src_port, dst_port, FALSE);
			}
		}
	}

	close(sock);
}

uint resolve(char *hostname)
{
	static struct in_addr i;
	struct hostent *h;

	i.s_addr = inet_addr(hostname);
	if(i.s_addr == -1)
	{
		h = gethostbyname(hostname);

		if(h == NULL)
			return 0;

		memcpy(h->h_addr, &i.s_addr, h->h_length);
	}

	return i.s_addr;
}

uint16 udp_csum(uint16 *hdr, int num_words)
{
	ulong sum = 0;

	for (;num_words > 0; --num_words) // 1s complement addition of hdr
	{
		sum += *(hdr++);
		sum = (sum & 0xFFFF) + (sum >> 16); // Add carry
	}

	sum = ~sum; // Calculate the 1s complement

	return sum;
}

uint16_t ip_csum(uint16 *hdr, int num_words)
{
	uint16_t sum = 0;

	for (;num_words > 0; --num_words) // 2s complement addition of hdr
		sum += *(hdr++);

	sum = (sum >> 16) + (sum & 0xFFFF); // Roll carries in
	sum += sum >> 16; // And the possible carry out

	sum = ~sum; // Calculate the 1s complement

	return sum;
}
