#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include "ntp.h"

#include "defs.h"

#define FLAG_CLI 0x23
#define FLAG_SRV 0x24

struct ntp_dgram
{
	uint8 flags;
	uint8 stratum;
	uint8 interval;
	uint8 precision;
	uint32 delay;
	uint32 dispersion;
	uint32 ref_id;
	uint64 ref_update;
	uint64 originate;
	uint64 receive;
	uint64 transmit;
};

struct dns_dgram
{
	uint16 id;       // identification number
	uint16 flags;    // bit-flags
	uint16 q_count;  // number of question entries
	uint16 ans_count; // number of answer entries
	uint16 auth_count; // number of authority entries
	uint16 add_count; // number of resource entries
	char name[16];
};

struct ntp_dgram prep()
{
	struct ntp_dgram packet;
	struct timespec curr;
	uint64 tmp;

	memset(&packet, 0, sizeof(packet));
	packet.stratum = 0x03;
	packet.interval = 0x08;
	packet.precision = 0xEE;
	packet.delay = htonl(0x1532);
	packet.dispersion = htonl(0x11A6);
	packet.ref_id = htonl(0x43D44ADC);
	
	clock_gettime(CLOCK_REALTIME, &curr);
	tmp = htonl(curr.tv_nsec);
	tmp = (tmp << 32) + htonl(curr.tv_sec + 2209000000);
	packet.ref_update = tmp;
	packet.originate = tmp;
	packet.receive = tmp;
	packet.transmit = tmp;

	return packet;
}

void make_vanilla_ntp(char* buff)
{
	struct ntp_dgram packet;

	packet = prep();
	packet.flags = FLAG_CLI;

	memcpy(buff, &packet, sizeof(packet));
}

void make_covert_ntp(char* buff, uint16 data)
{
	struct ntp_dgram packet;
	uint32 tmp;
	uint16 *ptr;

	packet = prep();
	packet.flags = FLAG_CLI;

	// Save and clear ref_id
	tmp = packet.ref_id;

	// Inject data
	packet.ref_id = data;

	// Reinsert high bytes
	ptr = ((uint16*)packet.ref_id) + 1;
	*ptr = tmp >> 16;

	memcpy(buff, &packet, sizeof(packet));
}

void make_covert_dns(char* buff, uint16 data)
{
	struct dns_dgram packet;

	packet.flags = 0x0100;
	packet.q_count = 0x1;
	packet.add_count = 0x0;
	packet.ans_count = 0x0;
	packet.auth_count = 0x0;

	strcpy(packet.name, "\3www\6google\3com");

	// Inject data
	packet.id = data;

	memcpy(buff, &packet, sizeof(packet));
}

uint8 isReq(char* data)
{
	struct ntp_dgram *packet = (struct ntp_dgram*) data;

	if (packet->flags == FLAG_CLI)
		return TRUE;

	return FALSE;
}

uint64 getsec()
{
	struct timespec curr;

	clock_gettime(CLOCK_REALTIME, &curr);

	return curr.tv_sec;
}
