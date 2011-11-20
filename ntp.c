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

void make_req(char* buff)
{
	struct ntp_dgram packet;

  packet = prep();
	packet.flags = FLAG_CLI;

	memcpy(buff, &packet, sizeof(packet));
}

uint8 isReq(char* data)
{
	struct ntp_dgram *packet = (struct ntp_dgram*) data;

	if (packet->flags == FLAG_CLI)
		return TRUE;

	return FALSE;
}

void make_rsp(char* buff)
{
	struct ntp_dgram packet;

	packet = prep();
	packet.flags = FLAG_SRV;

	memcpy(buff, &packet, sizeof(packet));
}

uint64 getsec()
{
	struct timespec curr;

	clock_gettime(CLOCK_REALTIME, &curr);

	return curr.tv_sec;
}
