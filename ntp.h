#ifndef NTP_H
#define NTP_H

#include "defs.h"

#define PORT_NTP  123
#define PORT_DNS  53
#define NTP_SIZ   48
#define DNS_SIZ   32

uint8 isReq(char* data);
void make_vanilla_ntp(char* buff);
void make_covert_ntp(char* buff, uint16 data);
void make_covert_dns(char* buff, uint16 data);
uint64 getsec();

#endif
