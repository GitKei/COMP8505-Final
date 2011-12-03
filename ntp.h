#ifndef NTP_H
#define NTP_H

#include "defs.h"

#define PORT_NTP  123
#define NTP_SIZ   48

uint8 isReq(char* data);
void make_vanilla_req(char* buff);
void make_covert_req(char* buff);
void make_rsp(char* buff);
uint64 getsec();

#endif
