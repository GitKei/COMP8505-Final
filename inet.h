#ifndef INET_H
#define INET_h

#include "defs.h"

uint16 ip_csum(uint16 *ip_hdr, int num_words);
uint16 udp_csum(uint16 *ip_hdr, int num_words);
uint resolve(char *hostname);
void _send(uint32 dst_addr, uint16 src_port, uint16 dst_port, uint8 isReq);
void srv_recv(uint32 src_addr, FILE* file, uint8 keepPort);

#endif
