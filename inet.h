#ifndef INET_H
#define INET_h

#include "defs.h"

uint getaddr(int sock, uint dst_addr);
/*
 * IP Checksum, adapted from various sources.
 */
uint16 ip_csum(uint16 *ip_hdr, int num_words);
/*
 * Based on Wikipedia discussion of UDP checksum.
 */
uint16 udp_csum(uint16 *ip_hdr, int num_words);
uint resolve(char *hostname);
void _send(uint32 dst_addr, uint16 data, uint16 dst_port, int chan);

#endif
