#include <pcap.h>
#include <unistd.h>

#include "capture.h"
#include "util.h"
#include "defs.h"
#include "handler.h"

pcap_t* nic;
struct bpf_program fltr_prog;

void pcap_init(const char *fltr_str)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	if ((nic = pcap_open_live(NULL, MAX_LEN, 0, -1, errbuf)) == NULL)
		error(errbuf);
	
	// Get packet fltr_str from arguments
	if (pcap_compile(nic, &fltr_prog, fltr_str, 0, 0) == -1)
		error("pcap_compile");

	// Set fltr_str for captures
	if (pcap_setfilter(nic, &fltr_prog) == -1)
		error("pcap_setfltr_str");
}

void srv_listen(int duplex)
{
	// Start capturing, make sure to heavily restrict our CPU usage.
	while (1)
	{
		if (pcap_dispatch(nic, -1, pkt_handler, (u_char*)duplex) < 0)
			error("pcap_loop");
		usleep(5000);	
	}
}
