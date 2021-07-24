#include "main.h"

int main(int argc, char* argv[])
{
	log_warn("Hyaxe SA:MP Firewall started!");

	system("iptables -D PREROUTING -t raw -p udp -m u32 ! --u32 \"28=0x53414d50\" -m set ! --match-set samp_whitelist src -j DROP");
	system("ipset -X samp_whitelist -!");

	system("ipset -N samp_whitelist hash:ip hashsize 16777216 maxelem 16777216 -!");
	system("iptables -A PREROUTING -t raw -p udp -m u32 ! --u32 \"28=0x53414d50\" -m set ! --match-set samp_whitelist src -j DROP");

	log_info("Default rules applied!");

	// Initialize cleaner interval
	clearSessionList();
	pthread_t threadClearSession;
	pthread_create(&threadClearSession, NULL, cleanerInterval, NULL);
	
	pcap_if_t *alldevsp;
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	// Get network interface
	char* iface;
	if (!argv[1])
	{
		FILE* f = fopen("/proc/net/route", "r");
		char line[100];
		while (fgets(line, 100, f))
		{
			char* p = strtok(line, " \t"); char* c = strtok(NULL, " \t");
			if ((p != NULL && c != NULL) && (strcmp(c, "00000000") == 0))
			{
				iface = p;
				break;
			}
		}
	}
	else iface = argv[1];

	if (!argv[1])
		log_info("Using default interface: %s", iface);
	
	// Sniffing devices
	log_debug("Finding available devices...");
	if (pcap_findalldevs(&alldevsp, errbuf))
	{
		log_error("Error finding devices: %s", errbuf);
		exit(1);
	}
	log_info("Device found!");
	
	log_debug("Opening device %s for sniffing...", iface);
	handle = pcap_open_live(iface, 65536, 1, 0, errbuf);
	
	if (handle == NULL)
	{
		log_error("Couldn't open device %s: %s", iface, errbuf);
		exit(1);
	}
	log_info("Device opened!");
	
	pcap_setdirection(handle, PCAP_D_IN);
	pcap_loop(handle, -1, processPackets, NULL);
	return 0;
}
