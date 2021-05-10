#pragma once

// Listen packets
void processPackets(u_char* args, const struct pcap_pkthdr* header, const u_char* buffer)
{
	struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	
	// UDP Protocol
	if (iph->protocol == 17)
	{
		int size = header->len;
		unsigned short iphdrlen;
	
		struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
		iphdrlen = iph->ihl * 4;
	
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;
	
		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->daddr;
	
		struct udphdr* udph = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	
		int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;
		const u_char* packet = buffer + header_size;

		bool valid = false;
		for (int i = 0; i < sizeof rgiValidPorts; i++)
		{
			if (!rgiValidPorts[i]) continue;
			if (rgiValidPorts[i] == ntohs(udph->dest))
			{
				valid = true;
				break;
			}
		}

		if (valid)
		{
			if ((uint)packet[0] == 0x53 && (uint)packet[1] == 0x41 && (uint)packet[2] == 0x4d && (uint)packet[3] == 0x50)
				OnIncomingQuery(inet_ntoa(source.sin_addr), ntohs(udph->source), ntohs(udph->dest), (uint)packet[10]);

			if ((uint)packet[0] == 0x08 && (uint)packet[1] == 0x1e && (uint)packet[3] == 0xda)
				OnIncomingCookie(inet_ntoa(source.sin_addr), ntohs(udph->source), ntohs(udph->dest));
		}
	}
}

// On SA:MP Query
void OnIncomingQuery(char* host, u_short port, u_short dst_port, uint query)
{
#if defined DEBUG_MODE
	log_debug("Incoming query (%c) from %s:%d to port %d", query, host, port, dst_port);
#endif
	registerQuery(host, query);
}

// On conncookie
void OnIncomingCookie(char* host, u_short port, u_short dst_port)
{
#if defined DEBUG_MODE
	log_debug("Incoming connection cookie from %s:%d to port %d", host, port, dst_port);
#endif
}