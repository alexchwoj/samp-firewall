#pragma once

int rgiValidPorts[422];
typedef unsigned int uint;
struct sockaddr_in source, dest;
void processPackets(u_char*, const struct pcap_pkthdr*, const u_char*);
void OnIncomingQuery(char* host, u_short port, u_short dst_port, uint query);
void OnIncomingCookie(char* host, u_short port, u_short dst_port);