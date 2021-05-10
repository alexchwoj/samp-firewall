/*
 * SA:MP Firewall for Hyaxe Cloud
 * Author: Atom
 */

#pragma once

// Libs
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <pthread.h>

// Config
#define DEBUG_MODE // Debug messages
#define INIT_RULES // Initialize with default iptables rules
#define VALIDATED_MESSAGES // Messages on validation
#define	MAX_SESSIONS (1024)

// Modules
#define LOG_USE_COLOR
#include "log.h"
#include "log.c"

#include "session.h"
#include "session.c"

#include "network.h"
#include "network.c"