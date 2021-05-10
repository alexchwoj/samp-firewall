#pragma once

void clearSessionList();
void* cleanerInterval(void *args);
int getIndexByAddress(char* address);
int getFreeSessionSlot();
void registerQuery(char* address, uint query);
void addQuery(int index, uint query);

struct tSessionInfo
{
	char sAddress[16];
	int aQueries[4];
	bool bValided;
};
struct tSessionInfo aSessions[MAX_SESSIONS];