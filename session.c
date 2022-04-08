#pragma once

void clearSessionList()
{
	memset(aSessions, 0, sizeof aSessions);
#if defined DEBUG_MODE
	log_info("Session list cleaned");
#endif
}

// Clear sessions list every 3 seconds
void* cleanerInterval(void *args)
{
	while (1)
	{
		sleep(3);
		clearSessionList();
	}
}

int getIndexByAddress(char* address)
{
	for (int i = 0; i < MAX_SESSIONS; i++)
	{
		if (strcmp(aSessions[i].sAddress, address) == 0)
			return i;
	}
	return -1;
}

int getFreeSessionSlot()
{
	for (int i = 0; i < MAX_SESSIONS; i++)
	{
		if (!aSessions[i].bValided)
			return i;
	}
	return -1;
}

void addQuery(int index, uint query)
{
	for (int i = 0; i < 4; i++)
	{
		if (!aSessions[index].aQueries[i])
		{
			aSessions[index].aQueries[i] = query;
			break;
		}
	}
}

void registerQuery(char* address, uint query)
{
	int index = getIndexByAddress(address);
	if (index != -1)
	{
		addQuery(index, query);

		/*
		* Magic key's:
		* PC: i (105), p (112), c (99), r (114), result: 430
		* SAMP ANDROID: p (112), r (114), c (99), p (112), result: 437
		*/

		int magic_key = 0;
		for (int i = 0; i < 4; i++)
		{
			//printf("%c (%d), ", aSessions[index].aQueries[i], aSessions[index].aQueries[i]);
			magic_key += aSessions[index].aQueries[i];
		}
		//printf("result: %d\n", magic_key);

		if (magic_key == 428 || magic_key == 430 || magic_key == 437 || magic_key == 325)
		{
			char rule[80];
			sprintf(rule, "ipset -D udp_whitelist %s -!", address);
			system(rule);

			sprintf(rule, "ipset -A udp_whitelist %s -!", address);
			system(rule);
#if defined VALIDATED_MESSAGES
			log_warn("Validated user: %s (magic_key: %d)", address, magic_key);
#endif
		}

#if defined DEBUG_MODE
		log_debug("Query %c added to session %s with index %d", query, address, index);
#endif
	}
	else
	{
		index = getFreeSessionSlot();
		strcpy(aSessions[index].sAddress, address);
		aSessions[index].bValided = true;
		addQuery(index, query);

#if defined DEBUG_MODE
		log_info("Session added with index %d: %s", index, address);
#endif
	}
}