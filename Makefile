all:
	gcc main.c -o firewall -pthread -lpcap

clean:
	$(RM) firewall