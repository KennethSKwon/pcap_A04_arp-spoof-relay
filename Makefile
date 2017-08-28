all:
	gcc v6_combination.c -o arp_spoof -w -lpcap -lpthread

clean:
	rm arp_spoof

