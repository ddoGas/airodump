#include <cstdio>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <list>

#include "dot11frame.h"
#include "airodump.h"

char iface[80];
std::list<struct beacon_info> beacons;
std::list<struct probe_info> probes;

bool check_dot11(const u_char* pkt){
    return true;
}

void update_dot11(const u_char* pkt){
    int a=3;
}

void print_dot11(){
    printf("good\n");
}

void usage() {
	printf("syntax : airodump <interface>\n");
    printf("sample : airodump mon0\n");
}

int main(int argc, char* argv[]) {
	
	if (argc != 2) {
		usage();
		return -1;
	}

	strcpy(iface, argv[1]);

    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", iface, errbuf);
		return false;
	}

    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    while(true){
        int res = pcap_next_ex(handle, &pkt_header, &pkt_data);

        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        if(check_dot11(pkt_data)){
            system("clear");
            update_dot11(pkt_data);
            print_dot11();
        }
    }
}