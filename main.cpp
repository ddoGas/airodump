#include <cstdio>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <list>

#include "dot11frame.h"
#include "airodump.h"

char iface[80];
std::list<struct beacon_info> beacons;
std::list<struct station_info> stations;

void print_mac(uint8_t* mac_ptr){
    printf("%02x:%02x:%02x:%02x:%02x:%02x\t", mac_ptr[0], mac_ptr[1], mac_ptr[2], mac_ptr[3], mac_ptr[4], mac_ptr[5]);
    return;
}

void print_dot11(){
    system("clear");
    printf("\n\n\n----------------------------------------\n");
    printf("BSSID\t\t\tbeacons\t\t\tESSID\n");
    for (std::list<struct beacon_info>::iterator it = beacons.begin(); it != beacons.end(); ++it){
        print_mac(it->bssid);
        printf("%d\t\t%s", it->beacons, it->essid);
        printf("\n");
    }
    printf("\n\n");
    printf("BSSID\t\t\tstation\t\t\tframes\n");
    for (std::list<struct station_info>::iterator it = stations.begin(); it != stations.end(); ++it){
        print_mac(it->bssid);
        print_mac(it->station);
        printf("%d", it->frames);
        printf("\n");
    }
    printf("\n----------------------------------------\n");
}

void airodump(const u_char* pkt){
    struct ieee80211_radiotap_header* radiotap_hdr = (struct ieee80211_radiotap_header*)pkt;
    if(radiotap_hdr->it_version!=0x00)
        return;

	struct dot11_frame_header* beacon_fr = (struct dot11_frame_header*)(pkt+radiotap_hdr->it_len);
    char* frame_body = ((char*)beacon_fr)+DOT_HDR_SIZE;

    if((beacon_fr->control&0xff)==0x80){
        char* essid_seg = frame_body+12;
        bool done=false;
        for (std::list<struct beacon_info>::iterator it = beacons.begin(); it != beacons.end(); ++it){
            if(!memcmp(it->bssid, beacon_fr->filter, 6)){
                it->beacons++;
                done = true;
                break;
            }
        }
        if(done==false){
            struct beacon_info new_beacon;
            memcpy(new_beacon.bssid, beacon_fr->filter, 6);
            new_beacon.beacons = 1;
            memcpy(new_beacon.essid, essid_seg+2, (int)(*(uint8_t*)essid_seg+1)); 
            beacons.push_back(new_beacon);
        }
    }
    else if(((beacon_fr->control&0xff)==0x40)||((beacon_fr->control&0xff)==0x48)){
        bool done=false;
        for (std::list<struct station_info>::iterator it = stations.begin(); it != stations.end(); ++it){
            if(!memcmp(it->station, beacon_fr->send, 6)){
                it->frames++;
                done = true;
                break;
            }
        }
        if(done==false){
            struct station_info new_station;
            memcpy(new_station.station, beacon_fr->send, 6);
            new_station.frames = 1;
            if((beacon_fr->control&0xff)==0x48)
                memcpy(new_station.bssid, beacon_fr->recv, 6);
            else
                memset(new_station.bssid, 0, 6);
            stations.push_back(new_station);
        }
    }
    else
        return;

    print_dot11();
    return;
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

        airodump(pkt_data);
    }
}