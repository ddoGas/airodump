struct beacon_info{
    uint8_t         bssid[6];
    int             beacons;
    char            essid[100];
};

struct probe_info{
	uint8_t         bssid[6];
	uint8_t         station[6];
	int             frames;
};