#include <unistd.h>

struct ieee80211_radiotap_header {
    u_int8_t        it_version;     /* set to 0 */
    u_int8_t        it_pad;
    u_int16_t       it_len;         /* entire length */
    u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct beacon_frame {
	uint16_t		control;
	#if (CID_ON)
        uint16_t    connect_id;
    #else
        uint8_t     duration;
    #endif
    uint8_t         recv[6];
    uint8_t         send[6];
    uint8_t         filter[6];
	uint16_t	    seq;
};

typedef struct Mac{
    uint8_t mac[6];
}Mac;