#ifndef HOSTAPD_H
#define HOSTAPD_H

#include "common.h"
#include "ap.h"

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

#include "hostap_common.h"
#include "config.h"


struct ieee80211_hdr {
	u16 frame_control;
	u16 duration_id;
	u8 addr1[6];
	u8 addr2[6];
	u8 addr3[6];
	u16 seq_ctrl;
	/* followed by 'u8 addr4[6];' if ToDS and FromDS is set in data frame
	 */
} __attribute__ ((packed));

#define IEEE80211_DA_FROMDS addr1
#define IEEE80211_BSSID_FROMDS addr2
#define IEEE80211_SA_FROMDS addr3

#define IEEE80211_HDRLEN (sizeof(struct ieee80211_hdr))

#define IEEE80211_FC(type, stype) host_to_le16((type << 2) | (stype << 4))

/* MTU to be set for the wlan#ap device; this is mainly needed for IEEE 802.1X
 * frames that might be longer than normal default MTU and they are not
 * fragmented */
#define HOSTAPD_MTU 2290

extern unsigned char rfc1042_header[6];

typedef struct hostapd_data {
	struct hostapd_config *conf;
	char *config_fname;

	int sock; /* raw packet socket for driver access */
	int ioctl_sock; /* socket for ioctl() use */
	u8 own_addr[6];

	int num_sta; /* number of entries in sta_list */
	struct sta_info *sta_list; /* STA info list head */
	struct sta_info *sta_hash[STA_HASH_SIZE];

	/* pointers to STA info; based on allocated AID or NULL if AID free
	 * AID is in the range 1-2007, so sta_aid[0] corresponders to AID 1
	 * and so on
	 */
	struct sta_info *sta_aid[MAX_AID_TABLE_SIZE];


	u8 *default_wep_key;
	u8 default_wep_key_idx;

	struct radius_client_data *radius;

	u16 iapp_identifier; /* next IAPP identifier */
	struct in_addr iapp_own, iapp_broadcast;
	int iapp_udp_sock;
	int iapp_packet_sock;

	enum { DO_NOT_ASSOC = 0, WAIT_BEACON, AUTHENTICATE, ASSOCIATE,
	       ASSOCIATED } assoc_ap_state;
	char assoc_ap_ssid[33];
	int assoc_ap_ssid_len;
	u16 assoc_ap_aid;

	struct hostapd_cached_radius_acl *acl_cache;
	struct hostapd_acl_query_data *acl_queries;
} hostapd;


void hostapd_new_assoc_sta(hostapd *hapd, struct sta_info *sta);
void hostapd_logger(hostapd *hapd, u8 *addr, unsigned int module, int level,
		    char *fmt, ...) __attribute__ ((format (printf, 5, 6)));


#define HOSTAPD_DEBUG(level, args...) \
do { \
	if (hapd->conf->debug >= (level)) \
		printf(args); \
} while (0)

#define HOSTAPD_DEBUG_COND(level) (hapd->conf->debug >= (level))

/* receive.c */
int hostapd_init_sockets(hostapd *hapd);

#endif /* HOSTAPD_H */
