#ifndef HOSTAP_80211_H
#define HOSTAP_80211_H

struct hostap_ieee80211_hdr {
	u16 frame_control;
	u16 duration_id;
	u8 addr1[6];
	u8 addr2[6];
	u8 addr3[6];
	u16 seq_ctrl;
	u8 addr4[6];
} __attribute__ ((packed));

#define IEEE80211_MGMT_HDR_LEN 24
#define IEEE80211_DATA_HDR3_LEN 24
#define IEEE80211_DATA_HDR4_LEN 30


struct hostap_80211_rx_status {
	u32 mac_time;
	u8 signal;
	u8 noise;
	u16 rate; /* in 100 kbps */
};


void hostap_80211_rx(struct net_device *dev, struct sk_buff *skb,
		     struct hostap_80211_rx_status *rx_stats);


/* prism2_rx_80211 'type' argument */
enum {
	PRISM2_RX_MONITOR, PRISM2_RX_MGMT, PRISM2_RX_NON_ASSOC,
	PRISM2_RX_NULLFUNC_ACK
};

int prism2_rx_80211(struct net_device *dev, struct sk_buff *skb,
		    struct hostap_80211_rx_status *rx_stats, int type);
void hostap_80211_rx(struct net_device *dev, struct sk_buff *skb,
		     struct hostap_80211_rx_status *rx_stats);
void hostap_dump_rx_80211(const char *name, struct sk_buff *skb,
			  struct hostap_80211_rx_status *rx_stats);

#endif /* HOSTAP_80211_H */
