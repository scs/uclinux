#ifndef DRIVER_H
#define DRIVER_H

struct hostap_sta_driver_data {
	unsigned long rx_packets, tx_packets, rx_bytes, tx_bytes;
};


int hostapd_set_iface_flags(hostapd *hapd, int dev_up);
int hostapd_ioctl(hostapd *hapd, struct prism2_hostapd_param *param, int len);
int hostap_ioctl_prism2param(hostapd *hapd, int param, int value);
int hostap_ioctl_setiwessid(hostapd *hapd, char *buf, int len);
int hostapd_set_encryption(hostapd *hapd, const char *alg, u8 *addr,
			   int idx, u8 *key, size_t key_len);
void remove_sta(hostapd *hapd, struct sta_info *sta);
int hostapd_flush(hostapd *hapd);
int hostapd_read_sta_driver_data(hostapd *hapd,
				 struct hostap_sta_driver_data *data,
				 u8 *addr);

#endif /* DRIVER_H */
