/*
 * Host AP (software wireless LAN access point) driver for
 * Intersil Prism2/2.5/3 - hostap.o module, common routines
 *
 * Copyright (c) 2001-2002, SSH Communications Security Corp and Jouni Malinen
 * <jkmaline@cc.hut.fi>
 * Copyright (c) 2002-2003, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include <linux/config.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/if_arp.h>
#include <linux/delay.h>
#include <linux/random.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,44))
#include <linux/tqueue.h>
#else
#include <linux/workqueue.h>
#endif
#include <linux/kmod.h>
#include <linux/rtnetlink.h>
#include "hostap_wext.h"
#include <asm/uaccess.h>

#include "hostap_wlan.h"
#include "hostap_80211.h"
#include "hostap_ap.h"
#include "hostap.h"
#include "hostap_crypt.h"

MODULE_AUTHOR("Jouni Malinen");
MODULE_DESCRIPTION("Host AP common routines");
MODULE_LICENSE("GPL");

#ifndef HOSTAP_CRYPT_MODULE
/* Old hostap_crypt module is now part of hostap module. */
#include "hostap_crypt.c"
#else /* HOSTAP_CRYPT_MODULE */
#define hostap_crypto_init()
#define hostap_crypto_deinit()
#endif /* HOSTAP_CRYPT_MODULE */

#define TX_TIMEOUT (2 * HZ)

#define PRISM2_MAX_FRAME_SIZE 2304
#define PRISM2_MIN_MTU 256
/* FIX: */
#define PRISM2_MAX_MTU (PRISM2_MAX_FRAME_SIZE - (6 /* LLC */ + 8 /* WEP */))


/* hostap.c */
static int prism2_wds_add(local_info_t *local, u8 *remote_addr,
			  int rtnl_locked);
static int prism2_wds_del(local_info_t *local, u8 *remote_addr,
			  int rtnl_locked, int do_not_remove);

/* hostap_ap.c */
#ifdef WIRELESS_EXT
static int prism2_ap_get_sta_qual(local_info_t *local, struct sockaddr addr[],
				  struct iw_quality qual[], int buf_size,
				  int aplist);
#if WIRELESS_EXT > 13
static int prism2_ap_translate_scan(struct net_device *dev, char *buffer);
#endif /* WIRELESS_EXT > 13 */
#endif /* WIRELESS_EXT */
static int prism2_hostapd(struct ap_data *ap,
			  struct prism2_hostapd_param *param);
static void * ap_crypt_get_ptrs(struct ap_data *ap, u8 *addr, int permanent,
				struct prism2_crypt_data ***crypt);
static void ap_control_kickall(struct ap_data *ap);
#ifndef PRISM2_NO_KERNEL_IEEE80211_MGMT
static int ap_control_add_mac(struct mac_restrictions *mac_restrictions,
			      u8 *mac);
static int ap_control_del_mac(struct mac_restrictions *mac_restrictions,
			      u8 *mac);
static void ap_control_flush_macs(struct mac_restrictions *mac_restrictions);
static int ap_control_kick_mac(struct ap_data *ap, struct net_device *dev,
			       u8 *mac);
#endif /* !PRISM2_NO_KERNEL_IEEE80211_MGMT */


#ifdef WIRELESS_EXT
static const long freq_list[] = { 2412, 2417, 2422, 2427, 2432, 2437, 2442,
				  2447, 2452, 2457, 2462, 2467, 2472, 2484 };
#define FREQ_COUNT (sizeof(freq_list) / sizeof(freq_list[0]))
#endif /* WIRELESS_EXT */


/* See IEEE 802.1H for LLC/SNAP encapsulation/decapsulation */
/* Ethernet-II snap header (RFC1042 for most EtherTypes) */
static unsigned char rfc1042_header[] =
{ 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };
/* Bridge-Tunnel header (for EtherTypes ETH_P_AARP and ETH_P_IPX) */
static unsigned char bridge_tunnel_header[] =
{ 0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8 };
/* No encapsulation header if EtherType < 0x600 (=length) */


/* FIX: these could be compiled separately and linked together to hostap.o */
#include "hostap_ap.c"
#include "hostap_info.c"
#include "hostap_ioctl.c"
#include "hostap_proc.c"
#include "hostap_80211_rx.c"


struct net_device * hostap_add_interface(struct local_info *local,
					 int type, int rtnl_locked,
					 const char *name)
{
	struct net_device *dev, *mdev;
	struct hostap_interface *iface;
	int ret;

	dev = alloc_etherdev(sizeof(struct hostap_interface));
	if (dev == NULL)
		return NULL;

	iface = dev->priv;
	iface->dev = dev;
	iface->local = local;
	iface->type = type;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0))
	dev->name = iface->name;
#endif
	list_add(&iface->list, &local->hostap_interfaces);

	mdev = local->dev;
	memcpy(dev->dev_addr, mdev->dev_addr, ETH_ALEN);
	dev->base_addr = mdev->base_addr;
	dev->irq = mdev->irq;
	dev->mem_start = mdev->mem_start;
	dev->mem_end = mdev->mem_end;

	hostap_setup_dev(dev, local, 0);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0))
	dev->destructor = free_netdev;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,0))
	/* Linux 2.4.x uses dev entry (reads dev->features) after
	 * dev->destructor has returned, so must not free struct net_device
	 * here. Set NETIF_F_DYNALLOC flag so that netdev_finish_unregister()
	 * frees the entry. */
	dev->features |= NETIF_F_DYNALLOC;
#endif

	sprintf(dev->name, "%s%s", mdev->name, name);
	if (!rtnl_locked)
		rtnl_lock();

	ret = 0;
	if (strchr(dev->name, '%'))
		ret = dev_alloc_name(dev, dev->name);

	if (ret >= 0)
		ret = register_netdevice(dev);

	if (!rtnl_locked)
		rtnl_unlock();

	if (ret < 0) {
		printk(KERN_WARNING "%s: failed to add new netdevice!\n",
		       dev->name);
		free_netdev(dev);
		return NULL;
	}

	printk(KERN_DEBUG "%s: registered netdevice %s\n",
	       mdev->name, dev->name);

	return dev;
}


void hostap_remove_interface(struct net_device *dev, int rtnl_locked,
			     int remove_from_list)
{
	if (!dev)
		return;

	if (remove_from_list) {
		struct hostap_interface *iface;
		iface = dev->priv;
		list_del(&iface->list);
	}
	if (rtnl_locked)
		unregister_netdevice(dev);
	else
		unregister_netdev(dev);

	/* dev->destructor = free_netdev() will free the device data, including
	 * private data, when removing the device */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0))
	/* Except for the compatibility case, which did not use
	 * dev->destructor.. */
	free_netdev(dev);
#endif
}


static inline int prism2_wds_special_addr(u8 *addr)
{
	if (addr[0] || addr[1] || addr[2] || addr[3] || addr[4] || addr[5])
		return 0;

	return 1;
}


static int prism2_wds_add(local_info_t *local, u8 *remote_addr,
			  int rtnl_locked)
{
	struct net_device *dev;
	struct list_head *ptr;
	struct hostap_interface *iface, *empty, *match;

	empty = match = NULL;
	read_lock_bh(&local->iface_lock);
	list_for_each(ptr, &local->hostap_interfaces) {
		iface = list_entry(ptr, struct hostap_interface, list);
		if (iface->type != HOSTAP_INTERFACE_WDS)
			continue;

		if (prism2_wds_special_addr(iface->u.wds.remote_addr))
			empty = iface;
		else if (memcmp(iface->u.wds.remote_addr, remote_addr,
				ETH_ALEN) == 0) {
			match = iface;
			break;
		}
	}
	if (!match && empty) {
		/* take pre-allocated entry into use */
		memcpy(empty->u.wds.remote_addr, remote_addr, ETH_ALEN);
	}

	if (!match && empty) {
		read_unlock_bh(&local->iface_lock);
		printk(KERN_DEBUG "%s: using pre-allocated WDS netdevice %s\n",
		       local->dev->name, empty->dev->name);
		return 0;
	}
	read_unlock_bh(&local->iface_lock);

	if (!prism2_wds_special_addr(remote_addr)) {
		if (match)
			return -EEXIST;
		hostap_add_sta(local->ap, remote_addr);
	}

	if (local->wds_connections >= local->wds_max_connections)
		return -ENOBUFS;

	/* verify that there is room for wds# postfix in the interface name */
	if (strlen(local->dev->name) > IFNAMSIZ - 5) {
		printk(KERN_DEBUG "'%s' too long base device name\n",
		       local->dev->name);
		return -EINVAL;
	}

	dev = hostap_add_interface(local, HOSTAP_INTERFACE_WDS, rtnl_locked,
				   "wds%d");
	if (dev == NULL)
		return -ENOMEM;

	iface = dev->priv;
	memcpy(iface->u.wds.remote_addr, remote_addr, ETH_ALEN);

	local->wds_connections++;

	return 0;
}


static int prism2_wds_del(local_info_t *local, u8 *remote_addr,
			  int rtnl_locked, int do_not_remove)
{
	unsigned long flags;
	struct list_head *ptr;
	struct hostap_interface *iface, *selected = NULL;

	write_lock_irqsave(&local->iface_lock, flags);
	list_for_each(ptr, &local->hostap_interfaces) {
		iface = list_entry(ptr, struct hostap_interface, list);
		if (iface->type != HOSTAP_INTERFACE_WDS)
			continue;

		if (memcmp(iface->u.wds.remote_addr, remote_addr,
			   ETH_ALEN) == 0) {
			selected = iface;
			break;
		}
	}
	if (selected && !do_not_remove)
		list_del(&selected->list);
	write_unlock_irqrestore(&local->iface_lock, flags);

	if (selected) {
		if (do_not_remove)
			memset(selected->u.wds.remote_addr, 0, ETH_ALEN);
		else {
			hostap_remove_interface(selected->dev, rtnl_locked, 0);
			local->wds_connections--;
		}
	}

	return selected ? 0 : -ENODEV;
}


u16 hostap_tx_callback_register(local_info_t *local,
				void (*func)(struct sk_buff *, int ok, void *),
				void *data)
{
	unsigned long flags;
	struct hostap_tx_callback_info *entry;

	entry = (struct hostap_tx_callback_info *) kmalloc(sizeof(*entry),
							   GFP_ATOMIC);
	if (entry == NULL)
		return 0;

	entry->func = func;
	entry->data = data;

	spin_lock_irqsave(&local->lock, flags);
	entry->idx = local->tx_callback ? local->tx_callback->idx + 1 : 1;
	entry->next = local->tx_callback;
	local->tx_callback = entry;
	spin_unlock_irqrestore(&local->lock, flags);

	return entry->idx;
}


int hostap_tx_callback_unregister(local_info_t *local, u16 idx)
{
	unsigned long flags;
	struct hostap_tx_callback_info *cb, *prev = NULL;

	spin_lock_irqsave(&local->lock, flags);
	cb = local->tx_callback;
	while (cb != NULL && cb->idx != idx) {
		prev = cb;
		cb = cb->next;
	}
	if (cb) {
		if (prev == NULL)
			local->tx_callback = cb->next;
		else
			prev->next = cb->next;
		kfree(cb);
	}
	spin_unlock_irqrestore(&local->lock, flags);

	return cb ? 0 : -1;
}


/* val is in host byte order */
int hostap_set_word(struct net_device *dev, int rid, u16 val)
{
	struct hostap_interface *iface = dev->priv;
	u16 tmp = cpu_to_le16(val);
	return iface->local->func->set_rid(dev, rid, &tmp, 2);
}


int hostap_set_string(struct net_device *dev, int rid, const char *val)
{
	struct hostap_interface *iface = dev->priv;
	char buf[MAX_SSID_LEN + 2];
	int len;

	len = strlen(val);
	if (len > MAX_SSID_LEN)
		return -1;
	memset(buf, 0, sizeof(buf));
	buf[0] = len; /* little endian 16 bit word */
	memcpy(buf + 2, val, len);

	return iface->local->func->set_rid(dev, rid, &buf, MAX_SSID_LEN + 2);
}


u16 hostap_get_porttype(local_info_t *local)
{
	if (local->iw_mode == IW_MODE_ADHOC && local->pseudo_adhoc)
		return HFA384X_PORTTYPE_PSEUDO_IBSS;
	if (local->iw_mode == IW_MODE_ADHOC)
		return HFA384X_PORTTYPE_IBSS;
	if (local->iw_mode == IW_MODE_INFRA)
		return HFA384X_PORTTYPE_BSS;
	if (local->iw_mode == IW_MODE_REPEAT)
		return HFA384X_PORTTYPE_WDS;
	if (local->iw_mode == IW_MODE_MONITOR)
		return HFA384X_PORTTYPE_PSEUDO_IBSS;
	return HFA384X_PORTTYPE_HOSTAP;
}


int hostap_set_encryption(local_info_t *local)
{
	u16 val;
	int i, keylen, len, idx;
	char keybuf[WEP_KEY_LEN + 1];
	enum { NONE, WEP, OTHER } encrypt_type;

	if (local->crypt == NULL || local->crypt->ops == NULL)
		encrypt_type = NONE;
	else if (strcmp(local->crypt->ops->name, "WEP") == 0)
		encrypt_type = WEP;
	else
		encrypt_type = OTHER;

	if (local->func->get_rid(local->dev, HFA384X_RID_CNFWEPFLAGS, &val, 2,
				 1) < 0) {
		printk(KERN_DEBUG "Could not read current WEP flags.\n");
		goto fail;
	}
	le16_to_cpus(&val);

	if (encrypt_type != NONE)
		val |= HFA384X_WEPFLAGS_PRIVACYINVOKED;
	else
		val &= ~HFA384X_WEPFLAGS_PRIVACYINVOKED;

	if (local->open_wep || encrypt_type == NONE ||
	    (local->ieee_802_1x && local->host_decrypt))
		val &= ~HFA384X_WEPFLAGS_EXCLUDEUNENCRYPTED;
	else
		val |= HFA384X_WEPFLAGS_EXCLUDEUNENCRYPTED;

	if (encrypt_type != NONE &&
	    (encrypt_type == OTHER || local->host_encrypt))
		val |= HFA384X_WEPFLAGS_HOSTENCRYPT;
	else
		val &= ~HFA384X_WEPFLAGS_HOSTENCRYPT;
	if (encrypt_type != NONE &&
	    (encrypt_type == OTHER || local->host_decrypt))
		val |= HFA384X_WEPFLAGS_HOSTDECRYPT;
	else
		val &= ~HFA384X_WEPFLAGS_HOSTDECRYPT;

	if (hostap_set_word(local->dev, HFA384X_RID_CNFWEPFLAGS, val)) {
		printk(KERN_DEBUG "Could not write new WEP flags (0x%x)\n",
		       val);
		goto fail;
	}

	if (encrypt_type != WEP)
		return 0;

	/* 104-bit support seems to require that all the keys are set to the
	 * same keylen */
	keylen = 6; /* first 5 octets */
	idx = local->crypt->ops->get_key_idx(local->crypt->priv);
	len = local->crypt->ops->get_key(idx, keybuf, sizeof(keybuf),
					 local->crypt->priv);
	if (idx >= 0 && idx < WEP_KEYS && len > 5)
		keylen = WEP_KEY_LEN + 1; /* first 13 octets */

	for (i = 0; i < WEP_KEYS; i++) {
		memset(keybuf, 0, sizeof(keybuf));
		(void) local->crypt->ops->get_key(i, keybuf, sizeof(keybuf),
						  local->crypt->priv);
		if (local->func->set_rid(local->dev,
					 HFA384X_RID_CNFDEFAULTKEY0 + i,
					 keybuf, keylen)) {
			printk(KERN_DEBUG "Could not set key %d (len=%d)\n",
			       i, keylen);
			goto fail;
		}
	}
	if (hostap_set_word(local->dev, HFA384X_RID_CNFWEPDEFAULTKEYID, idx)) {
		printk(KERN_DEBUG "Could not set default keyid %d\n", idx);
		goto fail;
	}

	return 0;

 fail:
	printk(KERN_DEBUG "%s: encryption setup failed\n", local->dev->name);
	return -1;
}


int hostap_set_antsel(local_info_t *local)
{
	u16 val;
	int ret = 0;

	if (local->antsel_tx != HOSTAP_ANTSEL_DO_NOT_TOUCH &&
	    local->func->cmd(local->dev, HFA384X_CMDCODE_READMIF,
			     HFA386X_CR_TX_CONFIGURE,
			     NULL, &val) == 0) {
		val &= ~(BIT(2) | BIT(1));
		switch (local->antsel_tx) {
		case HOSTAP_ANTSEL_DIVERSITY:
			val |= BIT(1);
			break;
		case HOSTAP_ANTSEL_LOW:
			break;
		case HOSTAP_ANTSEL_HIGH:
			val |= BIT(2);
			break;
		}

		if (local->func->cmd(local->dev, HFA384X_CMDCODE_WRITEMIF,
				     HFA386X_CR_TX_CONFIGURE, &val, NULL)) {
			printk(KERN_INFO "%s: setting TX AntSel failed\n",
			       local->dev->name);
			ret = -1;
		}
	}

	if (local->antsel_rx != HOSTAP_ANTSEL_DO_NOT_TOUCH &&
	    local->func->cmd(local->dev, HFA384X_CMDCODE_READMIF,
			     HFA386X_CR_RX_CONFIGURE,
			     NULL, &val) == 0) {
		val &= ~(BIT(1) | BIT(0));
		switch (local->antsel_rx) {
		case HOSTAP_ANTSEL_DIVERSITY:
			break;
		case HOSTAP_ANTSEL_LOW:
			val |= BIT(0);
			break;
		case HOSTAP_ANTSEL_HIGH:
			val |= BIT(0) | BIT(1);
			break;
		}

		if (local->func->cmd(local->dev, HFA384X_CMDCODE_WRITEMIF,
				     HFA386X_CR_RX_CONFIGURE, &val, NULL)) {
			printk(KERN_INFO "%s: setting RX AntSel failed\n",
			       local->dev->name);
			ret = -1;
		}
	}

	return ret;
}


int hostap_set_roaming(local_info_t *local)
{
	u16 val;

	switch (local->host_roaming) {
	case 1:
		val = HFA384X_ROAMING_HOST;
		break;
	case 2:
		val = HFA384X_ROAMING_DISABLED;
		break;
	case 0:
	default:
		val = HFA384X_ROAMING_FIRMWARE;
		break;
	}

	return hostap_set_word(local->dev, HFA384X_RID_CNFROAMINGMODE, val);
}


int hostap_set_auth_algs(local_info_t *local)
{
	int val = local->auth_algs;
	/* At least STA f/w v0.6.2 seems to have issues with cnfAuthentication
	 * set to include both Open and Shared Key flags. It tries to use
	 * Shared Key authentication in that case even if WEP keys are not
	 * configured.. STA f/w v0.7.6 is able to handle such configuration,
	 * but it is unknown when this was fixed between 0.6.2 .. 0.7.6. */
	if (local->sta_fw_ver < PRISM2_FW_VER(0,7,0) &&
	    val != PRISM2_AUTH_OPEN && val != PRISM2_AUTH_SHARED_KEY)
		val = PRISM2_AUTH_OPEN;

	if (hostap_set_word(local->dev, HFA384X_RID_CNFAUTHENTICATION, val)) {
		printk(KERN_INFO "%s: cnfAuthentication setting to 0x%x "
		       "failed\n", local->dev->name, local->auth_algs);
		return -EINVAL;
	}

	return 0;
}


void hostap_dump_rx_header(const char *name, const struct hfa384x_rx_frame *rx)
{
	u16 status, fc;

	status = __le16_to_cpu(rx->status);

	printk(KERN_DEBUG "%s: RX status=0x%04x (port=%d, type=%d, "
	       "fcserr=%d) silence=%d signal=%d rate=%d rxflow=%d; "
	       "jiffies=%ld\n",
	       name, status, (status >> 8) & 0x07, status >> 13, status & 1,
	       rx->silence, rx->signal, rx->rate, rx->rxflow, jiffies);

	fc = __le16_to_cpu(rx->frame_control);
	printk(KERN_DEBUG "   FC=0x%04x (type=%d:%d) dur=0x%04x seq=0x%04x "
	       "data_len=%d%s%s\n",
	       fc, WLAN_FC_GET_TYPE(fc), WLAN_FC_GET_STYPE(fc),
	       __le16_to_cpu(rx->duration_id), __le16_to_cpu(rx->seq_ctrl),
	       __le16_to_cpu(rx->data_len),
	       fc & WLAN_FC_TODS ? " [ToDS]" : "",
	       fc & WLAN_FC_FROMDS ? " [FromDS]" : "");

	printk(KERN_DEBUG "   A1=" MACSTR " A2=" MACSTR " A3=" MACSTR " A4="
	       MACSTR "\n",
	       MAC2STR(rx->addr1), MAC2STR(rx->addr2), MAC2STR(rx->addr3),
	       MAC2STR(rx->addr4));

	printk(KERN_DEBUG "   dst=" MACSTR " src=" MACSTR " len=%d\n",
	       MAC2STR(rx->dst_addr), MAC2STR(rx->src_addr),
	       __be16_to_cpu(rx->len));
}


void hostap_dump_tx_header(const char *name, const struct hfa384x_tx_frame *tx)
{
	u16 fc;

	printk(KERN_DEBUG "%s: TX status=0x%04x retry_count=%d tx_rate=%d "
	       "tx_control=0x%04x; jiffies=%ld\n",
	       name, __le16_to_cpu(tx->status), tx->retry_count, tx->tx_rate,
	       __le16_to_cpu(tx->tx_control), jiffies);

	fc = __le16_to_cpu(tx->frame_control);
	printk(KERN_DEBUG "   FC=0x%04x (type=%d:%d) dur=0x%04x seq=0x%04x "
	       "data_len=%d%s%s\n",
	       fc, WLAN_FC_GET_TYPE(fc), WLAN_FC_GET_STYPE(fc),
	       __le16_to_cpu(tx->duration_id), __le16_to_cpu(tx->seq_ctrl),
	       __le16_to_cpu(tx->data_len),
	       fc & WLAN_FC_TODS ? " [ToDS]" : "",
	       fc & WLAN_FC_FROMDS ? " [FromDS]" : "");

	printk(KERN_DEBUG "   A1=" MACSTR " A2=" MACSTR " A3=" MACSTR " A4="
	       MACSTR "\n",
	       MAC2STR(tx->addr1), MAC2STR(tx->addr2), MAC2STR(tx->addr3),
	       MAC2STR(tx->addr4));

	printk(KERN_DEBUG "   dst=" MACSTR " src=" MACSTR " len=%d\n",
	       MAC2STR(tx->dst_addr), MAC2STR(tx->src_addr),
	       __be16_to_cpu(tx->len));
}


/* TODO: share one netif queue for all interfaces and get rid of these
 * functions.. */
/* wake all netif queues in use */
void hostap_netif_wake_queues(struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	struct list_head *ptr;

	read_lock_bh(&local->iface_lock);
	list_for_each(ptr, &local->hostap_interfaces) {
		iface = list_entry(ptr, struct hostap_interface, list);
		netif_wake_queue(iface->dev);
	}
	read_unlock_bh(&local->iface_lock);
}


/* stop all netif queues in use */
void hostap_netif_stop_queues(struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	struct list_head *ptr;

	read_lock_bh(&local->iface_lock);
	list_for_each(ptr, &local->hostap_interfaces) {
		iface = list_entry(ptr, struct hostap_interface, list);
		netif_stop_queue(iface->dev);
	}
	read_unlock_bh(&local->iface_lock);
}


int hostap_80211_header_parse(struct sk_buff *skb, unsigned char *haddr)
{
	memcpy(haddr, skb->mac.raw + 10, ETH_ALEN); /* addr2 */
	return ETH_ALEN;
}


int hostap_80211_prism_header_parse(struct sk_buff *skb, unsigned char *haddr)
{
	if (*(u32 *)skb->mac.raw == LWNG_CAP_DID_BASE) {
		memcpy(haddr, skb->mac.raw +
		       sizeof(struct linux_wlan_ng_prism_hdr) + 10,
		       ETH_ALEN); /* addr2 */
	} else { /* (*(u32 *)skb->mac.raw == htonl(LWNG_CAPHDR_VERSION)) */
		memcpy(haddr, skb->mac.raw +
		       sizeof(struct linux_wlan_ng_cap_hdr) + 10,
		       ETH_ALEN); /* addr2 */
	}
	return ETH_ALEN;
}


int hostap_80211_get_hdrlen(u16 fc)
{
	int hdrlen = 24;

	switch (WLAN_FC_GET_TYPE(fc)) {
	case WLAN_FC_TYPE_DATA:
		if ((fc & WLAN_FC_FROMDS) && (fc & WLAN_FC_TODS))
			hdrlen = 30; /* Addr4 */
		break;
	case WLAN_FC_TYPE_CTRL:
		switch (WLAN_FC_GET_STYPE(fc)) {
		case WLAN_FC_STYPE_CTS:
		case WLAN_FC_STYPE_ACK:
			hdrlen = 10;
			break;
		default:
			hdrlen = 16;
			break;
		}
		break;
	}

	return hdrlen;
}


struct net_device_stats *hostap_get_stats(struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	return &iface->stats;
}


static int prism2_close(struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;

	PDEBUG(DEBUG_FLOW, "%s: prism2_close\n", dev->name);

#ifndef PRISM2_NO_KERNEL_IEEE80211_MGMT
	if (!local->hostapd && dev == local->dev &&
	    (!local->func->card_present || local->func->card_present(local)) &&
	    local->hw_ready && local->ap && local->iw_mode == IW_MODE_MASTER)
		hostap_deauth_all_stas(dev, local->ap, 1);
#endif /* PRISM2_NO_KERNEL_IEEE80211_MGMT */

	if (local->func->dev_close && local->func->dev_close(local))
		return 0;

	if (local->disable_on_close) {
		local->func->hw_shutdown(dev, HOSTAP_HW_ENABLE_CMDCOMPL);
	}

	if (netif_running(dev)) {
		netif_stop_queue(dev);
		netif_device_detach(dev);
	}

	flush_scheduled_work();

#ifdef NEW_MODULE_CODE
	module_put(local->hw_module);
#elif MODULE
	__MOD_DEC_USE_COUNT(local->hw_module);
#endif

	return 0;
}


static int prism2_open(struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;

	PDEBUG(DEBUG_FLOW, "%s: prism2_open\n", dev->name);

	if (local->func->dev_open && local->func->dev_open(local))
		return 1;

#ifdef NEW_MODULE_CODE
	if (!try_module_get(local->hw_module))
		return -ENODEV;
#elif MODULE
	__MOD_INC_USE_COUNT(local->hw_module);
#endif

	if (!local->dev_enabled && local->func->hw_enable(dev, 1)) {
		printk(KERN_WARNING "%s: could not enable MAC port\n",
		       dev->name);
		prism2_close(dev);
		return 1;
	}
	if (!local->dev_enabled)
		prism2_callback(local, PRISM2_CALLBACK_ENABLE);
	local->dev_enabled = 1;

	netif_device_attach(dev);
	netif_start_queue(dev);

	return 0;
}


#ifdef HAVE_SET_MAC_ADDR
static int prism2_set_mac_address(struct net_device *dev, void *p)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	struct list_head *ptr;
	struct sockaddr *addr = p;

	if (local->func->set_rid(dev, HFA384X_RID_CNFOWNMACADDR, addr->sa_data,
				 ETH_ALEN) < 0 || local->func->reset_port(dev))
		return -EINVAL;

	read_lock_bh(&local->iface_lock);
	list_for_each(ptr, &local->hostap_interfaces) {
		iface = list_entry(ptr, struct hostap_interface, list);
		memcpy(iface->dev->dev_addr, addr->sa_data, ETH_ALEN);
	}
	read_unlock_bh(&local->iface_lock);

	return 0;
}
#endif /* HAVE_SET_MAC_ADDR */


/* TODO: to be further implemented as soon as Prism2 fully supports
 *       GroupAddresses and correct documentation is available */
void hostap_set_multicast_list_queue(void *data)
{
	struct net_device *dev = (struct net_device *) data;
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;

	if (hostap_set_word(dev, HFA384X_RID_PROMISCUOUSMODE,
			    local->is_promisc)) {
		printk(KERN_INFO "%s: %sabling promiscuous mode failed\n",
		       dev->name, local->is_promisc ? "en" : "dis");
	}

#ifndef NEW_MODULE_CODE
	MOD_DEC_USE_COUNT;
#endif
}


static void hostap_set_multicast_list(struct net_device *dev)
{
#if 0
	/* FIX: promiscuous mode seems to be causing a lot of problems with
	 * some station firmware versions (FCSErr frames, invalid MACPort, etc.
	 * corrupted incoming frames). This code is now commented out while the
	 * problems are investigated. */
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;

	if ((dev->flags & IFF_ALLMULTI) || (dev->flags & IFF_PROMISC)) {
		local->is_promisc = 1;
	} else {
		local->is_promisc = 0;
	}

	PRISM2_SCHEDULE_TASK(&local->set_multicast_list_queue);
#endif
}


static int prism2_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < PRISM2_MIN_MTU || new_mtu > PRISM2_MAX_MTU)
		return -EINVAL;

	dev->mtu = new_mtu;
	return 0;
}


#ifdef HAVE_TX_TIMEOUT
static void prism2_tx_timeout(struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	struct hfa384x_regs regs;

	printk(KERN_WARNING "%s Tx timed out! Resetting card\n", dev->name);
	hostap_netif_stop_queues(dev);

	local->func->read_regs(dev, &regs);
	printk(KERN_DEBUG "%s: CMD=%04x EVSTAT=%04x "
	       "OFFSET0=%04x OFFSET1=%04x SWSUPPORT0=%04x\n",
	       dev->name, regs.cmd, regs.evstat, regs.offset0, regs.offset1,
	       regs.swsupport0);

	local->func->schedule_reset(local);
}
#endif /* HAVE_TX_TIMEOUT */


void hostap_setup_dev(struct net_device *dev, local_info_t *local,
		      int main_dev)
{
	ether_setup(dev);

	/* kernel callbacks */
	dev->get_stats = hostap_get_stats;
#ifdef WIRELESS_EXT
	dev->get_wireless_stats = main_dev ? hostap_get_wireless_stats : NULL;
#if WIRELESS_EXT > 12
	dev->wireless_handlers =
		(struct iw_handler_def *) &hostap_iw_handler_def;
#endif /* WIRELESS_EXT > 12 */
#ifdef HAVE_PRIVATE_IOCTL
	dev->do_ioctl = main_dev ? hostap_ioctl : NULL;
#endif
#endif /* WIRELESS_EXT */
	dev->open = prism2_open;
	dev->stop = prism2_close;
	if (local->func)
		dev->hard_start_xmit = local->func->tx;
	else
		printk(KERN_WARNING "hostap_setup_dev: local->func == NULL\n");
#ifdef HAVE_SET_MAC_ADDR
	dev->set_mac_address = prism2_set_mac_address;
#endif /* HAVE_SET_MAC_ADDR */
#ifdef HAVE_MULTICAST
	dev->set_multicast_list = hostap_set_multicast_list;
#endif
#ifdef HAVE_CHANGE_MTU
	dev->change_mtu = prism2_change_mtu;
#endif
#ifdef HAVE_TX_TIMEOUT
	dev->tx_timeout = prism2_tx_timeout;
	dev->watchdog_timeo = TX_TIMEOUT;
#endif

	dev->mtu = local->mtu;

	netif_stop_queue(dev);
}


static int hostap_enable_hostapd(local_info_t *local, int rtnl_locked)
{
	struct net_device *dev = local->dev;

	if (local->apdev)
		return -EEXIST;

	printk(KERN_DEBUG "%s: enabling hostapd mode\n", dev->name);

	local->apdev = hostap_add_interface(local, HOSTAP_INTERFACE_AP,
					    rtnl_locked, "ap");
	if (local->apdev == NULL)
		return -ENOMEM;

	local->apdev->hard_start_xmit = local->func->tx_80211;
	local->apdev->type = ARPHRD_IEEE80211;
	local->apdev->hard_header_parse = hostap_80211_header_parse;

	local->stadev = hostap_add_interface(local, HOSTAP_INTERFACE_STA,
					     rtnl_locked, "sta");
	if (local->stadev == NULL)
		return -ENOMEM;

	return 0;
}


static int hostap_disable_hostapd(local_info_t *local, int rtnl_locked)
{
	struct net_device *dev = local->dev;

	printk(KERN_DEBUG "%s: disabling hostapd mode\n", dev->name);

	hostap_remove_interface(local->apdev, rtnl_locked, 1);
	local->apdev = NULL;

	hostap_remove_interface(local->stadev, rtnl_locked, 1);
	local->stadev = NULL;

	return 0;
}


int hostap_set_hostapd(local_info_t *local, int val, int rtnl_locked)
{
	if (val < 0 || val > 1)
		return -EINVAL;

	if (local->hostapd == val)
		return 0;

	local->hostapd = val;

	if (val)
		return hostap_enable_hostapd(local, rtnl_locked);
	else
		return hostap_disable_hostapd(local, rtnl_locked);
}


struct proc_dir_entry *hostap_proc;

static int __init hostap_init(void)
{
	hostap_crypto_init();

	if (proc_net != NULL) {
		hostap_proc = proc_mkdir("hostap", proc_net);
		if (!hostap_proc)
			printk(KERN_WARNING "Failed to mkdir "
			       "/proc/net/hostap\n");
	} else
		hostap_proc = NULL;

	return 0;
}


static void __exit hostap_exit(void)
{
	if (hostap_proc != NULL) {
		hostap_proc = NULL;
		remove_proc_entry("hostap", proc_net);
	}

	hostap_crypto_deinit();
}


EXPORT_SYMBOL(hostap_set_word);
EXPORT_SYMBOL(hostap_set_string);
EXPORT_SYMBOL(hostap_get_porttype);
EXPORT_SYMBOL(hostap_set_encryption);
EXPORT_SYMBOL(hostap_set_antsel);
EXPORT_SYMBOL(hostap_set_roaming);
EXPORT_SYMBOL(hostap_set_auth_algs);
EXPORT_SYMBOL(hostap_dump_rx_header);
EXPORT_SYMBOL(hostap_dump_tx_header);
EXPORT_SYMBOL(hostap_netif_wake_queues);
EXPORT_SYMBOL(hostap_netif_stop_queues);
EXPORT_SYMBOL(hostap_80211_header_parse);
EXPORT_SYMBOL(hostap_80211_prism_header_parse);
EXPORT_SYMBOL(hostap_80211_get_hdrlen);
EXPORT_SYMBOL(hostap_get_stats);
EXPORT_SYMBOL(hostap_setup_dev);
EXPORT_SYMBOL(hostap_proc);
EXPORT_SYMBOL(hostap_set_multicast_list_queue);
EXPORT_SYMBOL(hostap_set_hostapd);
EXPORT_SYMBOL(hostap_add_interface);
EXPORT_SYMBOL(hostap_remove_interface);

module_init(hostap_init);
module_exit(hostap_exit);
