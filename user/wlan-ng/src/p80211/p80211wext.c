/* src/p80211/p80211wext.c
* 
* Glue code to make linux-wlan-ng a happy wireless extension camper.
* 
* original author:  Reyk Floeter <reyk@synack.de>
* Completely re-written by Solomon Peachy <solomon@linux-wlan.com>
*
* Copyright (C) 2002 AbsoluteValue Systems, Inc.  All Rights Reserved.
* --------------------------------------------------------------------
*
* linux-wlan
*
*   The contents of this file are subject to the Mozilla Public
*   License Version 1.1 (the "License"); you may not use this file
*   except in compliance with the License. You may obtain a copy of
*   the License at http://www.mozilla.org/MPL/
*
*   Software distributed under the License is distributed on an "AS
*   IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
*   implied. See the License for the specific language governing
*   rights and limitations under the License.
*
*   Alternatively, the contents of this file may be used under the
*   terms of the GNU Public License version 2 (the "GPL"), in which
*   case the provisions of the GPL are applicable instead of the
*   above.  If you wish to allow the use of your version of this file
*   only under the terms of the GPL and not to allow others to use
*   your version of this file under the MPL, indicate your decision
*   by deleting the provisions above and replace them with the notice
*   and other provisions required by the GPL.  If you do not delete
*   the provisions above, a recipient may use your version of this
*   file under either the MPL or the GPL.
*
* --------------------------------------------------------------------
*/

/*================================================================*/
/* System Includes */

#include <linux/config.h>
#include <linux/version.h>

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>
#if WIRELESS_EXT > 12
#include <net/iw_handler.h>
#endif
#include <linux/if_arp.h>
#include <asm/bitops.h>
#include <asm/uaccess.h>
#include <asm/byteorder.h>

#include <wlan/wlan_compat.h>

/*================================================================*/
/* Project Includes */

#include <wlan/version.h>
#include <wlan/p80211types.h>
#include <wlan/p80211hdr.h>
#include <wlan/p80211conv.h>
#include <wlan/p80211mgmt.h>
#include <wlan/p80211msg.h>
#include <wlan/p80211metastruct.h>
#include <wlan/p80211metadef.h>
#include <wlan/p80211netdev.h>
#include <wlan/p80211ioctl.h>
#include <wlan/p80211req.h>

/* compatibility to wireless extensions */
#ifdef WIRELESS_EXT

/* taken from orinoco.c ;-) */
const long p80211wext_channel_freq[] = {
	2412, 2417, 2422, 2427, 2432, 2437, 2442,
	2447, 2452, 2457, 2462, 2467, 2472, 2484
};

#define NUM_CHANNELS (sizeof(p80211wext_channel_freq) / sizeof(p80211wext_channel_freq[0])) 

/** function declarations =============== */

/* called by /proc/net/wireless */
struct iw_statistics* p80211wext_get_wireless_stats (netdevice_t *dev) 
{
	p80211msg_lnxreq_commsquality_t  quality;
	wlandevice_t *wlandev = (wlandevice_t*)dev->priv;
	struct iw_statistics* wstats = &wlandev->wstats;
	int retval;
	
	DBFENTER;
	
	/* Check */
	if ( (wlandev == NULL) || (wlandev->msdstate != WLAN_MSD_RUNNING) )
		return NULL;

	/* XXX Only valid in station mode */
	wstats->status = 0;

	/* build request message */
	quality.msgcode = DIDmsg_lnxreq_commsquality;
	quality.dbm.data = P80211ENUM_truth_true;
	quality.dbm.status = P80211ENUM_msgitem_status_data_ok;

	/* send message to nsd */
	if ( wlandev->mlmerequest == NULL )
		return NULL;

	retval = (*(wlandev->mlmerequest))(wlandev, (p80211msg_t*) &quality);

	wstats->qual.qual = quality.link.data;    /* overall link quality */
	wstats->qual.level = quality.level.data;  /* instant signal level */
	wstats->qual.noise = quality.noise.data;  /* instant noise level */

	wstats->qual.updated = 7;
	wstats->discard.code = wlandev->rx.decrypt_err;
	wstats->discard.nwid = 0;
	wstats->discard.misc = 0;

#if WIRELESS_EXT > 11	
	wstats->discard.fragment = 0;  // incomplete fragments
	wstats->discard.retries = 0;   // tx retries.
	wstats->miss.beacon = 0;
#endif

	DBFEXIT;
	
	return wstats;
}

static int p80211wext_giwname(netdevice_t *dev,
			      struct iw_request_info *info,
			      char *name, char *extra)
{
	DBFENTER;

	strcpy(name, "IEEE 802.11-b");
	/* "802.11-DS" if we're <= 2MBps */
	// XXX fixme eventually.

	DBFEXIT;
	return 0;
}

static int p80211wext_giwfreq(netdevice_t *dev,
			      struct iw_request_info *info,
			      struct iw_freq *freq, char *extra)
{
	wlandevice_t *wlandev = (wlandevice_t*)dev->priv;
	p80211item_uint32_t             mibitem;
	p80211msg_dot11req_mibset_t     msg;
	int result;
	int err = 0;

	DBFENTER;

	msg.msgcode = DIDmsg_dot11req_mibget;
	mibitem.did = DIDmib_dot11phy_dot11PhyDSSSTable_dot11CurrentChannel;
	memcpy(&msg.mibattribute.data, &mibitem, sizeof(mibitem));
	result = p80211req_dorequest(wlandev, (UINT8*)&msg);
	
	if (result) {
		err = -EFAULT;
		goto exit;
	}
	
	memcpy(&mibitem, &msg.mibattribute.data, sizeof(mibitem));
	
	if (mibitem.data > NUM_CHANNELS) {
		err = -EFAULT;
		goto exit;
	}
	
	/* convert into frequency instead of a channel */
	freq->e = 1;		
	freq->m = p80211wext_channel_freq[mibitem.data-1] * 100000;

 exit:
	DBFEXIT;
	return err;
}

#if WIRELESS_EXT > 8
static int p80211wext_giwmode(netdevice_t *dev,
			      struct iw_request_info *info,
			      __u32 *mode, char *extra)
{
	wlandevice_t *wlandev = (wlandevice_t*)dev->priv;

	DBFENTER;

	switch (wlandev->macmode) {
	case WLAN_MACMODE_IBSS_STA: 
		*mode = IW_MODE_ADHOC;
		break;
	case WLAN_MACMODE_ESS_STA:
		*mode = IW_MODE_INFRA;
		break;
	case WLAN_MACMODE_ESS_AP:
		*mode = IW_MODE_MASTER;
		break;
	default:
		/* Not set yet. */
		*mode = IW_MODE_AUTO;
	}

	DBFEXIT;
	return 0;
}

static int p80211wext_giwrange(netdevice_t *dev,
			       struct iw_request_info *info,
			       struct iw_point *data, char *extra)
{
        struct iw_range *range = (struct iw_range *) extra;
	int i, val;

	DBFENTER;

#if WIRELESS_EXT > 9
	range->txpower_capa = IW_TXPOW_DBM;
	// XXX what about min/max_pmp, min/max_pmt, etc.
#endif

#if WIRELESS_EXT > 10
	range->we_version_compiled = WIRELESS_EXT;
	range->we_version_source = 13;
	
	range->retry_capa = IW_RETRY_LIMIT;
	range->retry_flags = IW_RETRY_LIMIT;
	range->min_retry = 0;
	range->max_retry = 255;
#endif /* WIRELESS_EXT > 10 */

	range->num_channels = NUM_CHANNELS;

	/* XXX need to filter against the regulatory domain &| active set */
	val = 0;
	for (i = 0; i < NUM_CHANNELS ; i++) {
		range->freq[val].i = i + 1;
		range->freq[val].m = p80211wext_channel_freq[i] * 100000;
		range->freq[val].e = 1;
		val++;
	}

	range->num_frequency = val;
	
	/* Max of /proc/net/wireless */
	range->max_qual.qual = 92;
	range->max_qual.level = 154;
	range->max_qual.noise = 154;
	range->sensitivity = 3;
	// XXX these need to be nsd-specific!

	range->min_rts = 0;
	range->max_rts = 2347;
	range->min_frag = 256;
	range->max_frag = 2346;
	
	range->max_encoding_tokens = NUM_WEPKEYS;
	range->num_encoding_sizes = 2;
	range->encoding_size[0] = 5;
	range->encoding_size[1] = 13;
	
	// XXX what about num_bitrates/throughput?
	range->num_bitrates = 0;

	/* estimated max throughput */
	// XXX need to cap it if we're running at ~2Mbps..
	range->throughput = 5500000;

	DBFEXIT;
	return 0;
}
#endif

static int p80211wext_giwap(netdevice_t *dev,
			    struct iw_request_info *info,
			    struct sockaddr *ap_addr, char *extra)
{

	wlandevice_t *wlandev = (wlandevice_t*)dev->priv;

	DBFENTER;

	memcpy(ap_addr->sa_data, wlandev->bssid, WLAN_BSSID_LEN);
	ap_addr->sa_family = ARPHRD_ETHER;

	DBFEXIT;
	return 0;
}

#if WIRELESS_EXT > 8
static int p80211wext_giwencode(netdevice_t *dev,
				struct iw_request_info *info,
				struct iw_point *erq, char *key)
{
	wlandevice_t *wlandev = (wlandevice_t*)dev->priv;
	int err = 0;
	int i;

	DBFENTER;
	
	if (wlandev->hostwep & HOSTWEP_PRIVACYINVOKED)
		erq->flags = IW_ENCODE_DISABLED;
	else
		erq->flags = IW_ENCODE_ENABLED;

	if (wlandev->hostwep & HOSTWEP_EXCLUDEUNENCRYPTED)
		erq->flags |= IW_ENCODE_RESTRICTED;
	else
		erq->flags |= IW_ENCODE_OPEN;

	i = (erq->flags & IW_ENCODE_INDEX) - 1;

	if (i == -1)
		i = wlandev->hostwep & HOSTWEP_DEFAULTKEY_MASK;

	if ((i < 0) || (i >= NUM_WEPKEYS)) {
		err = -EINVAL;
		goto exit;
	}

	erq->flags |= i + 1;

	/* copy the key from the driver cache as the keys are read-only MIBs */
	erq->length = wlandev->wep_keylens[i];
	memcpy(key, wlandev->wep_keys[i], erq->length);

 exit:
	DBFEXIT;
	return err;
}

static int p80211wext_giwessid(netdevice_t *dev,
			       struct iw_request_info *info,
			       struct iw_point *data, char *essid)
{
	wlandevice_t *wlandev = (wlandevice_t*)dev->priv;
	p80211msg_dot11req_mibset_t     msg;
	p80211item_pstr32_t             pstr;

	int result;
	int err = 0;

	DBFENTER;

	memset(&msg, 0, sizeof(msg));
	memset(&pstr, 0, sizeof(pstr));  
	msg.msgcode = DIDmsg_dot11req_mibget;

	if (wlandev->macmode == WLAN_MACMODE_ESS_AP)
		pstr.did = DIDmib_p2_p2Static_p2CnfOwnSSID;
	else
		pstr.did = DIDmib_dot11smt_dot11StationConfigTable_dot11DesiredSSID;
	
	memcpy(&msg.mibattribute.data, &pstr, sizeof(pstr));
	result = p80211req_dorequest(wlandev, (UINT8*)&msg);
	
	if (result) {
		err = -EFAULT;
		goto exit;
	}
	
	memcpy(&pstr, &msg.mibattribute.data, sizeof(pstr));

	data->flags = 1;
	data->length = pstr.data.len;
	memcpy(essid, pstr.data.data, pstr.data.len);
	
 exit:
	DBFEXIT;
	return err;
}

static int p80211wext_giwrate(netdevice_t *dev,
			      struct iw_request_info *info,
			      struct iw_param *rrq, char *extra)
{
	wlandevice_t *wlandev = (wlandevice_t*)dev->priv;
	p80211item_uint32_t             mibitem;
	p80211msg_dot11req_mibset_t     msg;
	int result;
	int err = 0;

	DBFENTER;

	msg.msgcode = DIDmsg_dot11req_mibget;
	mibitem.did = DIDmib_p2_p2MAC_p2CurrentTxRate;
	memcpy(&msg.mibattribute.data, &mibitem, sizeof(mibitem));
	result = p80211req_dorequest(wlandev, (UINT8*)&msg);
	
	if (result) {
		err = -EFAULT;
		goto exit;
	}

	memcpy(&mibitem, &msg.mibattribute.data, sizeof(mibitem));

	rrq->fixed = 0;   /* can it change? */
	rrq->disabled = 0; 
	rrq->value = 0;

#define		HFA384x_RATEBIT_1			((UINT16)1)
#define		HFA384x_RATEBIT_2			((UINT16)2)
#define		HFA384x_RATEBIT_5dot5			((UINT16)4)
#define		HFA384x_RATEBIT_11			((UINT16)8)

	switch (mibitem.data) {
	case HFA384x_RATEBIT_1:
		rrq->value = 1000000;
		break;
	case HFA384x_RATEBIT_2:
		rrq->value = 2000000;
		break;
	case HFA384x_RATEBIT_5dot5:
		rrq->value = 5500000;
		break;
	case HFA384x_RATEBIT_11:
		rrq->value = 11000000;
		break;
	default:
		err = -EINVAL;
	}
 exit:
	DBFEXIT;
	return err;
}

static int p80211wext_giwrts(netdevice_t *dev,
			     struct iw_request_info *info,
			     struct iw_param *rts, char *extra)
{
	wlandevice_t *wlandev = (wlandevice_t*)dev->priv;
	p80211item_uint32_t             mibitem;
	p80211msg_dot11req_mibset_t     msg;
	int result;
	int err = 0;

	DBFENTER;

	msg.msgcode = DIDmsg_dot11req_mibget;
	mibitem.did = DIDmib_dot11mac_dot11OperationTable_dot11RTSThreshold;
	memcpy(&msg.mibattribute.data, &mibitem, sizeof(mibitem));
	result = p80211req_dorequest(wlandev, (UINT8*)&msg);

	if (result) {
		err = -EFAULT;
		goto exit;
	}

	memcpy(&mibitem, &msg.mibattribute.data, sizeof(mibitem));

	rts->value = mibitem.data;
	rts->disabled = (rts->value == 2347);
	rts->fixed = 1;

 exit:
	DBFEXIT;
	return err;
}

static int p80211wext_giwfrag(netdevice_t *dev,
			      struct iw_request_info *info,
			      struct iw_param *frag, char *extra)
{
	wlandevice_t *wlandev = (wlandevice_t*)dev->priv;
	p80211item_uint32_t             mibitem;
	p80211msg_dot11req_mibset_t     msg;
	int result;
	int err = 0;

	DBFENTER;

	msg.msgcode = DIDmsg_dot11req_mibget;
	mibitem.did = DIDmib_dot11mac_dot11OperationTable_dot11FragmentationThreshold;
	memcpy(&msg.mibattribute.data, &mibitem, sizeof(mibitem));
	result = p80211req_dorequest(wlandev, (UINT8*)&msg);

	if (result) {
		err = -EFAULT;
		goto exit;
	}

	memcpy(&mibitem, &msg.mibattribute.data, sizeof(mibitem));

	frag->value = mibitem.data;
	frag->disabled = (frag->value == 2346);
	frag->fixed = 1;

 exit:
	DBFEXIT;
	return err;
}

#endif  /* WIRELESS_EXT > 8 */

#if WIRELESS_EXT > 10
static int p80211wext_giwretry(netdevice_t *dev,
			       struct iw_request_info *info,
			       struct iw_param *rrq, char *extra)
{
	wlandevice_t *wlandev = (wlandevice_t*)dev->priv;
	p80211item_uint32_t             mibitem;
	p80211msg_dot11req_mibset_t     msg;
	int result;
	int err = 0;
	UINT16 shortretry, longretry, lifetime;

	DBFENTER;

	msg.msgcode = DIDmsg_dot11req_mibget;
	mibitem.did = DIDmib_dot11mac_dot11OperationTable_dot11ShortRetryLimit;

	memcpy(&msg.mibattribute.data, &mibitem, sizeof(mibitem));
	result = p80211req_dorequest(wlandev, (UINT8*)&msg);

	if (result) {
		err = -EFAULT;
		goto exit;
	}

	memcpy(&mibitem, &msg.mibattribute.data, sizeof(mibitem));

	shortretry = mibitem.data;

	mibitem.did = DIDmib_dot11mac_dot11OperationTable_dot11LongRetryLimit;

	memcpy(&msg.mibattribute.data, &mibitem, sizeof(mibitem));
	result = p80211req_dorequest(wlandev, (UINT8*)&msg);

	if (result) {
		err = -EFAULT;
		goto exit;
	}

	memcpy(&mibitem, &msg.mibattribute.data, sizeof(mibitem));

	longretry = mibitem.data;

	mibitem.did = DIDmib_dot11mac_dot11OperationTable_dot11MaxTransmitMSDULifetime;

	memcpy(&msg.mibattribute.data, &mibitem, sizeof(mibitem));
	result = p80211req_dorequest(wlandev, (UINT8*)&msg);

	if (result) {
		err = -EFAULT;
		goto exit;
	}

	memcpy(&mibitem, &msg.mibattribute.data, sizeof(mibitem));

	lifetime = mibitem.data;
	
	rrq->disabled = 0;

	if ((rrq->flags & IW_RETRY_TYPE) == IW_RETRY_LIFETIME) {
		rrq->flags = IW_RETRY_LIFETIME;
		rrq->value = lifetime * 1024;
	} else {
		if (rrq->flags & IW_RETRY_MAX) {
			rrq->flags = IW_RETRY_LIMIT | IW_RETRY_MAX;
			rrq->value = longretry;
		} else {
			rrq->flags = IW_RETRY_LIMIT;
			rrq->value = shortretry;
			if (shortretry != longretry)
				rrq->flags |= IW_RETRY_MIN;
		}
	}

 exit:
	DBFEXIT;
	return err;

}

#endif /* WIRELESS_EXT > 10 */

#if WIRELESS_EXT > 9
static int p80211wext_giwtxpow(netdevice_t *dev,
			       struct iw_request_info *info,
			       struct iw_param *rrq, char *extra)
{
	wlandevice_t *wlandev = (wlandevice_t*)dev->priv;
	p80211item_uint32_t             mibitem;
	p80211msg_dot11req_mibset_t     msg;
	int result;
	int err = 0;

	DBFENTER;

	msg.msgcode = DIDmsg_dot11req_mibget;
	mibitem.did = DIDmib_dot11phy_dot11PhyTxPowerTable_dot11CurrentTxPowerLevel;

	memcpy(&msg.mibattribute.data, &mibitem, sizeof(mibitem));
	result = p80211req_dorequest(wlandev, (UINT8*)&msg);

	if (result) {
		err = -EFAULT;
		goto exit;
	}

	memcpy(&mibitem, &msg.mibattribute.data, sizeof(mibitem));

	// XXX handle OFF by setting disabled = 1;

	rrq->flags = 0; // IW_TXPOW_DBM;
	rrq->disabled = 0;
	rrq->fixed = 0;
	rrq->value = mibitem.data;

 exit:
	DBFEXIT;
	return err;
}
#endif /* WIRELESS_EXT > 9 */

/*
typedef int (*iw_handler)(netdevice_t *dev, struct iw_request_info *info,
                          union iwreq_data *wrqu, char *extra);
*/

#if WIRELESS_EXT > 12
static iw_handler p80211wext_handlers[] =  {
	(iw_handler) NULL,				/* SIOCSIWCOMMIT */
	(iw_handler) p80211wext_giwname,		/* SIOCGIWNAME */
	(iw_handler) NULL,				/* SIOCSIWNWID */
	(iw_handler) NULL,				/* SIOCGIWNWID */
	(iw_handler) NULL,                		/* SIOCSIWFREQ */
	(iw_handler) p80211wext_giwfreq,  		/* SIOCGIWFREQ */
	(iw_handler) NULL,                		/* SIOCSIWMODE */
	(iw_handler) p80211wext_giwmode,       		/* SIOCGIWMODE */
	(iw_handler) NULL,                 		/* SIOCSIWSENS */
	(iw_handler) NULL,                		/* SIOCGIWSENS */
	(iw_handler) NULL, /* not used */     		/* SIOCSIWRANGE */
	(iw_handler) p80211wext_giwrange,      		/* SIOCGIWRANGE */
	(iw_handler) NULL, /* not used */     		/* SIOCSIWPRIV */
	(iw_handler) NULL, /* kernel code */   		/* SIOCGIWPRIV */
	(iw_handler) NULL, /* not used */     		/* SIOCSIWSTATS */
	(iw_handler) NULL, /* kernel code */   		/* SIOCGIWSTATS */
	(iw_handler) NULL,				/* SIOCSIWSPY */
	(iw_handler) NULL,               		/* SIOCGIWSPY */
	(iw_handler) NULL,				/* -- hole -- */
	(iw_handler) NULL,				/* -- hole -- */
	(iw_handler) NULL,              		/* SIOCSIWAP */
	(iw_handler) p80211wext_giwap,         		/* SIOCGIWAP */
	(iw_handler) NULL,				/* -- hole -- */
	(iw_handler) NULL,                  		/* SIOCGIWAPLIST */
#if WIRELESS_EXT > 13
	(iw_handler) NULL,   /* something */		/* SIOCSIWSCAN */
	(iw_handler) NULL,   /* something */		/* SIOCGIWSCAN */
#else /* WIRELESS_EXT > 13 */
	(iw_handler) NULL,	/* null */		/* SIOCSIWSCAN */
	(iw_handler) NULL,	/* null */		/* SIOCGIWSCAN */
#endif /* WIRELESS_EXT > 13 */
	(iw_handler) NULL,                 		/* SIOCSIWESSID */
	(iw_handler) p80211wext_giwessid,      		/* SIOCGIWESSID */
	(iw_handler) NULL,                 		/* SIOCSIWNICKN */
	(iw_handler) p80211wext_giwessid,      		/* SIOCGIWNICKN */
	(iw_handler) NULL,				/* -- hole -- */
	(iw_handler) NULL,				/* -- hole -- */
	(iw_handler) NULL,                		/* SIOCSIWRATE */
	(iw_handler) p80211wext_giwrate,      		/* SIOCGIWRATE */
	(iw_handler) NULL,               		/* SIOCSIWRTS */
	(iw_handler) p80211wext_giwrts,        		/* SIOCGIWRTS */
	(iw_handler) NULL,                		/* SIOCSIWFRAG */
	(iw_handler) p80211wext_giwfrag,   		/* SIOCGIWFRAG */
	(iw_handler) NULL,                 		/* SIOCSIWTXPOW */
	(iw_handler) p80211wext_giwtxpow,  		/* SIOCGIWTXPOW */
	(iw_handler) NULL,                 		/* SIOCSIWRETRY */
	(iw_handler) p80211wext_giwretry,  		/* SIOCGIWRETRY */
	(iw_handler) NULL,                    		/* SIOCSIWENCODE */
	(iw_handler) p80211wext_giwencode,  		/* SIOCGIWENCODE */
	(iw_handler) NULL,                 		/* SIOCSIWPOWER */
	(iw_handler) NULL,                  		/* SIOCGIWPOWER */
};

struct iw_handler_def p80211wext_handler_def = {
	num_standard: sizeof(p80211wext_handlers) / sizeof(iw_handler),
	num_private: 0,
	num_private_args: 0,
        standard: p80211wext_handlers,
	private: NULL,
	private_args: NULL
};

#endif

/* wireless extensions' ioctls */ 
int p80211wext_support_ioctl(netdevice_t *dev, struct ifreq *ifr, int cmd)
{
	wlandevice_t *wlandev = (wlandevice_t*)dev->priv;

#if WIRELESS_EXT < 13
	struct iwreq *iwr = (struct iwreq*)ifr;
#endif

	p80211item_uint32_t             mibitem;
	int err = 0;

	DBFENTER;

	mibitem.status = P80211ENUM_msgitem_status_data_ok;
	
	if ( wlandev->msdstate != WLAN_MSD_RUNNING ) {
		err = -ENODEV;
		goto exit;
	}

	WLAN_LOG_DEBUG(1, "Received wireless extension ioctl #%d.\n", cmd);

	switch (cmd) {
#if WIRELESS_EXT < 13
	case SIOCSIWNAME:  /* unused  */
		err = (-EOPNOTSUPP);
		break;
	case SIOCGIWNAME: /* get name == wireless protocol */
                err = p80211wext_giwname(dev, NULL, (char *) &iwr->u, NULL);
		break;	
	case SIOCSIWNWID:
	case SIOCGIWNWID:
		err = (-EOPNOTSUPP);
		break;

	case SIOCSIWFREQ: /* set channel */
		err = (-EOPNOTSUPP);
		break;
#if 0
		if ( (iwf->e == 0) && (iwf->m <= 1000) ) {
			/* input is a channel number */		
			chan = iwf->m;
		} else {
		/* input is a frequency - search the table */
			for (i = 0; i < (6 - iwf->e); i++)
				mult *= 10;
			
			for (i = 0; i < NUM_CHANNELS; i++)
				if (iwf->m == (prism2wext_channel_freq[i] * mult))
					chan = i+1;
		}

 		/* check for valid channels */ 
		if ((!intval) || (intval > NUM_CHANNELS))
			return (-EFAULT); 
#endif
	case SIOCGIWFREQ: /* get channel */
                err = p80211wext_giwfreq(dev, NULL, &(iwr->u.freq), NULL);
		break;

	case SIOCSIWRANGE:
	case SIOCSIWPRIV:	
	case SIOCSIWAP: /* set access point MAC addresses (BSSID) */	
		err = (-EOPNOTSUPP);
		break;

	case SIOCGIWAP:	/* get access point MAC addresses (BSSID) */
                err = p80211wext_giwap(dev, NULL, &(iwr->u.ap_addr), NULL);
		break;

#if WIRELESS_EXT > 8
	case SIOCSIWMODE: /* set operation mode */
	case SIOCSIWESSID: /* set SSID (network name) */
	case SIOCSIWRATE: /* set default bit rate (bps) */	
		err = (-EOPNOTSUPP);
		break;
		
	case SIOCGIWMODE: /* get operation mode */
		err = p80211wext_giwmode(dev, NULL, &iwr->u.mode, NULL);

		break;
	case SIOCGIWNICKN: /* get node name/nickname */
	case SIOCGIWESSID: /* get SSID */
		if(iwr->u.essid.pointer) {
                        char ssid[IW_ESSID_MAX_SIZE+1];
			memset(ssid, 0, sizeof(ssid));

			err = p80211wext_giwessid(dev, NULL, &iwr->u.essid, ssid);
			if(copy_to_user(iwr->u.essid.pointer, ssid, sizeof(ssid)))
				err = (-EFAULT);
		}
		break;
	case SIOCGIWRATE:
                err = p80211wext_giwrate(dev, NULL, &iwr->u.bitrate, NULL);
		break;
	case SIOCGIWRTS:	
		err = p80211wext_giwrts(dev, NULL, &iwr->u.rts, NULL);	
		break;
	case SIOCGIWFRAG:
		err = p80211wext_giwfrag(dev, NULL, &iwr->u.rts, NULL);	
		break;
	case SIOCGIWENCODE:
		if (!capable(CAP_NET_ADMIN))
			err = -EPERM;
		else if (iwr->u.encoding.pointer) {
			char keybuf[MAX_KEYLEN];
			err = p80211wext_giwencode(dev, NULL,
						     &iwr->u.encoding, keybuf);
			if (copy_to_user(iwr->u.encoding.pointer, keybuf,
					 iwr->u.encoding.length))
				err = -EFAULT;
		}
		break;
	case SIOCGIWAPLIST:	
	case SIOCSIWRTS:
	case SIOCSIWFRAG:	
	case SIOCSIWSENS:
	case SIOCGIWSENS:
	case SIOCSIWNICKN: /* set node name/nickname */	
	case SIOCSIWENCODE: /* set encoding token & mode */	
	case SIOCSIWSPY:
	case SIOCGIWSPY:
	case SIOCSIWPOWER:	
	case SIOCGIWPOWER:
	case SIOCGIWPRIV:
		err = (-EOPNOTSUPP);
		break;
	case SIOCGIWRANGE:
		if(iwr->u.data.pointer != NULL) {
                        struct iw_range range;
                        err = p80211wext_giwrange(dev, NULL, &iwr->u.data,
						  (char *) &range);
			/* Push that up to the caller */
			if (copy_to_user(iwr->u.data.pointer, &range, sizeof(range)))
				err = -EFAULT;
		}
		break;
#endif /* WIRELESS_EXT > 8 */
#if WIRELESS_EXT > 9
	case SIOCSIWTXPOW:
		err = (-EOPNOTSUPP);
		break;	
	case SIOCGIWTXPOW:	
		err = p80211wext_giwtxpow(dev, NULL, &iwr->u.txpower, NULL);
		break;
#endif /* WIRELESS_EXT > 9 */		
#if WIRELESS_EXT > 10
	case SIOCSIWRETRY:	
		err = (-EOPNOTSUPP);
		break;
	case SIOCGIWRETRY:	
		err = p80211wext_giwretry(dev, NULL, &iwr->u.retry, NULL);
		break;
#endif /* WIRELESS_EXT > 10 */		

#endif /* WIRELESS_EXT <= 12 */

	default:
		err = (-EOPNOTSUPP);
		break;
	}

 exit:
	DBFEXIT;
	return (err);
}

#endif /* compatibility to wireless extensions */




