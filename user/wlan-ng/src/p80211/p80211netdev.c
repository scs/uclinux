/* src/p80211/p80211knetdev.c
*
* Linux Kernel net device interface
*
* Copyright (C) 1999 AbsoluteValue Systems, Inc.  All Rights Reserved.
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
*
* Inquiries regarding the linux-wlan Open Source project can be
* made directly to:
*
* AbsoluteValue Systems Inc.
* info@linux-wlan.com
* http://www.linux-wlan.com
*
* --------------------------------------------------------------------
*
* Portions of the development of this software were funded by 
* Intersil Corporation as part of PRISM(R) chipset product development.
*
* --------------------------------------------------------------------
*
* The functions required for a Linux network device are defined here.
*
* --------------------------------------------------------------------
*/


/*================================================================*/
/* System Includes */

#define __NO_VERSION__		/* prevent the static definition */

#include <linux/config.h>
#include <linux/version.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/wireless.h>
#if WIRELESS_EXT > 12
#include <net/iw_handler.h>
#endif
#include <linux/etherdevice.h>
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
#include <wlan/p80211netdev.h>
#include <wlan/p80211ioctl.h>
#include <wlan/p80211req.h>
#include <wlan/p80211metastruct.h>
#include <wlan/p80211metadef.h>

/*================================================================*/
/* Local Constants */

#define MAX_WLAN_DEVICES	4	/* At most 3 non-intefering DS cards */

/*================================================================*/
/* Local Macros */


/*================================================================*/
/* Local Types */

/*================================================================*/
/* Local Static Definitions */

static wlandevice_t	*wlandev_index[MAX_WLAN_DEVICES];

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry	*proc_p80211;
#endif

/*================================================================*/
/* Local Function Declarations */

/* Support functions */
static int wlandev_get_index(wlandevice_t  *wlandev);
static void wlandev_clear_index(wlandevice_t  *wlandev);

#ifdef DECLARE_TASKLET
static void p80211netdev_rx_bh(unsigned long arg);
#else
static void p80211netdev_rx_bh(void *arg);
#endif

/* netdevice method functions */
static int p80211knetdev_init( netdevice_t *netdev);
static struct net_device_stats* p80211knetdev_get_stats(netdevice_t *netdev);
static int p80211knetdev_open( netdevice_t *netdev);
static int p80211knetdev_stop( netdevice_t *netdev );
static int p80211knetdev_hard_start_xmit( struct sk_buff *skb, netdevice_t *netdev);
static void p80211knetdev_set_multicast_list(netdevice_t *dev);
static int p80211knetdev_do_ioctl(netdevice_t *dev, struct ifreq *ifr, int cmd);
static int p80211knetdev_set_mac_address(netdevice_t *dev, void *addr);

#ifdef CONFIG_PROC_FS
static int
p80211netdev_proc_read(
	char	*page, 
	char	**start, 
	off_t	offset, 
	int	count,
	int	*eof,
	void	*data);
#endif

/*================================================================*/
/* Function Definitions */

/*----------------------------------------------------------------
* p80211knetdev_startup
*
* Initialize the wlandevice/netdevice part of 802.11 services at 
* load time.
*
* Arguments:
*	none
*
* Returns: 
*	nothing
----------------------------------------------------------------*/
void p80211netdev_startup(void)
{
	DBFENTER;

	memset( wlandev_index, 0, sizeof(wlandev_index));
#ifdef CONFIG_PROC_FS
	if (proc_net != NULL) {
		proc_p80211 = create_proc_entry(
				"p80211", 
				(S_IFDIR|S_IRUGO|S_IXUGO),
				proc_net);
	}
#endif
	DBFEXIT;
	return;
}

/*----------------------------------------------------------------
* p80211knetdev_shutdown
*
* Shutdown the wlandevice/netdevice part of 802.11 services at 
* unload time.
*
* Arguments:
*	none
*
* Returns: 
*	nothing
----------------------------------------------------------------*/
void
p80211netdev_shutdown(void)
{
	DBFENTER;
#ifdef CONFIG_PROC_FS
	if (proc_p80211 != NULL) {
		remove_proc_entry("p80211", proc_net);
	}
#endif
	DBFEXIT;
}

/*----------------------------------------------------------------
* p80211knetdev_init
*
* Init method for a Linux netdevice.  Called in response to
* register_netdev.
*
* Arguments:
*	none
*
* Returns: 
*	nothing
----------------------------------------------------------------*/
int p80211knetdev_init( netdevice_t *netdev)
{
	DBFENTER;
	/* Called in response to register_netdev */
	/* This is usually the probe function, but the probe has */
	/* already been done by the MSD and the create_kdev */
	/* function.  All we do here is return success */
	DBFEXIT;
	return 0;
}


/*----------------------------------------------------------------
* p80211knetdev_get_stats
*
* Statistics retrieval for linux netdevices.  Here we're reporting
* the Linux i/f level statistics.  Hence, for the primary numbers,
* we don't want to report the numbers from the MIB.  Eventually,
* it might be useful to collect some of the error counters though.
*
* Arguments:
*	netdev		Linux netdevice
*
* Returns: 
*	the address of the statistics structure
----------------------------------------------------------------*/
struct net_device_stats*
p80211knetdev_get_stats(netdevice_t *netdev)
{
	wlandevice_t	*wlandev = (wlandevice_t*)netdev->priv;
	DBFENTER;

	/* TODO: review the MIB stats for items that correspond to 
		linux stats */

	DBFEXIT;
	return &(wlandev->linux_stats);
}


/*----------------------------------------------------------------
* p80211knetdev_open
*
* Linux netdevice open method.  Following a successful call here,
* the device is supposed to be ready for tx and rx.  In our
* situation that may not be entirely true due to the state of the
* MAC below.
*
* Arguments:
*	netdev		Linux network device structure
*
* Returns: 
*	zero on success, non-zero otherwise
----------------------------------------------------------------*/
int p80211knetdev_open( netdevice_t *netdev )
{
	int 		result = 0; /* success */
	wlandevice_t	*wlandev = (wlandevice_t*)(netdev->priv);

	DBFENTER;

	/* Check to make sure the MSD is running */
	if ( wlandev->msdstate != WLAN_MSD_RUNNING ) {
		return -ENODEV;
	}

	/* Tell the MSD to open */
	if ( wlandev->open != NULL) {
		result = (*(wlandev->open))(wlandev);
		if ( result == 0 ) {
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,3,43) )
			netdev->interrupt = 0;
#endif
			p80211netdev_start_queue(wlandev);
			wlandev->state = WLAN_DEVICE_OPEN;
		}
	} else {
		result = -EAGAIN;
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* p80211knetdev_stop
*
* Linux netdevice stop (close) method.  Following this call,
* no frames should go up or down through this interface.
*
* Arguments:
*	netdev		Linux network device structure
*
* Returns: 
*	zero on success, non-zero otherwise
----------------------------------------------------------------*/
int p80211knetdev_stop( netdevice_t *netdev )
{
	int		result = 0;
	wlandevice_t	*wlandev = (wlandevice_t*)(netdev->priv);

	DBFENTER;

	if ( wlandev->close != NULL ) {
		result = (*(wlandev->close))(wlandev);
	}

	p80211netdev_stop_queue(wlandev);
	wlandev->state = WLAN_DEVICE_CLOSED;

	DBFEXIT;
	return result;
}

/*----------------------------------------------------------------
* p80211netdev_rx
*
* Frame receive function called by the mac specific driver.
*
* Arguments:
*	wlandev		WLAN network device structure
*	skb		skbuff containing a full 802.11 frame.
* Returns: 
*	nothing
* Side effects:
*	
----------------------------------------------------------------*/
void 
p80211netdev_rx(wlandevice_t *wlandev, struct sk_buff *skb ) 
{
	DBFENTER;

	/* Enqueue for post-irq processing */
	skb_queue_tail(&wlandev->nsd_rxq, skb);
	
#ifdef DECLARE_TASKLET
	tasklet_schedule(&wlandev->rx_bh);
#else
	queue_task(&wlandev->rx_bh, &tq_immediate);
	mark_bh(IMMEDIATE_BH);
#endif
	
        DBFEXIT;
	return;
}

/*----------------------------------------------------------------
* p80211netdev_rx_bh
*
* Deferred processing of all received frames.
*
* Arguments:
*	wlandev		WLAN network device structure
*	skb		skbuff containing a full 802.11 frame.
* Returns: 
*	nothing
* Side effects:
*	
----------------------------------------------------------------*/
#ifdef DECLARE_TASKLET
void
p80211netdev_rx_bh(unsigned long arg)
#else
void
p80211netdev_rx_bh(void *arg)
#endif
{
	wlandevice_t *wlandev = (wlandevice_t *) arg;
	struct sk_buff *skb = NULL; 
	netdevice_t     *dev = wlandev->netdev;

        DBFENTER;

	/* Let's empty our our queue */
	while ( (skb = skb_dequeue(&wlandev->nsd_rxq)) ) {
		if (wlandev->state == WLAN_DEVICE_OPEN) {

			if (dev->type != ARPHRD_ETHER) {
				/* RAW frame; we shouldn't convert it */
				skb->dev->last_rx = jiffies;
				wlandev->linux_stats.rx_packets++;
				wlandev->linux_stats.rx_bytes += skb->len;
				netif_rx(skb);
				continue;
			} else {
				if ( skb_p80211_to_ether(wlandev, wlandev->ethconv, skb) == 0 ) {
					skb->dev->last_rx = jiffies;
					wlandev->linux_stats.rx_packets++;
					wlandev->linux_stats.rx_bytes += skb->len;
					netif_rx(skb);
					continue;
				} 
				WLAN_LOG_DEBUG0(1, "p80211_to_ether failed.\n");
			}
		}
		dev_kfree_skb(skb);
	}

        DBFEXIT;
}


/*----------------------------------------------------------------
* p80211knetdev_hard_start_xmit
*
* Linux netdevice method for transmitting a frame.
*
* Arguments:
*	skb	Linux sk_buff containing the frame.
*	netdev	Linux netdevice.
*
* Side effects:
*	If the lower layers report that buffers are full. netdev->tbusy
*	will be set to prevent higher layers from sending more traffic.
*
*	Note: If this function returns non-zero, higher layers retain
*	      ownership of the skb.
*
* Returns: 
*	zero on success, non-zero on failure.
----------------------------------------------------------------*/
int p80211knetdev_hard_start_xmit( struct sk_buff *skb, netdevice_t *netdev)
{
	int		result = 0;
	int		txresult = -1;
	wlandevice_t	*wlandev = (wlandevice_t*)netdev->priv;
	p80211_hdr_t    p80211_hdr;
	p80211_metawep_t p80211_wep;

	DBFENTER;

	if (skb == NULL ) {
		return 0;
	}

        if (wlandev->state != WLAN_DEVICE_OPEN) {
		return 1;
	}

	memset(&p80211_hdr, 0, sizeof(p80211_hdr_t));
	memset(&p80211_wep, 0, sizeof(p80211_metawep_t));

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,38) )
	if ( test_and_set_bit(0, (void*)&(netdev->tbusy)) != 0 ) {
		/* We've been called w/ tbusy set, has the tx */
		/* path stalled?   */
		WLAN_LOG_DEBUG0(1, "called when tbusy set\n");
		result = 1;
		goto failed;
	} 
#else
	if ( netif_queue_stopped(netdev) ) {
		WLAN_LOG_DEBUG0(1, "called when queue stopped.\n");
		result = 1;
		goto failed;
	}

	netif_stop_queue(netdev);

	/* No timeout handling here, 2.3.38+ kernels call the 
	 * timeout function directly.
	 * TODO: Add timeout handling.
	*/
#endif

	/* Check to see that a valid mode is set */
	switch( wlandev->macmode ) {
	case WLAN_MACMODE_IBSS_STA: 
	case WLAN_MACMODE_ESS_STA:
	case WLAN_MACMODE_ESS_AP:
		break;
	default:
		/* Mode isn't set yet, just drop the frame 
		 * and return success .
		 * TODO: we need a saner way to handle this 
		 */
		if(skb->protocol != ETH_P_80211_RAW) {
			p80211netdev_wake_queue(wlandev);
			WLAN_LOG_NOTICE0(
				"Tx attempt prior to association, frame dropped.\n");
			wlandev->linux_stats.tx_dropped++;
			result = 0;
			goto failed;
		}
		break;
	}
		
	/* Check for raw transmits */
	if(skb->protocol == ETH_P_80211_RAW) {
		if (!capable(CAP_NET_ADMIN)) {
			return(-EPERM);
		}
		/* move the header over */
		memcpy(&p80211_hdr, skb->data, sizeof(p80211_hdr_t));
		skb_pull(skb, sizeof(p80211_hdr_t));
	} else {
		if ( skb_ether_to_p80211(wlandev, wlandev->ethconv, skb, &p80211_hdr, &p80211_wep) != 0 ) {
			/* convert failed */
			WLAN_LOG_DEBUG(1, "ether_to_80211(%d) failed.\n", 
					wlandev->ethconv);
			result = 1;
			goto failed;
		}
	}
	if ( wlandev->txframe == NULL ) {
		result = 1;
		goto failed;
	}

	netdev->trans_start = jiffies;

	wlandev->linux_stats.tx_packets++;
	/* count only the packet payload */
	wlandev->linux_stats.tx_bytes += skb->len;
	
	txresult = (*(wlandev->txframe))(wlandev, skb, &p80211_hdr, &p80211_wep);

	if ( txresult == 0) {
		/* success and more buf */
		/* avail, re: hw_txdata */
		p80211netdev_wake_queue(wlandev);
		result = 0;
	} else if ( txresult == 1 ) { 
		/* success, no more avail */
		WLAN_LOG_DEBUG0(3, "txframe success, no more bufs\n");
		/* netdev->tbusy = 1;  don't set here, irqhdlr */
		/*   may have already cleared it */
		result = 0;
	} else if ( txresult == 2 ) { 
		/* alloc failure, drop frame */
		WLAN_LOG_DEBUG0(3, "txframe returned alloc_fail\n");
		p80211netdev_wake_queue(wlandev);
		result = 1;
	} else { 
		/* buffer full or queue busy */
		WLAN_LOG_DEBUG0(3, "txframe returned full or busy\n");
		p80211netdev_wake_queue(wlandev);
		result = 1;
	}

 failed:
	/* Free up the WEP buffer if it's not the same as the skb */
	if ((p80211_wep.data) && (p80211_wep.data != skb->data))
		kfree(p80211_wep.data);

	/* we always free the skb here, never in a lower level. */
	if (!result)
		dev_kfree_skb(skb);

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* p80211knetdev_set_multicast_list
*
* Called from higher lavers whenever there's a need to set/clear
* promiscuous mode or rewrite the multicast list.
*
* Arguments:
*	none
*
* Returns: 
*	nothing
----------------------------------------------------------------*/
void p80211knetdev_set_multicast_list(netdevice_t *dev)
{
  /* TODO:  real multicast support as well */

        wlandevice_t    *wlandev = (wlandevice_t*)dev->priv;
	p80211msg_dot11req_mibset_t     msg;
	p80211item_uint32_t             mibitem;
	UINT32          arg;
	int             result;

	int             doPromisc = 0;
	
	DBFENTER;
	
	if (dev->flags & IFF_ALLMULTI) {  
		/* Set a MIB for 'allmulti_rx'?  */
		doPromisc = 1;
	}

	if (dev->flags & IFF_PROMISC) {
		doPromisc = 1;
	}

	// XXX if we're in AP mode, don't do this.

        mibitem.did = DIDmib_p2_p2Dynamic_p2PromiscuousMode;
        mibitem.status = (UINT16) P80211ENUM_msgitem_status_data_ok;
 
        msg.msgcode = DIDmsg_dot11req_mibset;
 
        arg = P80211ENUM_truth_false;
        if (doPromisc)
                arg = P80211ENUM_truth_true;
  
        memcpy(&mibitem.data, &arg, sizeof(UINT32));
        memcpy(&msg.mibattribute.data, &mibitem, sizeof(mibitem));
        result = p80211req_dorequest(wlandev, (UINT8*)&msg);

	/* TODO:  Check result */
	
	DBFEXIT;
}


/*----------------------------------------------------------------
* p80211knetdev_do_ioctl
*
* Handle an ioctl call on one of our devices.  Everything Linux
* ioctl specific is done here.  Then we pass the contents of the
* ifr->data to the request message handler.
*
* Arguments:
*	dev	Linux kernel netdevice
*	ifr	Our private ioctl request structure, typed for the
*		generic struct ifreq so we can use ptr to func
*		w/o cast.
*
* Returns: 
*	zero on success, a negative errno on failure.  Possible values:
*		-ENETDOWN Device isn't up.
*		-EBUSY	cmd already in progress
*		-ETIME	p80211 cmd timed out (MSD may have its own timers)
*		-EFAULT memory fault copying msg from user buffer
*		-ENOMEM unable to allocate kernel msg buffer
*		-ENOSYS	bad magic, it the cmd really for us?
*		-EINTR	sleeping on cmd, awakened by signal, cmd cancelled.
*
* Call Context:
*	Process thread (ioctl caller).  TODO: SMP support may require
*	locks.
----------------------------------------------------------------*/
int p80211knetdev_do_ioctl(netdevice_t *dev, struct ifreq *ifr, int cmd)
{
	int			result = 0;
	p80211ioctl_req_t	*req = (p80211ioctl_req_t*)ifr;
	wlandevice_t		*wlandev = (wlandevice_t*)dev->priv;
	UINT8			*msgbuf;
	DBFENTER;

	WLAN_LOG_DEBUG(2, "rx'd ioctl, cmd=%d, len=%d\n", cmd, req->len);

#if WIRELESS_EXT < 13
	/* Is this a wireless extensions ioctl? */
	if ((cmd >= SIOCIWFIRST) && (cmd <= SIOCIWLAST)) {
		if ((result = p80211wext_support_ioctl(dev, ifr, cmd)) 
		    != (-EOPNOTSUPP)) {
			goto bail;
		}
	}
#endif

	/* Test the magic, assume ifr is good if it's there */
	if ( req->magic != P80211_IOCTL_MAGIC ) {
		result = -ENOSYS;
		goto bail;
	}

	if ( cmd == P80211_IFTEST ) {
		result = 0;
		goto bail;
	} else if ( cmd != P80211_IFREQ ) {
		result = -ENOSYS;
		goto bail;
	}

	/* Allocate a buf of size req->len */
	if ((msgbuf = kmalloc( req->len, GFP_KERNEL))) {
		if ( copy_from_user( msgbuf, req->data, req->len) ) {
			result = -EFAULT;
		} else {
			result = p80211req_dorequest( wlandev, msgbuf);
		}

		if ( result == 0 ) {
			if ( copy_to_user( req->data, msgbuf, req->len)) {
				result = -EFAULT;
			}
		}
		kfree(msgbuf);
	} else {
		result = -ENOMEM;
	}
bail:
	DBFEXIT;
	return result; /* If allocate,copyfrom or copyto fails, return errno */
}

/*----------------------------------------------------------------
* p80211knetdev_set_mac_address
*
* Handles the ioctl for changing the MACAddress of a netdevice
* 
* references: linux/netdevice.h and drivers/net/net_init.c
*
* NOTE: [MSM] We only prevent address changes when the netdev is
* up.  We don't control anything based on dot11 state.  If the 
* address is changed on a STA that's currently associated, you
* will probably lose the ability to send and receive data frames.
* Just be aware.  Therefore, this should usually only be done
* prior to scan/join/auth/assoc.
*
* Arguments:
*	dev	netdevice struct
*	addr	the new MACAddress (a struct)
*
* Returns:
*	zero on success, a negative errno on failure.  Possible values:
*		-EBUSY	device is bussy (cmd not possible)
*		-and errors returned by: p80211req_dorequest(..)
*
* by: Collin R. Mulliner <collin@mulliner.org>
----------------------------------------------------------------*/
int p80211knetdev_set_mac_address(netdevice_t *dev, void *addr)
{
	struct sockaddr			*new_addr = addr;
	p80211msg_dot11req_mibset_t	dot11req;
	p80211item_unk392_t		*mibattr;
	p80211item_pstr6_t		*macaddr;
	p80211item_uint32_t		*resultcode;
	int result = 0;
	
	DBFENTER;
	/* If we're running, we don't allow MAC address changes */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,38) )
	if ( dev->start) {
		return -EBUSY;
	}
#else
	if (netif_running(dev)) {
		return -EBUSY;
	}
#endif

	/* Set up some convenience pointers. */
	mibattr = &dot11req.mibattribute;
	macaddr = (p80211item_pstr6_t*)&mibattr->data;
	resultcode = &dot11req.resultcode;

	/* Set up a dot11req_mibset */
	memset(&dot11req, 0, sizeof(p80211msg_dot11req_mibset_t));
	dot11req.msgcode = DIDmsg_dot11req_mibset;
	dot11req.msglen = sizeof(p80211msg_dot11req_mibset_t);
	memcpy(dot11req.devname, 
		((wlandevice_t*)(dev->priv))->name, 
		WLAN_DEVNAMELEN_MAX - 1);

	/* Set up the mibattribute argument */
	mibattr->did = DIDmsg_dot11req_mibset_mibattribute;
	mibattr->status = P80211ENUM_msgitem_status_data_ok;
	mibattr->len = sizeof(mibattr->data);
	
	macaddr->did = DIDmib_dot11mac_dot11OperationTable_dot11MACAddress;
	macaddr->status = P80211ENUM_msgitem_status_data_ok;
	macaddr->len = sizeof(macaddr->data);
	macaddr->data.len = WLAN_ADDR_LEN;
	memcpy(&macaddr->data.data, new_addr->sa_data, WLAN_ADDR_LEN);

	/* Set up the resultcode argument */
	resultcode->did = DIDmsg_dot11req_mibset_resultcode;
	resultcode->status = P80211ENUM_msgitem_status_no_value;
	resultcode->len = sizeof(resultcode->data);
	resultcode->data = 0;
	
	/* now fire the request */
	result = p80211req_dorequest(dev->priv, (UINT8*)&dot11req);

	/* If the request wasn't successful, report an error and don't
	 * change the netdev address
	 */
	if ( result != 0 || resultcode->data != P80211ENUM_resultcode_success) {
		WLAN_LOG_ERROR0(
		"Low-level driver failed dot11req_mibset(dot11MACAddress).\n");
		result = -EADDRNOTAVAIL;
	} else {
		/* everything's ok, change the addr in netdev */
		memcpy(dev->dev_addr, new_addr->sa_data, dev->addr_len);
	}

	DBFEXIT;
	return result;
}

int wlan_change_mtu(netdevice_t *dev, int new_mtu)
{
	DBFENTER;
	// 2312 is max 802.11 payload, 20 is overhead, (ether + llc +snap)
        if ( (new_mtu < 68) || (new_mtu > (2312 - 20)))
                return -EINVAL;

        dev->mtu = new_mtu;

	DBFEXIT;

        return 0;
}



/*----------------------------------------------------------------
* wlan_setup
*
* Roughly matches the functionality of ether_setup.  Here
* we set up any members of the wlandevice structure that are common
* to all devices.  Additionally, we allocate a linux 'struct device'
* and perform the same setup as ether_setup.
*
* Note: It's important that the caller have setup the wlandev->name
*	ptr prior to calling this function.
*
* Arguments:
*	wlandev		ptr to the wlandev structure for the
*			interface.
* Returns: 
*	zero on success, non-zero otherwise.
* Call Context:
*	Should be process thread.  We'll assume it might be
*	interrupt though.  When we add support for statically
*	compiled drivers, this function will be called in the 
*	context of the kernel startup code.
----------------------------------------------------------------*/
int wlan_setup(wlandevice_t *wlandev)
{
	int		result = 0;
	netdevice_t	*dev;

	DBFENTER;

	if (wlandev->name == NULL ) {
		WLAN_LOG_ERROR0("called without wlandev->name set.\n");
		result = 1;
	} else {
		/* Set up the wlandev */
		wlandev->state = WLAN_DEVICE_CLOSED;
		wlandev->ethconv = WLAN_ETHCONV_8021h;
		wlandev->macmode = WLAN_MACMODE_NONE;

		init_waitqueue_head(&wlandev->reqwq);

		/* Set up the rx queue */
		skb_queue_head_init(&wlandev->nsd_rxq);
#ifdef DECLARE_TASKLET
		tasklet_init(&wlandev->rx_bh, 
			     p80211netdev_rx_bh, 
			     (unsigned long)wlandev);
#else
		INIT_TQUEUE(&wlandev->rx_bh, 
			    p80211netdev_rx_bh, 
			    (void*)wlandev);
#endif
		/* Allocate and initialize the struct device */
		dev = kmalloc(sizeof(netdevice_t), GFP_ATOMIC);
		if ( dev == NULL ) {
			WLAN_LOG_ERROR0("Failed to alloc netdev.\n");
			result = 1;
		} else {
			memset( dev, 0, sizeof(netdevice_t));
			ether_setup(dev);
			wlandev->netdev = dev;
			dev->priv = wlandev;
			dev->hard_start_xmit =	&p80211knetdev_hard_start_xmit;
			dev->get_stats =	&p80211knetdev_get_stats;
			dev->do_ioctl = 	&p80211knetdev_do_ioctl;
			dev->set_multicast_list = &p80211knetdev_set_multicast_list;
			dev->init =		&p80211knetdev_init;
			dev->open =		&p80211knetdev_open;
			dev->stop =		&p80211knetdev_stop;


#ifdef WIRELESS_EXT
			/* called by /proc/net/wireless */
			dev->get_wireless_stats = &p80211wext_get_wireless_stats;
#if WIRELESS_EXT > 12
			dev->wireless_handlers = &p80211wext_handler_def;
#endif
#endif
			
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,38) )
			dev->tbusy = 1;
			dev->start = 0;
#else
			netif_stop_queue(dev);
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,99) )
			dev->name = wlandev->name;
#endif

			dev->change_mtu = wlan_change_mtu;

			/*
			 * set new function to handle the ioctl for
			 * changing the mac address
			 *
			 * must be after "ether_setup()" because
			 * "ether_setup()" sets the pointer to the
			 * default function but we need to do more
			 *
			 * see p80211knetdev_set_mac_address(...)
			 * above
			 *
			 * by: Collin R. Mulliner
			 * <collin@mulliner.org>
			 */
			dev->set_mac_address =	&p80211knetdev_set_mac_address;

		}

	}

	DBFEXIT;
	return result;
}

/*----------------------------------------------------------------
* wlan_unsetup
*
* This function is paired with the wlan_setup routine.  It should
* be called after unregister_wlandev.  Basically, all it does is
* free the 'struct device' that's associated with the wlandev.
* We do it here because the 'struct device' isn't allocated 
* explicitly in the driver code, it's done in wlan_setup.  To
* do the free in the driver might seem like 'magic'.
*
* Arguments:
*	wlandev		ptr to the wlandev structure for the
*			interface.
* Returns: 
*	zero on success, non-zero otherwise.
* Call Context:
*	Should be process thread.  We'll assume it might be
*	interrupt though.  When we add support for statically
*	compiled drivers, this function will be called in the 
*	context of the kernel startup code.
----------------------------------------------------------------*/
int wlan_unsetup(wlandevice_t *wlandev)
{
	int		result = 0;

	DBFENTER;

	if (wlandev->netdev == NULL ) {
		WLAN_LOG_ERROR0("called without wlandev->netdev set.\n");
		result = 1;
	} else {
		kfree_s(wlandev->netdev, sizeof(netdevice_t));
		wlandev->netdev = NULL;
	}

	DBFEXIT;
	return 0;
}



/*----------------------------------------------------------------
* register_wlandev
*
* Roughly matches the functionality of register_netdev.  This function
* is called after the driver has successfully probed and set up the
* resources for the device.  It's now ready to become a named device
* in the Linux system.
*
* First we allocate a name for the device (if not already set), then
* we call the Linux function register_netdevice.
*
* Arguments:
*	wlandev		ptr to the wlandev structure for the
*			interface.
* Returns: 
*	zero on success, non-zero otherwise.
* Call Context:
*	Can be either interrupt or not.
----------------------------------------------------------------*/
int register_wlandev(wlandevice_t *wlandev)
{
	int		i = -1;
	netdevice_t	*dev = wlandev->netdev;

	DBFENTER;
	rtnl_lock();

	if ( wlandev->name != NULL && 
		(wlandev->name[0] == '\0' || wlandev->name[0] == ' ') ) {
		i = wlandev_get_index(wlandev);
	}

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,99) )
	strcpy(dev->name, wlandev->name);
#endif

	if (register_netdevice(dev)) {
		if ( i >= 0 ) {
			wlandev_clear_index(wlandev);
		}
		rtnl_unlock();
		return -EIO;
	}

	rtnl_unlock();

#ifndef NEW_MODULE_CODE
	MOD_INC_USE_COUNT;
#endif

#ifdef CONFIG_PROC_FS
	if (proc_p80211) {
		wlandev->procdir = proc_mkdir(wlandev->name, proc_p80211);
		if ( wlandev->procdir ) {
			wlandev->procwlandev = 
			  create_proc_read_entry("wlandev", 0,
						 wlandev->procdir,
						 p80211netdev_proc_read,
						 wlandev);
		}
	}
#endif
	DBFEXIT;
	return 0;
}


/*----------------------------------------------------------------
* unregister_wlandev
*
* Roughly matches the functionality of unregister_netdev.  This
* function is called to remove a named device from the system.
*
* First we tell linux that the device should no longer exist.
* Then we remove it from the list of known wlan devices.
*
* Arguments:
*	wlandev		ptr to the wlandev structure for the
*			interface.
* Returns: 
*	zero on success, non-zero otherwise.
* Call Context:
*	Can be either interrupt or not.
----------------------------------------------------------------*/
int unregister_wlandev(wlandevice_t *wlandev)
{
	struct sk_buff *skb;

	DBFENTER;

#ifdef CONFIG_PROC_FS
	if ( wlandev->procwlandev ) {
		remove_proc_entry("wlandev", wlandev->procdir);
	}
	if (wlandev->procdir) {
		remove_proc_entry(wlandev->name, proc_p80211);
	}
#endif

	rtnl_lock();
	unregister_netdevice(wlandev->netdev);
	wlandev_clear_index(wlandev);
	rtnl_unlock();

#ifdef DECLARE_TASKLET
	tasklet_kill(&wlandev->rx_bh);
#else
#warning "We aren't cleaning up the rx_bh cleanly!"
#endif

	/* Now to clean out the rx queue */
	while ( (skb = skb_dequeue(&wlandev->nsd_rxq)) ) {
		dev_kfree_skb(skb);
	}


#ifndef NEW_MODULE_CODE
	MOD_DEC_USE_COUNT;
#endif

	DBFEXIT;
	return 0;
}

#ifdef CONFIG_PROC_FS
/*----------------------------------------------------------------
* proc_read
*
* Read function for /proc/net/p80211/<device>/wlandev
*
* Arguments:
*	buf
*	start 
*	offset 
*	count
*	eof
*	data
* Returns: 
*	zero on success, non-zero otherwise.
* Call Context:
*	Can be either interrupt or not.
----------------------------------------------------------------*/
static int
p80211netdev_proc_read(
	char	*page, 
	char	**start, 
	off_t	offset, 
	int	count,
	int	*eof,
	void	*data)
{
	char	 *p = page;
	wlandevice_t *wlandev = (wlandevice_t *) data;

	DBFENTER;
	if (offset != 0) {
		*eof = 1;
		goto exit;
	} 

	p += sprintf(p, "p80211 version: %s (%s)\n\n", 
		     WLAN_RELEASE, WLAN_BUILD_DATE);
	p += sprintf(p, "name       : %s\n", wlandev->name);
	p += sprintf(p, "bus        : %s\n", wlandev->slotname);
	p += sprintf(p, "address    : %02x:%02x:%02x:%02x:%02x:%02x\n",
		     wlandev->netdev->dev_addr[0], wlandev->netdev->dev_addr[1], wlandev->netdev->dev_addr[2],
		     wlandev->netdev->dev_addr[3], wlandev->netdev->dev_addr[4], wlandev->netdev->dev_addr[5]);
	p += sprintf(p, "nsd caps   : %s%s%s%s%s%s%s%s%s%s\n",  
		     (wlandev->nsdcaps & P80211_NSDCAP_HARDWAREWEP) ? "wep_hw " : "",
		     (wlandev->nsdcaps & P80211_NSDCAP_TIEDWEP) ? "wep_tied " : "",
		     (wlandev->nsdcaps & P80211_NSDCAP_NOHOSTWEP) ? "wep_hw_only " : "",
		     (wlandev->nsdcaps & P80211_NSDCAP_PBCC) ? "pbcc " : "",
		     (wlandev->nsdcaps & P80211_NSDCAP_SHORT_PREAMBLE) ? "short_preamble " : "",
		     (wlandev->nsdcaps & P80211_NSDCAP_AGILITY) ? "agility " : "",
		     (wlandev->nsdcaps & P80211_NSDCAP_AP_RETRANSMIT) ? "ap_retransmit " : "",
		     (wlandev->nsdcaps & P80211_NSDCAP_HWFRAGMENT) ? "hw_frag " : "",
		     (wlandev->nsdcaps & P80211_NSDCAP_AUTOJOIN) ? "autojoin " : "",
		     (wlandev->nsdcaps & P80211_NSDCAP_NOSCAN) ? "" : "scan ");

	p += sprintf(p, "Enabled    : %s%s\n", 
		     (wlandev->shortpreamble) ? "short_preamble " : "",
		     (wlandev->hostwep & HOSTWEP_PRIVACYINVOKED) ? "privacy" : "");

 exit:
	DBFEXIT;
	return (p - page);
}
#endif


/*----------------------------------------------------------------
* wlandev_get_index
*
* Allocates a device number and constructs the name for the given 
* wlandev.  
*
* Arguments:
*	wlandev		ptr to the wlandev structure for the
*			interface.
* Returns: 
*	The device number on success, -1 otherwise
* Side effects:
*	The name is constructed in the space pointed to by wlandev->name.
*	It had _better_ be a valid pointer.
* Call Context:
*	Can be either interrupt or not.
----------------------------------------------------------------*/
int wlandev_get_index(wlandevice_t  *wlandev)
{
	int	i;

	DBFENTER;
	for  ( i = 0; i < MAX_WLAN_DEVICES; i++) {
		if ( wlandev_index[i] == NULL ) {
			sprintf(wlandev->name, "wlan%d", i);
			WLAN_LOG_DEBUG(1,"Loading device '%s'...\n", wlandev->name);
			wlandev_index[i] = wlandev;
			return i;
		}
	}
	DBFEXIT;
	return -1;
}


/*----------------------------------------------------------------
* wlandev_clear_index
*
* Frees a previously allocated device number.
*
* Arguments:
*	wlandev		ptr to the wlandev structure for the
*			interface.
* Returns: 
*	nothing
* Side effects:
*	none
* Call Context:
*	Can be either interrupt or not.
----------------------------------------------------------------*/
void wlandev_clear_index(wlandevice_t  *wlandev)
{
	int	i;
	DBFENTER;
	for  ( i = 0; i < MAX_WLAN_DEVICES; i++) {
		if ( wlandev_index[i] == wlandev ) {
			wlandev_index[i] = NULL;
		}
	}
	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* p80211netdev_hwremoved
*
* Hardware removed notification. This function should be called
* immediately after an MSD has detected that the underlying hardware
* has been yanked out from under us.  The primary things we need
* to do are:
*   - Mark the wlandev
*   - Prevent any further traffic from the knetdev i/f
*   - Prevent any further requests from mgmt i/f
*   - If there are any waitq'd mgmt requests or mgmt-frame exchanges,
*     shut them down.
*   - Call the MSD hwremoved function.
*
* The remainder of the cleanup will be handled by unregister().
* Our primary goal here is to prevent as much tickling of the MSD
* as possible since the MSD is already in a 'wounded' state.
*
* TODO: As new features are added, this function should be 
*       updated.
*
* Arguments:
*	wlandev		WLAN network device structure
* Returns: 
*	nothing
* Side effects:
*
* Call context:
*	Usually interrupt.
----------------------------------------------------------------*/
void p80211netdev_hwremoved(wlandevice_t *wlandev)
{
	DBFENTER;
	wlandev->hwremoved = 1;
	if ( wlandev->state == WLAN_DEVICE_OPEN) {
		p80211netdev_stop_queue(wlandev);
	}
	if (wlandev->hwremoved) {
		(*(wlandev->hwremovedfn))(wlandev);
	}
	DBFEXIT;
}

