/*
 * Host AP (software wireless LAN access point) driver for
 * Intersil Prism2/2.5/3.
 *
 * Copyright (c) 2001-2002, SSH Communications Security Corp and Jouni Malinen
 * <jkmaline@cc.hut.fi>
 * Copyright (c) 2002-2003, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 *
 * FIX:
 * - there is currently no way of associating TX packets to correct wds device
 *   when TX Exc/OK event occurs, so all tx_packets and some
 *   tx_errors/tx_dropped are added to the main netdevice; using sw_support
 *   field in txdesc might be used to fix this (using Alloc event to increment
 *   tx_packets would need some further info in txfid table)
 *
 * Buffer Access Path (BAP) usage:
 *   Prism2 cards have two separate BAPs for accessing the card memory. These
 *   should allow concurrent access to two different frames and the driver
 *   previously used BAP0 for sending data and BAP1 for receiving data.
 *   However, there seems to be number of issues with concurrent access and at
 *   least one know hardware bug in using BAP0 and BAP1 concurrently with PCI
 *   Prism2.5. Therefore, the driver now only uses BAP0 for moving data between
 *   host and card memories. BAP0 accesses are protected with local->baplock
 *   (spin_lock_bh) to prevent concurrent use.
 */


#include <linux/config.h>
#include <linux/version.h>

#include <asm/delay.h>
#include <asm/uaccess.h>

#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/if_arp.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/rtnetlink.h>
#include "hostap_wext.h"
#include <asm/irq.h>


#include "hostap_80211.h"
#include "hostap.h"
#include "hostap_ap.h"


/* #define final_version */

static int mtu = 1500;
MODULE_PARM(mtu, "i");
MODULE_PARM_DESC(mtu, "Maximum transfer unit");

static int channel[MAX_PARM_DEVICES] = { 3, DEF_INTS };
MODULE_PARM(channel, PARM_MIN_MAX "i");
MODULE_PARM_DESC(channel, "Initial channel");

static char *essid[MAX_PARM_DEVICES] = { "test" };
MODULE_PARM(essid, PARM_MIN_MAX "s");
MODULE_PARM_DESC(essid, "Host AP's ESSID");

static int iw_mode[MAX_PARM_DEVICES] = { IW_MODE_MASTER, DEF_INTS };
MODULE_PARM(iw_mode, PARM_MIN_MAX "i");
MODULE_PARM_DESC(iw_mode, "Initial operation mode");

static int beacon_int[MAX_PARM_DEVICES] = { 100, DEF_INTS };
MODULE_PARM(beacon_int, PARM_MIN_MAX "i");
MODULE_PARM_DESC(beacon_int, "Beacon interval (1 = 1024 usec)");

static int dtim_period[MAX_PARM_DEVICES] = { 1, DEF_INTS };
MODULE_PARM(dtim_period, PARM_MIN_MAX "i");
MODULE_PARM_DESC(dtim_period, "DTIM period");

static int delayed_enable /* = 0 */;
MODULE_PARM(delayed_enable, "i");
MODULE_PARM_DESC(delayed_enable, "Delay MAC port enable until netdevice open");

static int disable_on_close /* = 0 */;
MODULE_PARM(disable_on_close, "i");
MODULE_PARM_DESC(disable_on_close, "Disable MAC port on netdevice close");

#if defined(PRISM2_PCI) && defined(PRISM2_BUS_MASTER)
static int bus_master_threshold_rx[MAX_PARM_DEVICES] = { 100, DEF_INTS };
MODULE_PARM(bus_master_threshold_rx, "i");
MODULE_PARM_DESC(bus_master_threshold_rx, "Packet length threshold for using "
		 "PCI bus master on RX");

static int bus_master_threshold_tx[MAX_PARM_DEVICES] = { 100, DEF_INTS };
MODULE_PARM(bus_master_threshold_tx, "i");
MODULE_PARM_DESC(bus_master_threshold_tx, "Packet length threshold for using "
		 "PCI bus master on TX");
#endif /* PRISM2_PCI and PRISM2_BUS_MASTER */

static char *dev_template = "eth%d";
MODULE_PARM(dev_template, "s");
MODULE_PARM_DESC(dev_template, "Prefix for network device name (default: "
		 "eth%d)");


/* See IEEE 802.1H for LLC/SNAP encapsulation/decapsulation */
/* Ethernet-II snap header (RFC1042 for most EtherTypes) */
static unsigned char rfc1042_header[] =
{ 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };
/* Bridge-Tunnel header (for EtherTypes ETH_P_AARP and ETH_P_IPX) */
static unsigned char bridge_tunnel_header[] =
{ 0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8 };
/* No encapsulation header if EtherType < 0x600 (=length) */


#ifdef final_version
#define EXTRA_EVENTS_WTERR 0
#else
/* check WTERR events (Wait Time-out) in development versions */
#define EXTRA_EVENTS_WTERR HFA384X_EV_WTERR
#endif

#if defined(PRISM2_PCI) && defined(PRISM2_BUS_MASTER)
#define EXTRA_EVENTS_BUS_MASTER (HFA384X_EV_PCI_M0 | HFA384X_EV_PCI_M1)
#else
#define EXTRA_EVENTS_BUS_MASTER 0
#endif

/* Events that will be using BAP0 */
#define HFA384X_BAP0_EVENTS \
	(HFA384X_EV_TXEXC | HFA384X_EV_RX | HFA384X_EV_INFO | HFA384X_EV_TX)

/* event mask, i.e., events that will result in an interrupt */
#define HFA384X_EVENT_MASK \
	(HFA384X_BAP0_EVENTS | HFA384X_EV_ALLOC | HFA384X_EV_INFDROP | \
	HFA384X_EV_CMD | HFA384X_EV_TICK | \
	EXTRA_EVENTS_WTERR | EXTRA_EVENTS_BUS_MASTER)

/* Default TX control flags: use 802.11 headers and request interrupt for
 * failed transmits. Frames that request ACK callback, will add
 * _TX_OK flag and _ALT_RTRY flag may be used to select different retry policy.
 */
#define HFA384X_TX_CTRL_FLAGS \
	(HFA384X_TX_CTRL_802_11 | HFA384X_TX_CTRL_TX_EX)


/* ca. 1 usec */
#define HFA384X_CMD_BUSY_TIMEOUT 5000
#define HFA384X_BAP_BUSY_TIMEOUT 50000

/* ca. 10 usec */
#define HFA384X_CMD_COMPL_TIMEOUT 20000
#define HFA384X_DL_COMPL_TIMEOUT 1000000

/* Wait times for initialization; yield to other processes to avoid busy
 * waiting for long time. */
#define HFA384X_INIT_TIMEOUT (HZ / 2) /* 500 ms */
#define HFA384X_ALLOC_COMPL_TIMEOUT (HZ / 20) /* 50 ms */


static void prism2_hw_reset(struct net_device *dev);
static void prism2_check_sta_fw_version(local_info_t *local);

#ifdef PRISM2_DOWNLOAD_SUPPORT
/* hostap_download.c */
static u8 * prism2_read_pda(struct net_device *dev);
static int prism2_download(local_info_t *local,
			   struct prism2_download_param *param);
static void prism2_download_free_data(struct prism2_download_data *dl);
static int prism2_download_volatile(local_info_t *local,
				    struct prism2_download_data *param);
static int prism2_download_genesis(local_info_t *local,
				   struct prism2_download_data *param);
#endif /* PRISM2_DOWNLOAD_SUPPORT */




#ifndef final_version
/* magic value written to SWSUPPORT0 reg. for detecting whether card is still
 * present */
#define HFA384X_MAGIC 0x8A32
#endif


static u16 hfa384x_read_reg(struct net_device *dev, u16 reg)
{
	return HFA384X_INW(reg);
}


static void hfa384x_read_regs(struct net_device *dev,
			      struct hfa384x_regs *regs)
{
	regs->cmd = HFA384X_INW(HFA384X_CMD_OFF);
	regs->evstat = HFA384X_INW(HFA384X_EVSTAT_OFF);
	regs->offset0 = HFA384X_INW(HFA384X_OFFSET0_OFF);
	regs->offset1 = HFA384X_INW(HFA384X_OFFSET1_OFF);
	regs->swsupport0 = HFA384X_INW(HFA384X_SWSUPPORT0_OFF);
}


/* local->cmdlock must be locked when calling this helper function */
static inline void __hostap_cmd_queue_free(local_info_t *local,
					   struct hostap_cmd_queue *entry,
					   int del_req)
{
	if (del_req) {
		entry->del_req = 1;
		if (!list_empty(&entry->list)) {
			list_del_init(&entry->list);
			local->cmd_queue_len--;
		}
	}

	if (atomic_dec_and_test(&entry->usecnt) && entry->del_req)
		kfree(entry);
}

static inline void hostap_cmd_queue_free(local_info_t *local,
					 struct hostap_cmd_queue *entry,
					 int del_req)
{
	unsigned long flags;

	spin_lock_irqsave(&local->cmdlock, flags);
	__hostap_cmd_queue_free(local, entry, del_req);
	spin_unlock_irqrestore(&local->cmdlock, flags);
}


static inline int hfa384x_cmd_issue(struct net_device *dev,
				    struct hostap_cmd_queue *entry)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	int tries;
	u16 reg;
	unsigned long flags;

	if (entry->issued) {
		printk(KERN_DEBUG "%s: driver bug - re-issuing command @%p\n",
		       dev->name, entry);
	}

	/* wait until busy bit is clear; this should always be clear since the
	 * commands are serialized */
	tries = HFA384X_CMD_BUSY_TIMEOUT;
	while (HFA384X_INW(HFA384X_CMD_OFF) & HFA384X_CMD_BUSY && tries > 0) {
		tries--;
		udelay(1);
	}
#ifndef final_version
	if (tries != HFA384X_CMD_BUSY_TIMEOUT) {
		prism2_io_debug_error(dev, 1);
		printk(KERN_DEBUG "%s: hfa384x_cmd_issue: cmd reg was busy "
		       "for %d usec\n", dev->name,
		       HFA384X_CMD_BUSY_TIMEOUT - tries);
	}
#endif
	if (tries == 0) {
		reg = HFA384X_INW(HFA384X_CMD_OFF);
		prism2_io_debug_error(dev, 2);
		printk(KERN_DEBUG "%s: hfa384x_cmd_issue - timeout - "
		       "reg=0x%04x\n", dev->name, reg);
		return -ETIMEDOUT;
	}

	/* write command */
	spin_lock_irqsave(&local->cmdlock, flags);
	HFA384X_OUTW(entry->param0, HFA384X_PARAM0_OFF);
	HFA384X_OUTW(entry->param1, HFA384X_PARAM1_OFF);
	HFA384X_OUTW(entry->cmd, HFA384X_CMD_OFF);
	entry->issued = 1;
	spin_unlock_irqrestore(&local->cmdlock, flags);

	return 0;
}


/* Issue given command (possibly after waiting in command queue) and sleep
 * until the command is completed (or timed out). This can be called only
 * from user context. */
static int hfa384x_cmd(struct net_device *dev, u16 cmd, u16 param0,
		       u16 *param1, u16 *resp0)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	int err, res, issue, issued = 0;
	unsigned long flags;
	struct hostap_cmd_queue *entry;
	DECLARE_WAITQUEUE(wait, current);

	if (in_interrupt()) {
		printk(KERN_DEBUG "%s: hfa384x_cmd called from interrupt "
		       "context\n", dev->name);
		return -1;
	}

	if (local->cmd_queue_len >= HOSTAP_CMD_QUEUE_MAX_LEN) {
		printk(KERN_DEBUG "%s: hfa384x_cmd: cmd_queue full\n",
		       dev->name);
		return -1;
	}

	if (signal_pending(current))
		return -EINTR;

	entry = (struct hostap_cmd_queue *)
		kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (entry == NULL) {
		printk(KERN_DEBUG "%s: hfa384x_cmd - kmalloc failed\n",
		       dev->name);
		return -ENOMEM;
	}
	memset(entry, 0, sizeof(*entry));
	atomic_set(&entry->usecnt, 1);
	entry->type = CMD_SLEEP;
	entry->cmd = cmd;
	entry->param0 = param0;
	if (param1)
		entry->param1 = *param1;
	init_waitqueue_head(&entry->compl);

	/* prepare to wait for command completion event, but do not sleep yet
	 */
	add_wait_queue(&entry->compl, &wait);
	set_current_state(TASK_INTERRUPTIBLE);

	spin_lock_irqsave(&local->cmdlock, flags);
	issue = list_empty(&local->cmd_queue);
	if (issue)
		entry->issuing = 1;
	list_add_tail(&entry->list, &local->cmd_queue);
	local->cmd_queue_len++;
	spin_unlock_irqrestore(&local->cmdlock, flags);

	err = 0;
	if (!issue)
		goto wait_completion;

	if (signal_pending(current))
		err = -EINTR;

	if (!err) {
		if (hfa384x_cmd_issue(dev, entry))
			err = -ETIMEDOUT;
		else
			issued = 1;
	}

 wait_completion:
	if (!err && entry->type != CMD_COMPLETED) {
		/* sleep until command is completed or timed out */
		res = schedule_timeout(2 * HZ);
	} else
		res = -1;

	if (!err && signal_pending(current))
		err = -EINTR;

	if (err && issued) {
		/* the command was issued, so a CmdCompl event should occur
		 * soon; however, there's a pending signal and
		 * schedule_timeout() would be interrupted; wait a short period
		 * of time to avoid removing entry from the list before
		 * CmdCompl event */
		udelay(300);
	}

	set_current_state(TASK_RUNNING);
	remove_wait_queue(&entry->compl, &wait);

	/* If entry->list is still in the list, it must be removed
	 * first and in this case prism2_cmd_ev() does not yet have
	 * local reference to it, and the data can be kfree()'d
	 * here. If the command completion event is still generated,
	 * it will be assigned to next (possibly) pending command, but
	 * the driver will reset the card anyway due to timeout
	 *
	 * If the entry is not in the list prism2_cmd_ev() has a local
	 * reference to it, but keeps cmdlock as long as the data is
	 * needed, so the data can be kfree()'d here. */

	/* FIX: if the entry->list is in the list, it has not been completed
	 * yet, so removing it here is somewhat wrong.. this could cause
	 * references to freed memory and next list_del() causing NULL pointer
	 * dereference.. it would probably be better to leave the entry in the
	 * list and the list should be emptied during hw reset */

	spin_lock_irqsave(&local->cmdlock, flags);
	if (!list_empty(&entry->list)) {
		printk(KERN_DEBUG "%s: hfa384x_cmd: entry still in list? "
		       "(entry=%p, type=%d, res=%d)\n", dev->name, entry,
		       entry->type, res);
		list_del_init(&entry->list);
		local->cmd_queue_len--;
	}
	spin_unlock_irqrestore(&local->cmdlock, flags);

	if (err) {
		printk(KERN_DEBUG "%s: hfa384x_cmd: interrupted; err=%d\n",
		       dev->name, err);
		res = err;
		goto done;
	}

	if (entry->type != CMD_COMPLETED) {
		u16 reg = HFA384X_INW(HFA384X_EVSTAT_OFF);
		printk(KERN_DEBUG "%s: hfa384x_cmd: command was not "
		       "completed (res=%d, entry=%p, type=%d, cmd=0x%04x, "
		       "param0=0x%04x, EVSTAT=%04x INTEN=%04x)\n", dev->name,
		       res, entry, entry->type, entry->cmd, entry->param0, reg,
		       HFA384X_INW(HFA384X_INTEN_OFF));
		if (reg & HFA384X_EV_CMD) {
			/* Command completion event is pending, but the
			 * interrupt was not delivered - probably an issue
			 * with pcmcia-cs configuration. */
			printk(KERN_WARNING "%s: interrupt delivery does not "
			       "seem to work\n", dev->name);
		}
		prism2_io_debug_error(dev, 3);
		res = -ETIMEDOUT;
		goto done;
	}

	if (resp0 != NULL)
		*resp0 = entry->resp0;
#ifndef final_version
	if (entry->res) {
		printk(KERN_DEBUG "%s: CMD=0x%04x => res=0x%02x, "
		       "resp0=0x%04x\n",
		       dev->name, cmd, entry->res, entry->resp0);
	}
#endif /* final_version */

	res = entry->res;
 done:
	hostap_cmd_queue_free(local, entry, 1);
	return res;
}


/* Issue given command (possibly after waiting in command queue) and use
 * callback function to indicate command completion. This can be called both
 * from user and interrupt context. */
static int hfa384x_cmd_callback(struct net_device *dev, u16 cmd, u16 param0,
				void (*callback)(struct net_device *dev,
						 void *context, u16 resp0,
						 u16 status),
				void *context)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	int issue, ret;
	unsigned long flags;
	struct hostap_cmd_queue *entry;

	if (local->cmd_queue_len >= HOSTAP_CMD_QUEUE_MAX_LEN + 2) {
		printk(KERN_DEBUG "%s: hfa384x_cmd: cmd_queue full\n",
		       dev->name);
		return -1;
	}

	entry = (struct hostap_cmd_queue *)
		kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (entry == NULL) {
		printk(KERN_DEBUG "%s: hfa384x_cmd_callback - kmalloc "
		       "failed\n", dev->name);
		return -ENOMEM;
	}
	memset(entry, 0, sizeof(*entry));
	atomic_set(&entry->usecnt, 1);
	entry->type = CMD_CALLBACK;
	entry->cmd = cmd;
	entry->param0 = param0;
	entry->callback = callback;
	entry->context = context;

	spin_lock_irqsave(&local->cmdlock, flags);
	issue = list_empty(&local->cmd_queue);
	if (issue)
		entry->issuing = 1;
	list_add_tail(&entry->list, &local->cmd_queue);
	local->cmd_queue_len++;
	spin_unlock_irqrestore(&local->cmdlock, flags);

	if (issue && hfa384x_cmd_issue(dev, entry))
		ret = -ETIMEDOUT;
	else
		ret = 0;

	hostap_cmd_queue_free(local, entry, ret);

	return ret;
}


static int hfa384x_cmd_wait(struct net_device *dev, u16 cmd, u16 param0)
{
	int res, tries;
	u16 reg;

	/* wait until busy bit is clear; this should always be clear since the
	 * commands are serialized */
	tries = HFA384X_CMD_BUSY_TIMEOUT;
	while (HFA384X_INW(HFA384X_CMD_OFF) & HFA384X_CMD_BUSY && tries > 0) {
		tries--;
		udelay(1);
	}
	if (tries == 0) {
		prism2_io_debug_error(dev, 4);
		printk(KERN_DEBUG "%s: hfa384x_cmd_wait - timeout - "
		       "reg=0x%04x\n", dev->name,
		       HFA384X_INW(HFA384X_CMD_OFF));
		return -ETIMEDOUT;
	}

	/* write command */
	HFA384X_OUTW(param0, HFA384X_PARAM0_OFF);
	HFA384X_OUTW(cmd, HFA384X_CMD_OFF);

        /* wait for command completion */
	if ((cmd & HFA384X_CMDCODE_MASK) == HFA384X_CMDCODE_DOWNLOAD)
		tries = HFA384X_DL_COMPL_TIMEOUT;
	else
		tries = HFA384X_CMD_COMPL_TIMEOUT;

        while (!(HFA384X_INW(HFA384X_EVSTAT_OFF) & HFA384X_EV_CMD) &&
               tries > 0) {
                tries--;
                udelay(10);
        }
        if (tries == 0) {
                reg = HFA384X_INW(HFA384X_EVSTAT_OFF);
		prism2_io_debug_error(dev, 5);
                printk(KERN_DEBUG "%s: hfa384x_cmd_wait - timeout2 - "
		       "reg=0x%04x\n", dev->name, reg);
                return -ETIMEDOUT;
        }

        res = (HFA384X_INW(HFA384X_STATUS_OFF) &
               (BIT(14) | BIT(13) | BIT(12) | BIT(11) | BIT(10) | BIT(9) |
                BIT(8))) >> 8;
#ifndef final_version
	if (res) {
		printk(KERN_DEBUG "%s: CMD=0x%04x => res=0x%02x\n",
		       dev->name, cmd, res);
	}
#endif

	HFA384X_OUTW(HFA384X_EV_CMD, HFA384X_EVACK_OFF);

	return res;
}


static int hfa384x_cmd_no_wait(struct net_device *dev, u16 cmd, u16 param0)
{
	int tries;
	u16 reg;

	/* wait until busy bit is clear */
	tries = HFA384X_CMD_BUSY_TIMEOUT;
	while (HFA384X_INW(HFA384X_CMD_OFF) & HFA384X_CMD_BUSY && tries > 0) {
		tries--;
		udelay(1);
	}
	if (tries == 0) {
		reg = HFA384X_INW(HFA384X_CMD_OFF);
		prism2_io_debug_error(dev, 6);
		printk("%s: hfa384x_cmd - timeout - reg=0x%04x\n", dev->name,
		       reg);
		return -ETIMEDOUT;
	}

	/* write command */
	HFA384X_OUTW(param0, HFA384X_PARAM0_OFF);
	HFA384X_OUTW(cmd, HFA384X_CMD_OFF);

	return 0;
}


static inline int hfa384x_wait_offset(struct net_device *dev, u16 o_off)
{
	int tries = HFA384X_BAP_BUSY_TIMEOUT;
	int res = HFA384X_INW(o_off) & HFA384X_OFFSET_BUSY;

	while (res && tries > 0) {
		tries--;
		udelay(1);
		res = HFA384X_INW(o_off) & HFA384X_OFFSET_BUSY;
	}
	return res;
}


/* Offset must be even */
static int hfa384x_setup_bap(struct net_device *dev, u16 bap, u16 id,
			     int offset)
{
	u16 o_off, s_off;
	int ret = 0;

	if (offset % 2 || bap > 1)
		return -EINVAL;

	if (bap == BAP1) {
		o_off = HFA384X_OFFSET1_OFF;
		s_off = HFA384X_SELECT1_OFF;
	} else {
		o_off = HFA384X_OFFSET0_OFF;
		s_off = HFA384X_SELECT0_OFF;
	}

	if (hfa384x_wait_offset(dev, o_off)) {
		prism2_io_debug_error(dev, 7);
		printk(KERN_DEBUG "%s: hfa384x_setup_bap - timeout before\n",
		       dev->name);
		ret = -ETIMEDOUT;
		goto out;
	}

	HFA384X_OUTW(id, s_off);
	HFA384X_OUTW(offset, o_off);

	if (hfa384x_wait_offset(dev, o_off)) {
		prism2_io_debug_error(dev, 8);
		printk(KERN_DEBUG "%s: hfa384x_setup_bap - timeout after\n",
		       dev->name);
		ret = -ETIMEDOUT;
		goto out;
	}
#ifndef final_version
	if (HFA384X_INW(o_off) & HFA384X_OFFSET_ERR) {
		prism2_io_debug_error(dev, 9);
		printk(KERN_DEBUG "%s: hfa384x_setup_bap - offset error "
		       "(%d,0x04%x,%d); reg=0x%04x\n",
		       dev->name, bap, id, offset, HFA384X_INW(o_off));
		ret = -EINVAL;
	}
#endif

 out:
	return ret;
}


static int hfa384x_get_rid(struct net_device *dev, u16 rid, void *buf, int len,
			   int exact_len)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	int res, rlen = 0;
	struct hfa384x_rid_hdr rec;

	res = down_interruptible(&local->rid_bap_sem);
	if (res)
		return res;

	res = hfa384x_cmd(dev, HFA384X_CMDCODE_ACCESS, rid, NULL, NULL);
	if (res) {
		printk(KERN_DEBUG "%s: hfa384x_get_rid: CMDCODE_ACCESS failed "
		       "(res=%d, rid=%04x, len=%d)\n",
		       dev->name, res, rid, len);
		up(&local->rid_bap_sem);
		return res;
	}

	spin_lock_bh(&local->baplock);

	res = hfa384x_setup_bap(dev, BAP0, rid, 0);
	if (!res)
		res = hfa384x_from_bap(dev, BAP0, &rec, sizeof(rec));

	if (le16_to_cpu(rec.len) == 0) {
		/* RID not available */
		res = -ENODATA;
	}

	rlen = (le16_to_cpu(rec.len) - 1) * 2;
	if (!res && exact_len && rlen != len) {
		printk(KERN_DEBUG "%s: hfa384x_get_rid - RID len mismatch: "
		       "rid=0x%04x, len=%d (expected %d)\n",
		       dev->name, rid, rlen, len);
		res = -ENODATA;
	}

	if (!res)
		res = hfa384x_from_bap(dev, BAP0, buf, len);

	spin_unlock_bh(&local->baplock);
	up(&local->rid_bap_sem);

	if (res) {
		if (res != -ENODATA)
			printk(KERN_DEBUG "%s: hfa384x_get_rid (rid=%04x, "
			       "len=%d) - failed - res=%d\n", dev->name, rid,
			       len, res);
		if (res == -ETIMEDOUT)
			prism2_hw_reset(dev);
		return res;
	}

	return rlen;
}


static int hfa384x_set_rid(struct net_device *dev, u16 rid, void *buf, int len)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	struct hfa384x_rid_hdr rec;
	int res;

	rec.rid = cpu_to_le16(rid);
	/* RID len in words and +1 for rec.rid */
	rec.len = cpu_to_le16(len / 2 + len % 2 + 1);

	res = down_interruptible(&local->rid_bap_sem);
	if (res)
		return res;

	spin_lock_bh(&local->baplock);
	res = hfa384x_setup_bap(dev, BAP0, rid, 0);
	if (!res)
		res = hfa384x_to_bap(dev, BAP0, &rec, sizeof(rec));
	if (!res)
		res = hfa384x_to_bap(dev, BAP0, buf, len);
	spin_unlock_bh(&local->baplock);

	if (res) {
		printk(KERN_DEBUG "%s: hfa384x_set_rid (rid=%04x, len=%d) - "
		       "failed - res=%d\n", dev->name, rid, len, res);
		up(&local->rid_bap_sem);
		return res;
	}

	res = hfa384x_cmd(dev, HFA384X_CMDCODE_ACCESS_WRITE, rid, NULL, NULL);
	up(&local->rid_bap_sem);
	if (res) {
		printk(KERN_DEBUG "%s: hfa384x_set_rid: CMDCODE_ACCESS_WRITE "
		       "failed (res=%d, rid=%04x, len=%d)\n",
		       dev->name, res, rid, len);
		return res;
	}

	if (res == -ETIMEDOUT)
		prism2_hw_reset(dev);

	return res;
}


static void hfa384x_disable_interrupts(struct net_device *dev)
{
	/* disable interrupts and clear event status */
	HFA384X_OUTW(0, HFA384X_INTEN_OFF);
	HFA384X_OUTW(0xffff, HFA384X_EVACK_OFF);
}


static void hfa384x_enable_interrupts(struct net_device *dev)
{
	/* ack pending events and enable interrupts from selected events */
	HFA384X_OUTW(0xffff, HFA384X_EVACK_OFF);
	HFA384X_OUTW(HFA384X_EVENT_MASK, HFA384X_INTEN_OFF);
}


static void hfa384x_events_no_bap0(struct net_device *dev)
{
	HFA384X_OUTW(HFA384X_EVENT_MASK & ~HFA384X_BAP0_EVENTS,
		     HFA384X_INTEN_OFF);
}


static void hfa384x_events_all(struct net_device *dev)
{
	HFA384X_OUTW(HFA384X_EVENT_MASK, HFA384X_INTEN_OFF);
}


static void hfa384x_events_only_cmd(struct net_device *dev)
{
	HFA384X_OUTW(HFA384X_EV_CMD, HFA384X_INTEN_OFF);
}


static u16 hfa384x_allocate_fid(struct net_device *dev, int len)
{
	u16 fid;
	unsigned long delay;

	/* FIX: this could be replace with hfa384x_cmd() if the Alloc event
	 * below would be handled like CmdCompl event (sleep here, wake up from
	 * interrupt handler */
	if (hfa384x_cmd_wait(dev, HFA384X_CMDCODE_ALLOC, len)) {
		printk(KERN_DEBUG "%s: cannot allocate fid, len=%d\n",
		       dev->name, len);
		return 0xffff;
	}

	delay = jiffies + HFA384X_ALLOC_COMPL_TIMEOUT;
	while (!(HFA384X_INW(HFA384X_EVSTAT_OFF) & HFA384X_EV_ALLOC) &&
	       time_before(jiffies, delay))
		yield();
	if (!(HFA384X_INW(HFA384X_EVSTAT_OFF) & HFA384X_EV_ALLOC)) {
		printk("%s: fid allocate, len=%d - timeout\n", dev->name, len);
		return 0xffff;
	}

	fid = HFA384X_INW(HFA384X_ALLOCFID_OFF);
	HFA384X_OUTW(HFA384X_EV_ALLOC, HFA384X_EVACK_OFF);

	return fid;
}


static int prism2_reset_port(struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	int res;

	if (!local->dev_enabled)
		return 0;

	res = hfa384x_cmd(dev, HFA384X_CMDCODE_DISABLE, 0,
			  NULL, NULL);
	if (res)
		printk(KERN_DEBUG "%s: reset port failed to disable port\n",
		       dev->name);
	else {
		res = hfa384x_cmd(dev, HFA384X_CMDCODE_ENABLE, 0,
				  NULL, NULL);
		if (res)
			printk(KERN_DEBUG "%s: reset port failed to enable "
			       "port\n", dev->name);
	}

	return res;
}


static int prism2_get_version_info(struct net_device *dev, u16 rid,
				   const char *txt)
{
	struct hfa384x_comp_ident comp;

	if (hfa384x_get_rid(dev, rid, &comp, sizeof(comp), 1) < 0) {
		printk(KERN_DEBUG "Could not get RID for component %s\n", txt);
		return -1;
	}

	printk(KERN_INFO "%s: %s: id=0x%02x v%d.%d.%d\n", dev->name, txt,
	       __le16_to_cpu(comp.id), __le16_to_cpu(comp.major),
	       __le16_to_cpu(comp.minor), __le16_to_cpu(comp.variant));
	return 0;
}


static int prism2_setup_rids(struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	u16 tmp;
	int ret = 0;

	hostap_set_word(dev, HFA384X_RID_TICKTIME, 2000);

	if (!local->fw_ap) {
		tmp = hostap_get_porttype(local);
		ret = hostap_set_word(dev, HFA384X_RID_CNFPORTTYPE, tmp);
		if (ret) {
			printk("%s: Port type setting to %d failed\n",
			       dev->name, tmp);
			goto fail;
		}
	}

	/* Setting SSID to empty string seems to kill the card in Host AP mode
	 */
	if (local->iw_mode != IW_MODE_MASTER || local->essid[0] != '\0') {
		ret = hostap_set_string(dev, HFA384X_RID_CNFOWNSSID,
					local->essid);
		if (ret) {
			printk("%s: AP own SSID setting failed\n", dev->name);
			goto fail;
		}
	}

	ret = hostap_set_word(dev, HFA384X_RID_CNFMAXDATALEN,
			      PRISM2_DATA_MAXLEN);
	if (ret) {
		printk("%s: MAC data length setting to %d failed\n",
		       dev->name, PRISM2_DATA_MAXLEN);
		goto fail;
	}

	if (hfa384x_get_rid(dev, HFA384X_RID_CHANNELLIST, &tmp, 2, 1) < 0) {
		printk("%s: Channel list read failed\n", dev->name);
		ret = -EINVAL;
		goto fail;
	}
	local->channel_mask = __le16_to_cpu(tmp);

	if (local->channel < 1 || local->channel > 14 ||
	    !(local->channel_mask & (1 << (local->channel - 1)))) {
		printk(KERN_WARNING "%s: Channel setting out of range "
		       "(%d)!\n", dev->name, local->channel);
		ret = -EBUSY;
		goto fail;
	}

	ret = hostap_set_word(dev, HFA384X_RID_CNFOWNCHANNEL, local->channel);
	if (ret) {
		printk("%s: Channel setting to %d failed\n",
		       dev->name, local->channel);
		goto fail;
	}

	ret = hostap_set_word(dev, HFA384X_RID_CNFBEACONINT,
			      local->beacon_int);
	if (ret) {
		printk("%s: Beacon interval setting to %d failed\n",
		       dev->name, local->beacon_int);
		/* this may fail with Symbol/Lucent firmware */
		if (ret == -ETIMEDOUT)
			goto fail;
	}

	ret = hostap_set_word(dev, HFA384X_RID_CNFOWNDTIMPERIOD,
			      local->dtim_period);
	if (ret) {
		printk("%s: DTIM period setting to %d failed\n",
		       dev->name, local->dtim_period);
		/* this may fail with Symbol/Lucent firmware */
		if (ret == -ETIMEDOUT)
			goto fail;
	}

	ret = hostap_set_word(dev, HFA384X_RID_PROMISCUOUSMODE,
			      local->is_promisc);
	if (ret)
		printk(KERN_INFO "%s: Setting promiscuous mode (%d) failed\n",
		       dev->name, local->is_promisc);

	if (!local->fw_ap) {
		ret = hostap_set_string(dev, HFA384X_RID_CNFDESIREDSSID,
					local->essid);
		if (ret) {
			printk("%s: Desired SSID setting failed\n", dev->name);
			goto fail;
		}
	}

	/* Setup TXRateControl, defaults to allow use of 1, 2, 5.5, and
	 * 11 Mbps in automatic TX rate fallback and 1 and 2 Mbps as basic
	 * rates */
	if (local->tx_rate_control == 0) {
		local->tx_rate_control =
			HFA384X_RATES_1MBPS |
			HFA384X_RATES_2MBPS |
			HFA384X_RATES_5MBPS |
			HFA384X_RATES_11MBPS;
	}
	if (local->basic_rates == 0)
		local->basic_rates = HFA384X_RATES_1MBPS | HFA384X_RATES_2MBPS;

	if (!local->fw_ap) {
		ret = hostap_set_word(dev, HFA384X_RID_TXRATECONTROL,
				      local->tx_rate_control);
		if (ret) {
			printk("%s: TXRateControl setting to %d failed\n",
			       dev->name, local->tx_rate_control);
			goto fail;
		}

		ret = hostap_set_word(dev, HFA384X_RID_CNFSUPPORTEDRATES,
				      local->tx_rate_control);
		if (ret) {
			printk("%s: cnfSupportedRates setting to %d failed\n",
			       dev->name, local->tx_rate_control);
		}

		ret = hostap_set_word(dev, HFA384X_RID_CNFBASICRATES,
				      local->basic_rates);
		if (ret) {
			printk("%s: cnfBasicRates setting to %d failed\n",
			       dev->name, local->basic_rates);
		}

		ret = hostap_set_word(dev, HFA384X_RID_CREATEIBSS, 1);
		if (ret) {
			printk("%s: Create IBSS setting to 1 failed\n",
			       dev->name);
		}
	}

	if (local->name_set)
		(void) hostap_set_string(dev, HFA384X_RID_CNFOWNNAME,
					 local->name);

	if (hostap_set_encryption(local)) {
		printk(KERN_INFO "%s: could not configure encryption\n",
		       dev->name);
	}

	(void) hostap_set_antsel(local);

	if (hostap_set_roaming(local)) {
		printk(KERN_INFO "%s: could not set host roaming\n",
		       dev->name);
	}

	if (local->sta_fw_ver >= PRISM2_FW_VER(1,6,3) &&
	    hostap_set_word(dev, HFA384X_RID_CNFENHSECURITY, local->enh_sec))
		printk(KERN_INFO "%s: cnfEnhSecurity setting to 0x%x failed\n",
		       dev->name, local->enh_sec);

	/* 32-bit tallies were added in STA f/w 0.8.0, but they were apparently
	 * not working correctly (last seven counters report bogus values).
	 * This has been fixed in 0.8.2, so enable 32-bit tallies only
	 * beginning with that firmware version. Another bug fix for 32-bit
	 * tallies in 1.4.0; should 16-bit tallies be used for some other
	 * versions, too? */
	if (local->sta_fw_ver >= PRISM2_FW_VER(0,8,2)) {
		if (hostap_set_word(dev, HFA384X_RID_CNFTHIRTY2TALLY, 1)) {
			printk(KERN_INFO "%s: cnfThirty2Tally setting "
			       "failed\n", dev->name);
			local->tallies32 = 0;
		} else
			local->tallies32 = 1;
	} else
		local->tallies32 = 0;

	hostap_set_auth_algs(local);

	if (hostap_set_word(dev, HFA384X_RID_FRAGMENTATIONTHRESHOLD,
			    local->fragm_threshold)) {
		printk(KERN_INFO "%s: setting FragmentationThreshold to %d "
		       "failed\n", dev->name, local->fragm_threshold);
	}

	if (hostap_set_word(dev, HFA384X_RID_RTSTHRESHOLD,
			    local->rts_threshold)) {
		printk(KERN_INFO "%s: setting RTSThreshold to %d failed\n",
		       dev->name, local->rts_threshold);
	}

 fail:
	return ret;
}


static void prism2_clear_cmd_queue(local_info_t *local)
{
	struct list_head *ptr, *n;
	unsigned long flags;
	struct hostap_cmd_queue *entry;

	spin_lock_irqsave(&local->cmdlock, flags);
	for (ptr = local->cmd_queue.next, n = ptr->next;
	     ptr != &local->cmd_queue; ptr = n, n = ptr->next) {
		entry = list_entry(ptr, struct hostap_cmd_queue, list);
		atomic_inc(&entry->usecnt);
		printk(KERN_DEBUG "%s: removed pending cmd_queue entry "
		       "(type=%d, cmd=0x%04x, param0=0x%04x)\n",
		       local->dev->name, entry->type, entry->cmd,
		       entry->param0);
		__hostap_cmd_queue_free(local, entry, 1);
	}
	if (local->cmd_queue_len) {
		printk(KERN_DEBUG "%s: cmd_queue_len (%d) not zero after "
		       "flush\n", local->dev->name, local->cmd_queue_len);
		local->cmd_queue_len = 0;
	}
	spin_unlock_irqrestore(&local->cmdlock, flags);
}


static int prism2_hw_init(struct net_device *dev, int initial)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	int ret, first = 1;
	unsigned long start, delay;

	PDEBUG(DEBUG_FLOW, "prism2_hw_init()\n");

	clear_bit(HOSTAP_BITS_TRANSMIT, &local->bits);

 init:
	/* initialize HFA 384x */
	ret = hfa384x_cmd_no_wait(dev, HFA384X_CMDCODE_INIT, 0);
	if (ret) {
		printk("%s: first command failed - is the card compatible?\n",
		       dev_info);
		return 1;
	}

	if (first && (HFA384X_INW(HFA384X_EVSTAT_OFF) & HFA384X_EV_CMD)) {
		/* EvStat has Cmd bit set in some cases, so retry once if no
		 * wait was needed */
		HFA384X_OUTW(HFA384X_EV_CMD, HFA384X_EVACK_OFF);
		printk(KERN_DEBUG "%s: init command completed too quickly - "
		       "retrying\n", dev->name);
		first = 0;
		goto init;
	}

	start = jiffies;
	delay = jiffies + HFA384X_INIT_TIMEOUT;
	while (!(HFA384X_INW(HFA384X_EVSTAT_OFF) & HFA384X_EV_CMD) &&
	       time_before(jiffies, delay))
		yield();
	if (!(HFA384X_INW(HFA384X_EVSTAT_OFF) & HFA384X_EV_CMD)) {
		printk("%s: card initialization timed out\n", dev_info);
		return 1;
	}
	printk(KERN_DEBUG "prism2_hw_init: initialized in %lu ms\n",
	       (jiffies - start) * 1000 / HZ);
	HFA384X_OUTW(HFA384X_EV_CMD, HFA384X_EVACK_OFF);
	return 0;
}


static int prism2_hw_init2(struct net_device *dev, int initial)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	int i;

#ifdef PRISM2_DOWNLOAD_SUPPORT
	local->pda = prism2_read_pda(dev);
#endif /* PRISM2_DOWNLOAD_SUPPORT */

	hfa384x_disable_interrupts(dev);

#ifndef final_version
	HFA384X_OUTW(HFA384X_MAGIC, HFA384X_SWSUPPORT0_OFF);
	if (HFA384X_INW(HFA384X_SWSUPPORT0_OFF) != HFA384X_MAGIC) {
		printk("SWSUPPORT0 write/read failed: %04X != %04X\n",
		       HFA384X_INW(HFA384X_SWSUPPORT0_OFF), HFA384X_MAGIC);
		goto failed;
	}
#endif

	if (initial || local->pri_only) {
		hfa384x_events_only_cmd(dev);
		/* get card version information */
		if (prism2_get_version_info(dev, HFA384X_RID_NICID, "NIC") ||
		    prism2_get_version_info(dev, HFA384X_RID_PRIID, "PRI")) {
			hfa384x_disable_interrupts(dev);
			goto failed;
		}

		if (prism2_get_version_info(dev, HFA384X_RID_STAID, "STA")) {
			printk(KERN_DEBUG "%s: Failed to read STA f/w version "
			       "- only Primary f/w present\n", dev->name);
			local->pri_only = 1;
			return 0;
		}
		local->pri_only = 0;
		hfa384x_disable_interrupts(dev);
	}

	/* FIX: could convert allocate_fid to use sleeping CmdCompl wait and
	 * enable interrupts before this. This would also require some sort of
	 * sleeping AllocEv waiting */

	/* allocate TX FIDs */
	local->txfid_len = PRISM2_TXFID_LEN;
	for (i = 0; i < PRISM2_TXFID_COUNT; i++) {
		local->txfid[i] = hfa384x_allocate_fid(dev, local->txfid_len);
		if (local->txfid[i] == 0xffff && local->txfid_len > 1600) {
			local->txfid[i] = hfa384x_allocate_fid(dev, 1600);
			if (local->txfid[i] != 0xffff) {
				printk(KERN_DEBUG "%s: Using shorter TX FID "
				       "(1600 bytes)\n", dev->name);
				local->txfid_len = 1600;
			}
		}
		if (local->txfid[i] == 0xffff)
			goto failed;
		local->intransmitfid[i] = PRISM2_TXFID_EMPTY;
	}

	hfa384x_events_only_cmd(dev);

	if (initial) {
		prism2_check_sta_fw_version(local);

		if (hfa384x_get_rid(dev, HFA384X_RID_CNFOWNMACADDR,
				    &dev->dev_addr, 6, 1) < 0) {
			printk("%s: could not get own MAC address\n",
			       dev->name);
		}
		if (local->apdev)
			memcpy(local->apdev->dev_addr, dev->dev_addr,
			       ETH_ALEN);
		if (local->stadev)
			memcpy(local->stadev->dev_addr, dev->dev_addr,
			       ETH_ALEN);
	} else if (local->fw_ap)
		prism2_check_sta_fw_version(local);

	prism2_setup_rids(dev);

	/* MAC is now configured, but port 0 is not yet enabled */
	return 0;

 failed:
	printk(KERN_WARNING "%s: Initialization failed\n", dev_info);
	return 1;
}


static int prism2_hw_enable(struct net_device *dev, int initial)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	int was_resetting = local->hw_resetting;

	if (hfa384x_cmd(dev, HFA384X_CMDCODE_ENABLE, 0, NULL, NULL)) {
		printk("%s: MAC port 0 enabling failed\n", dev->name);
		return 1;
	}

	local->hw_ready = 1;
	local->hw_reset_tries = 0;
	local->hw_resetting = 0;
	hfa384x_enable_interrupts(dev);

	/* at least D-Link DWL-650 seems to require additional port reset
	 * before it starts acting as an AP, so reset port automatically
	 * here just in case */
	if (initial && prism2_reset_port(dev)) {
		printk("%s: MAC port 0 reseting failed\n", dev->name);
		return 1;
	}

	if (was_resetting && netif_queue_stopped(dev)) {
		/* If hw_reset() was called during pending transmit, netif
		 * queue was stopped. Wake it up now since the wlan card has
		 * been resetted. */
		hostap_netif_wake_queues(dev);
	}

	return 0;
}


static int prism2_hw_config(struct net_device *dev, int initial)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	if (local->hw_downloading)
		return 1;

	if (prism2_hw_init(dev, initial) || prism2_hw_init2(dev, initial))
		return 1;

	if (!local->pri_only && (!initial || !delayed_enable)) {
		if (!local->dev_enabled)
			prism2_callback(local, PRISM2_CALLBACK_ENABLE);
		local->dev_enabled = 1;
		return prism2_hw_enable(dev, initial);
	}

	return 0;
}


static void prism2_hw_shutdown(struct net_device *dev, int no_disable)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;

	/* Allow only command completion events during disable */
	hfa384x_events_only_cmd(dev);

	local->hw_ready = 0;
	if (local->dev_enabled)
		prism2_callback(local, PRISM2_CALLBACK_DISABLE);
	local->dev_enabled = 0;

	if (local->func->card_present && !local->func->card_present(local)) {
		printk(KERN_DEBUG "%s: card already removed or not configured "
		       "during shutdown\n", dev->name);
		return;
	}

	if ((no_disable & HOSTAP_HW_NO_DISABLE) == 0 &&
	    hfa384x_cmd(dev, HFA384X_CMDCODE_DISABLE, 0, NULL, NULL))
		printk(KERN_WARNING "%s: Shutdown failed\n", dev_info);

	hfa384x_disable_interrupts(dev);

	if (no_disable & HOSTAP_HW_ENABLE_CMDCOMPL)
		hfa384x_events_only_cmd(dev);
	else
		prism2_clear_cmd_queue(local);
}


static void prism2_hw_reset(struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;

#if 0
	static long last_reset = 0;

	/* do not reset card more than once per second to avoid ending up in a
	 * busy loop reseting the card */
	if (time_before_eq(jiffies, last_reset + HZ))
		return;
	last_reset = jiffies;
#endif

	if (in_interrupt()) {
		printk(KERN_DEBUG "%s: driver bug - prism2_hw_reset() called "
		       "in interrupt context\n", dev->name);
		return;
	}

	if (local->hw_downloading)
		return;

	if (local->hw_resetting) {
		printk(KERN_WARNING "%s: %s: already resetting card - "
		       "ignoring reset request\n", dev_info, dev->name);
		return;
	}

	local->hw_reset_tries++;
	if (local->hw_reset_tries > 10) {
		printk(KERN_WARNING "%s: too many reset tries, skipping\n",
		       dev->name);
		return;
	}

	printk(KERN_WARNING "%s: %s: resetting card\n", dev_info, dev->name);
	hfa384x_disable_interrupts(dev);
	local->hw_resetting = 1;
	if (local->func->cor_sreset) {
		/* Host system seems to hang in some cases with high traffic
		 * load or shared interrupts during COR sreset. Disable shared
		 * interrupts during reset to avoid these crashes. COS sreset
		 * takes quite a long time, so it is unfortunate that this
		 * seems to be needed. Anyway, I do not know of any better way
		 * of avoiding the crash. */
		disable_irq(dev->irq);
		local->func->cor_sreset(local);
		enable_irq(dev->irq);
	}
	prism2_hw_shutdown(dev, 1);
	prism2_hw_config(dev, 0);
	local->hw_resetting = 0;

#ifdef PRISM2_DOWNLOAD_SUPPORT
	if (local->dl_pri) {
		printk(KERN_DEBUG "%s: persistent download of primary "
		       "firmware\n", dev->name);
		if (prism2_download_genesis(local, local->dl_pri) < 0)
			printk(KERN_WARNING "%s: download (PRI) failed\n",
			       dev->name);
	}

	if (local->dl_sec) {
		printk(KERN_DEBUG "%s: persistent download of secondary "
		       "firmware\n", dev->name);
		if (prism2_download_volatile(local, local->dl_sec) < 0)
			printk(KERN_WARNING "%s: download (SEC) failed\n",
			       dev->name);
	}
#endif /* PRISM2_DOWNLOAD_SUPPORT */
}


static void prism2_schedule_reset(local_info_t *local)
{
	PRISM2_SCHEDULE_TASK(&local->reset_queue);
}


/* Called only as scheduled task after noticing card timeout in interrupt
 * context */
static void handle_reset_queue(void *data)
{
	local_info_t *local = (local_info_t *) data;

	printk(KERN_DEBUG "%s: scheduled card reset\n", local->dev->name);
	prism2_hw_reset(local->dev);

	if (netif_queue_stopped(local->dev)) {
		int i;

		for (i = 0; i < PRISM2_TXFID_COUNT; i++)
			if (local->intransmitfid[i] == PRISM2_TXFID_EMPTY) {
				PDEBUG(DEBUG_EXTRA, "prism2_tx_timeout: "
				       "wake up queue\n");
				hostap_netif_wake_queues(local->dev);
				break;
			}
	}

#ifndef NEW_MODULE_CODE
	MOD_DEC_USE_COUNT;
#endif
}


/* TODO: share one netif queue for all interfaces and get rid of this
 * function.. */
/* update trans_start for all used devices */
static void prism2_netif_update_trans_start(struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	struct list_head *ptr;

	read_lock_bh(&local->iface_lock);
	list_for_each(ptr, &local->hostap_interfaces) {
		iface = list_entry(ptr, struct hostap_interface, list);
		iface->dev->trans_start = jiffies;
	}
	read_unlock_bh(&local->iface_lock);
}


static int prism2_get_txfid_idx(local_info_t *local)
{
	int idx, end;
	unsigned long flags;

	spin_lock_irqsave(&local->txfidlock, flags);
	end = idx = local->next_txfid;
	do {
		if (local->intransmitfid[idx] == PRISM2_TXFID_EMPTY) {
			local->intransmitfid[idx] = PRISM2_TXFID_RESERVED;
			spin_unlock_irqrestore(&local->txfidlock, flags);
			return idx;
		}
		idx++;
		if (idx >= PRISM2_TXFID_COUNT)
			idx = 0;
	} while (idx != end);
	spin_unlock_irqrestore(&local->txfidlock, flags);

	PDEBUG(DEBUG_EXTRA2, "prism2_get_txfid_idx: no room in txfid buf: "
	       "packet dropped\n");
	local->stats.tx_dropped++;

	return -1;
}


/* Called only from hardware IRQ */
static void prism2_transmit_cb(struct net_device *dev, void *context,
			       u16 resp0, u16 res)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	int idx = (int) context;

	if (res) {
		printk(KERN_DEBUG "%s: prism2_transmit_cb - res=0x%02x\n",
		       dev->name, res);
		return;
	}

	if (idx < 0 || idx >= PRISM2_TXFID_COUNT) {
		printk(KERN_DEBUG "%s: prism2_transmit_cb called with invalid "
		       "idx=%d\n", dev->name, idx);
		return;
	}

	if (!test_and_clear_bit(HOSTAP_BITS_TRANSMIT, &local->bits)) {
		printk(KERN_DEBUG "%s: driver bug: prism2_transmit_cb called "
		       "with no pending transmit\n", dev->name);
	}

	if (netif_queue_stopped(dev)) {
		/* ready for next TX, so wake up queue that was stopped in
		 * prism2_transmit() */
		hostap_netif_wake_queues(dev);
	}

	spin_lock(&local->txfidlock);

	/* With reclaim, Resp0 contains new txfid for transmit; the old txfid
	 * will be automatically allocated for the next TX frame */
	local->intransmitfid[idx] = resp0;

	PDEBUG(DEBUG_FID, "%s: prism2_cmd_ev: txfid[%d]=0x%04x, resp0=0x%04x, "
	       "transmit_txfid=0x%04x\n", dev->name, idx, local->txfid[idx],
	       resp0, local->intransmitfid[local->next_txfid]);

	idx++;
	if (idx >= PRISM2_TXFID_COUNT)
		idx = 0;
	local->next_txfid = idx;

	/* check if all TX buffers are occupied */
	do {
		if (local->intransmitfid[idx] == PRISM2_TXFID_EMPTY) {
			spin_unlock(&local->txfidlock);
			return;
		}
		idx++;
		if (idx >= PRISM2_TXFID_COUNT)
			idx = 0;
	} while (idx != local->next_txfid);
	spin_unlock(&local->txfidlock);

	/* no empty TX buffers, stop queue */
	hostap_netif_stop_queues(dev);
}


/* Called only from software IRQ if PCI bus master is not used (with bus master
 * this can be called both from software and hardware IRQ) */
static int prism2_transmit(struct net_device *dev, int idx)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	int res;

	/* The driver tries to stop netif queue so that there would not be
	 * more than one attempt to transmit frames going on; check that this
	 * is really the case */

	if (test_and_set_bit(HOSTAP_BITS_TRANSMIT, &local->bits)) {
		printk(KERN_DEBUG "%s: driver bug - prism2_transmit() called "
		       "when previous TX was pending\n", dev->name);
		return -1;
	}

	/* stop the queue for the time that transmit is pending */
	hostap_netif_stop_queues(dev);

	/* transmit packet */
	res = hfa384x_cmd_callback(
		dev,
		HFA384X_CMDCODE_TRANSMIT | HFA384X_CMD_TX_RECLAIM,
		local->txfid[idx],
		prism2_transmit_cb, (void *) idx);

	if (res) {
		struct net_device_stats *stats;
		printk(KERN_DEBUG "%s: prism2_transmit: CMDCODE_TRANSMIT "
		       "failed (res=%d)\n", dev->name, res);
		stats = hostap_get_stats(dev);
		stats->tx_dropped++;
		hostap_netif_wake_queues(dev);
		return -1;
	}
	prism2_netif_update_trans_start(dev);

	/* Since we did not wait for command completion, the card continues
	 * to process on the background and we will finish handling when
	 * command completion event is handled (prism2_cmd_ev() function) */

	return 0;
}


/* Called only from hardware IRQ */
static void prism2_cmd_ev(struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	struct hostap_cmd_queue *entry = NULL;

	spin_lock(&local->cmdlock);
	if (!list_empty(&local->cmd_queue)) {
		entry = list_entry(local->cmd_queue.next,
				   struct hostap_cmd_queue, list);
		atomic_inc(&entry->usecnt);
		list_del_init(&entry->list);
		local->cmd_queue_len--;

		if (!entry->issued) {
			printk(KERN_DEBUG "%s: Command completion event, but "
			       "cmd not issued\n", dev->name);
			__hostap_cmd_queue_free(local, entry, 1);
			entry = NULL;
		}
	}
	spin_unlock(&local->cmdlock);

	if (!entry) {
		HFA384X_OUTW(HFA384X_EV_CMD, HFA384X_EVACK_OFF);
		printk(KERN_DEBUG "%s: Command completion event, but no "
		       "pending commands\n", dev->name);
		return;
	}

	entry->resp0 = HFA384X_INW(HFA384X_RESP0_OFF);
	entry->res = (HFA384X_INW(HFA384X_STATUS_OFF) &
		      (BIT(14) | BIT(13) | BIT(12) | BIT(11) | BIT(10) |
		       BIT(9) | BIT(8))) >> 8;
	HFA384X_OUTW(HFA384X_EV_CMD, HFA384X_EVACK_OFF);

	/* TODO: rest of the CmdEv handling could be moved to tasklet */
	if (entry->type == CMD_SLEEP) {
		entry->type = CMD_COMPLETED;
		wake_up_interruptible(&entry->compl);
	} else if (entry->type == CMD_CALLBACK) {
		if (entry->callback)
			entry->callback(dev, entry->context, entry->resp0,
					entry->res);
	} else {
		printk(KERN_DEBUG "%s: Invalid command completion type %d\n",
		       dev->name, entry->type);
	}
	hostap_cmd_queue_free(local, entry, 1);

	/* issue next command, if pending */
	entry = NULL;
	spin_lock(&local->cmdlock);
	if (!list_empty(&local->cmd_queue)) {
		entry = list_entry(local->cmd_queue.next,
				   struct hostap_cmd_queue, list);
		if (entry->issuing) {
			/* hfa384x_cmd() has already started issuing this
			 * command, so do not start here */
			entry = NULL;
		}
		if (entry)
			atomic_inc(&entry->usecnt);
	}
	spin_unlock(&local->cmdlock);

	if (entry) {
		/* issue next command; if command issuing fails, remove the
		 * entry from cmd_queue */
		int res = hfa384x_cmd_issue(dev, entry);
		spin_lock(&local->cmdlock);
		__hostap_cmd_queue_free(local, entry, res);
		spin_unlock(&local->cmdlock);
	}
}


#if defined(PRISM2_PCI) && defined(PRISM2_BUS_MASTER)
static void prism2_tx_cb(struct net_device *dev, void *context,
			 u16 resp0, u16 res)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	unsigned long addr;
	int buf_len = (int) context;

	if (res) {
		printk(KERN_DEBUG "%s: prism2_tx_cb - res=0x%02x\n",
		       dev->name, res);
		return;
	}

	addr = virt_to_phys(local->bus_m0_buf);
	HFA384X_OUTW((addr & 0xffff0000) >> 16, HFA384X_PCI_M0_ADDRH_OFF);
	HFA384X_OUTW(addr & 0x0000ffff, HFA384X_PCI_M0_ADDRL_OFF);
	HFA384X_OUTW(buf_len / 2, HFA384X_PCI_M0_LEN_OFF);
	HFA384X_OUTW(HFA384X_PCI_CTL_TO_BAP, HFA384X_PCI_M0_CTL_OFF);
}
#endif /* PRISM2_PCI and PRISM2_BUS_MASTER */


/* Called only from software IRQ */
static int prism2_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	int res, idx = -1, ret = 1, data_len;
	struct hfa384x_tx_frame txdesc;
	u16 fc, ethertype = 0;
	enum { WDS_NO, WDS_OWN_FRAME, WDS_COMPLIANT_FRAME } use_wds = WDS_NO;
	struct net_device_stats *stats;
	u8 *wepbuf = NULL;
	int wepbuf_len = 0, host_encrypt = 0;
	struct prism2_crypt_data *crypt = NULL;
	void *sta = NULL;
	u8 *encaps_data;
	int encaps_len, skip_header_bytes;
	int no_encrypt = 0;
	int to_assoc_ap = 0;

	prism2_callback(local, PRISM2_CALLBACK_TX_START);
	stats = hostap_get_stats(dev);

	if ((local->func->card_present && !local->func->card_present(local)) ||
	    !local->hw_ready || local->hw_downloading || local->pri_only) {
		if (net_ratelimit())
			printk(KERN_DEBUG "%s: prism2_tx: hw not ready - "
			       "skipping\n", dev->name);
		ret = 0;
		goto fail;
	}

	if (skb->len < ETH_HLEN) {
		printk(KERN_DEBUG "%s: prism2_tx: short skb (len=%d)\n",
		       dev->name, skb->len);
		ret = 0;
		goto fail;
	}

	if (local->dev != dev) {
		use_wds = (local->iw_mode == IW_MODE_MASTER &&
			   !(local->wds_type & HOSTAP_WDS_STANDARD_FRAME)) ?
			WDS_OWN_FRAME : WDS_COMPLIANT_FRAME;
		if (dev == local->stadev) {
			to_assoc_ap = 1;
			use_wds = WDS_NO;
		} else if (dev == local->apdev) {
			printk(KERN_DEBUG "%s: prism2_tx: trying to use "
			       "AP device with Ethernet net dev\n", dev->name);
			ret = 0;
			goto fail;
		}
	} else {
		if (local->iw_mode == IW_MODE_REPEAT) {
			printk(KERN_DEBUG "%s: prism2_tx: trying to use "
			       "non-WDS link in Repeater mode\n", dev->name);
			ret = 0;
			goto fail;
		} else if (local->iw_mode == IW_MODE_INFRA &&
			   (local->wds_type & HOSTAP_WDS_AP_CLIENT) &&
			   memcmp(skb->data + ETH_ALEN, dev->dev_addr,
				  ETH_ALEN) != 0) {
			/* AP client mode: send frames with foreign src addr
			 * using 4-addr WDS frames */
			use_wds = WDS_COMPLIANT_FRAME;
		}
	}

	if (local->host_encrypt) {
		/* Set crypt to default algorithm and key; will be replaced in
		 * AP code if STA has own alg/key */
		crypt = local->crypt;
		host_encrypt = 1;
	}

	if (skb->protocol == __constant_htons(ETH_P_HOSTAP)) {
		/* frame from prism2_send_mgmt() */
		if (skb->len < sizeof(txdesc)) {
			printk(KERN_DEBUG "%s: prism2_tx: short ETH_P_HOSTAP "
			       "skb\n", dev->name);
			ret = 0;
			goto fail;
		}
		memcpy(&txdesc, skb->data, sizeof(txdesc));
		skb_pull(skb, sizeof(txdesc));
		encaps_data = NULL;
		encaps_len = 0;
		skip_header_bytes = 0;
		data_len = skb->len;

		fc = le16_to_cpu(txdesc.frame_control);

		/* data frames use normal host encryption, if needed */
		if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_DATA)
			goto data_txdesc_set;

		/* mgmt/ctrl frames do not need further processing, so skip to
		 * frame transmit */
		goto frame_processing_done;
	}

	/* Incoming skb->data: dst_addr[6], src_addr[6], proto[2], payload
	 * ==>
	 * Prism2 TX frame with 802.11 header:
	 * txdesc (address order depending on used mode; includes dst_addr and
	 * src_addr), possible encapsulation (RFC1042/Bridge-Tunnel;
	 * proto[2], payload {, possible addr4[6]} */

	ethertype = (skb->data[12] << 8) | skb->data[13];

	memset(&txdesc, 0, sizeof(txdesc));

	txdesc.tx_control = __cpu_to_le16(local->tx_control);

	/* Length of data after txdesc */
	data_len = skb->len - ETH_HLEN;
	encaps_data = NULL;
	encaps_len = 0;
	skip_header_bytes = ETH_HLEN;
	if (ethertype == ETH_P_AARP || ethertype == ETH_P_IPX) {
		encaps_data = bridge_tunnel_header;
		encaps_len = sizeof(bridge_tunnel_header);
		data_len += encaps_len + 2;
		skip_header_bytes -= 2;
	} else if (ethertype >= 0x600) {
		encaps_data = rfc1042_header;
		encaps_len = sizeof(rfc1042_header);
		data_len += encaps_len + 2;
		skip_header_bytes -= 2;
	}

	fc = (WLAN_FC_TYPE_DATA << 2) | (WLAN_FC_STYPE_DATA << 4);
	memcpy(&txdesc.dst_addr, skb->data, 2 * ETH_ALEN);

	if (use_wds != WDS_NO) {
		/* Note! Prism2 station firmware has problems with sending real
		 * 802.11 frames with four addresses; until these problems can
		 * be fixed or worked around, 4-addr frames needed for WDS are
		 * using incompatible format: FromDS flag is not set and the
		 * fourth address is added after the frame payload; it is
		 * assumed, that the receiving station knows how to handle this
		 * frame format */

		if (use_wds == WDS_COMPLIANT_FRAME) {
			fc |= WLAN_FC_FROMDS | WLAN_FC_TODS;
			/* From&To DS: Addr1 = RA, Addr2 = TA, Addr3 = DA,
			 * Addr4 = SA */
			memcpy(&txdesc.addr4, skb->data + ETH_ALEN, ETH_ALEN);
		} else {
			/* bogus 4-addr format to workaround Prism2 station
			 * f/w bug */
			fc |= WLAN_FC_TODS;
			/* From DS: Addr1 = DA (used as RA),
			 * Addr2 = BSSID (used as TA), Addr3 = SA (used as DA),
			 */

			/* SA from skb->data + ETH_ALEN will be added after
			 * frame payload */
			data_len += ETH_ALEN;

			memcpy(&txdesc.src_addr, dev->dev_addr, ETH_ALEN);
		}

		/* send broadcast and multicast frames to broadcast RA, if
		 * configured; otherwise, use unicast RA of the WDS link */
		if ((local->wds_type & HOSTAP_WDS_BROADCAST_RA) &&
		    skb->data[0] & 0x01)
			memset(&txdesc.addr1, 0xff, ETH_ALEN);
		else if (iface->type == HOSTAP_INTERFACE_WDS)
			memcpy(&txdesc.addr1, iface->u.wds.remote_addr,
			       ETH_ALEN);
		else
			memcpy(&txdesc.addr1, local->bssid, ETH_ALEN);
		memcpy(&txdesc.addr2, dev->dev_addr, ETH_ALEN);
		memcpy(&txdesc.addr3, skb->data, ETH_ALEN);
	} else if (local->iw_mode == IW_MODE_MASTER && !to_assoc_ap) {
		fc |= WLAN_FC_FROMDS;
		/* From DS: Addr1 = DA, Addr2 = BSSID, Addr3 = SA */
		memcpy(&txdesc.addr1, skb->data, ETH_ALEN);
		/* FIX - addr2 replaced by f/w, so no need to fill it now(?) */
		memcpy(&txdesc.addr2, dev->dev_addr, ETH_ALEN);
		memcpy(&txdesc.addr3, skb->data + ETH_ALEN, ETH_ALEN);
	} else if (local->iw_mode == IW_MODE_INFRA || to_assoc_ap) {
		fc |= WLAN_FC_TODS;
		/* To DS: Addr1 = BSSID, Addr2 = SA, Addr3 = DA */
		memcpy(&txdesc.addr1, to_assoc_ap ?
		       local->assoc_ap_addr : local->bssid, ETH_ALEN);
		memcpy(&txdesc.addr2, skb->data + ETH_ALEN, ETH_ALEN);
		memcpy(&txdesc.addr3, skb->data, ETH_ALEN);
	} else if (local->iw_mode == IW_MODE_ADHOC) {
		/* not From/To DS: Addr1 = DA, Addr2 = SA, Addr3 = BSSID */
		memcpy(&txdesc.addr1, skb->data, ETH_ALEN);
		memcpy(&txdesc.addr2, skb->data + ETH_ALEN, ETH_ALEN);
		memcpy(&txdesc.addr3, local->bssid, ETH_ALEN);
	}

	txdesc.frame_control = __cpu_to_le16(fc);
	txdesc.data_len = __cpu_to_le16(data_len);
	txdesc.len = __cpu_to_be16(data_len);

	skb->dev = dev;

 data_txdesc_set:
	if (to_assoc_ap)
		goto skip_ap_processing;

	switch (hostap_handle_sta_tx(local, skb, &txdesc, use_wds != WDS_NO,
				     host_encrypt, &crypt, &sta)) {
	case AP_TX_CONTINUE:
		break;
	case AP_TX_CONTINUE_NOT_AUTHORIZED:
		if (local->ieee_802_1x && ethertype != ETH_P_PAE &&
		    use_wds == WDS_NO) {
			printk(KERN_DEBUG "%s: dropped frame to unauthorized "
			       "port (IEEE 802.1X): ethertype=0x%04x\n",
			       dev->name, ethertype);
			hostap_dump_tx_header(dev->name, &txdesc);

			ret = 0; /* drop packet */
			stats->tx_dropped++;
			goto fail;
		}
		break;
	case AP_TX_DROP:
		ret = 0; /* drop packet */
		stats->tx_dropped++;
		goto fail;
	case AP_TX_RETRY:
		goto fail;
	case AP_TX_BUFFERED:
		/* do not free skb here, it will be freed when the
		 * buffered frame is sent/timed out */
		ret = 0;
		goto tx_exit;
	}

 skip_ap_processing:

	if (local->ieee_802_1x && ethertype == ETH_P_PAE) {
		if (crypt) {
			no_encrypt = 1;
			printk(KERN_DEBUG "%s: TX: IEEE 802.1X - passing "
			       "unencrypted EAPOL frame\n", dev->name);
		}
		crypt = NULL; /* no encryption for IEEE 802.1X frames */
	}

	if (crypt && (!crypt->ops || !crypt->ops->encrypt))
		crypt = NULL;
	else if ((crypt || local->crypt) && !no_encrypt) {
		/* Add ISWEP flag both for firmware and host based encryption
		 */
		fc |= WLAN_FC_ISWEP;
		txdesc.frame_control = cpu_to_le16(fc);
	}

	if (crypt) {
		/* Perform host driver -based encryption */
		u8 *pos;
		int olen;

		olen = data_len;
		data_len += crypt->ops->extra_prefix_len +
			crypt->ops->extra_postfix_len;
		txdesc.data_len = cpu_to_le16(data_len);
		txdesc.len = cpu_to_be16(data_len);

		wepbuf_len = data_len;
		wepbuf = (u8 *) kmalloc(wepbuf_len, GFP_ATOMIC);
		if (wepbuf == NULL) {
			printk(KERN_DEBUG "%s: could not allocate TX wepbuf\n",
			       dev->name);
			goto fail;
		}

		pos = wepbuf + crypt->ops->extra_prefix_len;
		if (encaps_len > 0) {
			memcpy(pos, encaps_data, encaps_len);
			pos += encaps_len;
		}
		memcpy(pos, skb->data + skip_header_bytes,
		       skb->len - skip_header_bytes);
		if (use_wds == WDS_OWN_FRAME) {
			memcpy(pos + skb->len - skip_header_bytes,
			       skb->data + ETH_ALEN, ETH_ALEN);
		}

		atomic_inc(&crypt->refcnt);
		olen = crypt->ops->encrypt(wepbuf, olen, crypt->priv);
		atomic_dec(&crypt->refcnt);
		if (olen > wepbuf_len) {
			printk(KERN_WARNING "%s: encrypt overwrote wepbuf "
			       "(%d > %d)\n", dev->name, olen, wepbuf_len);
		}
		if (olen < 0)
			goto fail;

		data_len = wepbuf_len = olen;
		txdesc.data_len = cpu_to_le16(data_len);
		txdesc.len = cpu_to_be16(data_len);
	}

 frame_processing_done:
	idx = prism2_get_txfid_idx(local);
	if (idx < 0)
		goto fail;

	if (local->frame_dump & PRISM2_DUMP_TX_HDR)
		hostap_dump_tx_header(dev->name, &txdesc);

	spin_lock(&local->baplock);
	res = hfa384x_setup_bap(dev, BAP0, local->txfid[idx], 0);

#if defined(PRISM2_PCI) && defined(PRISM2_BUS_MASTER)
	if (!res && skb->len >= local->bus_master_threshold_tx) {
		u8 *pos;
		int buf_len;

		local->bus_m0_tx_idx = idx;

		/* FIX: BAP0 should be locked during bus master transfer, but
		 * baplock with BH's disabled is not OK for this; netif queue
		 * stopping is not enough since BAP0 is used also for RID
		 * read/write */

		/* stop the queue for the time that bus mastering on BAP0 is
		 * in use */
		hostap_netif_stop_queues(dev);

		spin_unlock(&local->baplock);

		/* Copy frame data to bus_m0_buf */
		pos = local->bus_m0_buf;
		memcpy(pos, &txdesc, sizeof(txdesc));
		pos += sizeof(txdesc);

		if (!wepbuf) {
			if (encaps_len > 0) {
				memcpy(pos, encaps_data, encaps_len);
				pos += encaps_len;
			}
			memcpy(pos, skb->data + skip_header_bytes,
			       skb->len - skip_header_bytes);
			pos += skb->len - skip_header_bytes;
		}
		if (!wepbuf && use_wds == WDS_OWN_FRAME) {
			/* add addr4 (SA) to bogus frame format if WDS is used
			 */
			memcpy(pos, skb->data + ETH_ALEN, ETH_ALEN);
			pos += ETH_ALEN;
		}

		if (wepbuf) {
			memcpy(pos, wepbuf, wepbuf_len);
			pos += wepbuf_len;
		}

		buf_len = pos - local->bus_m0_buf;
		if (buf_len & 1)
			buf_len++;

#ifdef PRISM2_ENABLE_BEFORE_TX_BUS_MASTER
		/* Any RX packet seems to break something with TX bus
		 * mastering; enable command is enough to fix this.. */
		if (hfa384x_cmd_callback(dev, HFA384X_CMDCODE_ENABLE, 0,
					 prism2_tx_cb, (void *) buf_len)) {
			printk(KERN_DEBUG "%s: TX: enable port0 failed\n",
			       dev->name);
		}
#else /* PRISM2_ENABLE_BEFORE_TX_BUS_MASTER */
		prism2_tx_cb(dev, (void *) buf_len, 0, 0);
#endif /* PRISM2_ENABLE_BEFORE_TX_BUS_MASTER */

		/* Bus master transfer will be started from command completion
		 * event handler and TX handling will be finished by calling
		 * prism2_transmit() from bus master event handler */
		goto tx_stats;
	}
#endif /* PRISM2_PCI and PRISM2_BUS_MASTER */

	if (!res)
		res = hfa384x_to_bap(dev, BAP0, &txdesc, sizeof(txdesc));
	if (!res && !wepbuf && encaps_len > 0)
		res = hfa384x_to_bap(dev, BAP0, encaps_data, encaps_len);
	if (!res && !wepbuf && use_wds != WDS_OWN_FRAME)
		res = hfa384x_to_bap(dev, BAP0, skb->data + skip_header_bytes,
				     skb->len - skip_header_bytes);
	else if (!res && !wepbuf && use_wds == WDS_OWN_FRAME) {
		int wlen, is_odd;

		wlen = skb->len - skip_header_bytes;
		is_odd = wlen & 1;

		if (is_odd)
			wlen--; /* need to avoid using odd offset */

		res = hfa384x_to_bap(dev, BAP0, skb->data + skip_header_bytes,
				     wlen);

		/* add addr4 (SA) to bogus frame format if WDS is used */
		if (!res && is_odd) {
			char tmpbuf[ETH_ALEN + 1];
			tmpbuf[0] = *(skb->data + skb->len - 1);
			memcpy(tmpbuf + 1, skb->data + ETH_ALEN, ETH_ALEN);
			res = hfa384x_to_bap(dev, BAP0, tmpbuf, ETH_ALEN + 1);
		} else if (!res) {
			res = hfa384x_to_bap(dev, BAP0, skb->data + ETH_ALEN,
					     ETH_ALEN);
		}
	}

	if (!res && wepbuf)
		res = hfa384x_to_bap(dev, BAP0, wepbuf, wepbuf_len);
	spin_unlock(&local->baplock);

	if (!res)
		res = prism2_transmit(dev, idx);
	if (res) {
		printk(KERN_DEBUG "%s: prism2_tx - to BAP0 failed\n",
		       dev->name);
		local->intransmitfid[idx] = PRISM2_TXFID_EMPTY;
		PRISM2_SCHEDULE_TASK(&local->reset_queue);
		ret = 0; /* do not retry failed frames to avoid problems */
		goto fail;
	}

#if defined(PRISM2_PCI) && defined(PRISM2_BUS_MASTER)
 tx_stats:
#endif
	stats->tx_packets++;
	stats->tx_bytes += data_len + 36;

	ret = 0;

 fail:
	if (wepbuf)
		kfree(wepbuf);

	if (!ret)
		dev_kfree_skb(skb);

 tx_exit:
	if (sta)
		hostap_handle_sta_release(sta);

	prism2_callback(local, PRISM2_CALLBACK_TX_END);
	return ret;
}


/* Called only from software IRQ */
static int prism2_tx_80211(struct sk_buff *skb, struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	struct hfa384x_tx_frame txdesc;
	int hdr_len, data_len, ret = 1, idx, res;
	u16 fc, tx_control;

	if ((local->func->card_present && !local->func->card_present(local)) ||
	    !local->hw_ready || local->hw_downloading || local->pri_only) {
		printk(KERN_DEBUG "%s: prism2_tx_80211: hw not ready - "
		       "skipping\n", dev->name);
		ret = 0;
		local->apdevstats.tx_dropped++;
		goto fail;
	}

	if (skb->len < 24) {
		printk(KERN_DEBUG "%s: prism2_tx_80211: short skb (len=%d)\n",
		       dev->name, skb->len);
		ret = 0;
		local->apdevstats.tx_dropped++;
		goto fail;
	}

	memset(&txdesc, 0, sizeof(txdesc));
	/* txdesc.tx_rate might need to be set if f/w does not select suitable
	 * TX rate */

	/* skb->data starts with txdesc->frame_control */
	hdr_len = 24;
	memcpy(&txdesc.frame_control, skb->data, hdr_len);
 	fc = le16_to_cpu(txdesc.frame_control);
	if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_DATA &&
	    (fc & WLAN_FC_FROMDS) && (fc & WLAN_FC_TODS) && skb->len >= 30) {
		/* Addr4 */
		memcpy(txdesc.addr4, skb->data + hdr_len, ETH_ALEN);
		hdr_len += ETH_ALEN;
	}

	tx_control = local->tx_control;
	/* Request TX callback if protocol version is 2 in 802.11 header;
	 * this version 2 is a special case used between hostapd and kernel
	 * driver */
	if (((fc & WLAN_FC_PVER) == BIT(1)) &&
	    local->ap && local->ap->tx_callback_idx) {
		tx_control |= HFA384X_TX_CTRL_TX_OK;
		txdesc.sw_support = cpu_to_le16(local->ap->tx_callback_idx);

		/* remove special version from the frame header */
		fc &= ~WLAN_FC_PVER;
		txdesc.frame_control = cpu_to_le16(fc);
	}
	txdesc.tx_control = cpu_to_le16(tx_control);
	
	data_len = skb->len - hdr_len;
	txdesc.data_len = __cpu_to_le16(data_len);
	txdesc.len = __cpu_to_be16(data_len);

	/* We do not need to care about frame authorization etc. here since
	 * hostapd has full knowledge of auth/assoc status. However, we need to
	 * buffer the frame is the destination STA is in power saving mode.
	 *
	 * Wi-Fi 802.11b test plan suggests that AP should ignore power save
	 * bit in authentication and (re)association frames and assume tha
	 * STA remains awake for the response. */
	if (hostap_handle_sta_tx(local, skb, &txdesc, 0, 0, NULL, NULL) ==
	    AP_TX_BUFFERED &&
	    (WLAN_FC_GET_TYPE(fc) != WLAN_FC_TYPE_MGMT ||
	     (WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_AUTH &&
	      WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_ASSOC_RESP &&
	      WLAN_FC_GET_STYPE(fc) != WLAN_FC_STYPE_REASSOC_RESP))) {
		/* do not free skb here, it will be freed when the
		 * buffered frame is sent/timed out */
		ret = 0;
		goto tx_exit;
	}

	idx = prism2_get_txfid_idx(local);
	if (idx < 0) {
		local->apdevstats.tx_dropped++;
		goto fail;
	}

	spin_lock(&local->baplock);
	res = hfa384x_setup_bap(dev, BAP0, local->txfid[idx], 0);
	if (!res)
		res = hfa384x_to_bap(dev, BAP0, &txdesc, sizeof(txdesc));
	if (!res)
		res = hfa384x_to_bap(dev, BAP0, skb->data + hdr_len,
				     skb->len - hdr_len);
	spin_unlock(&local->baplock);

	if (!res)
		res = prism2_transmit(dev, idx);
	if (res) {
		printk(KERN_DEBUG "%s: prism2_tx_80211 - to BAP0 failed\n",
		       dev->name);
		local->intransmitfid[idx] = PRISM2_TXFID_EMPTY;
		PRISM2_SCHEDULE_TASK(&local->reset_queue);
		local->apdevstats.tx_dropped++;
		ret = 0;
		goto fail;
	}

	ret = 0;

	local->apdevstats.tx_packets++;
	local->apdevstats.tx_bytes += skb->len;

 fail:
	if (!ret)
		dev_kfree_skb(skb);
 tx_exit:
	return ret;
}


/* Some SMP systems have reported number of odd errors with hostap_pci. fid
 * register has changed values between consecutive reads for an unknown reason.
 * This should really not happen, so more debugging is needed. This test
 * version is a big slower, but it will detect most of such register changes
 * and will try to get the correct fid eventually. */
#define EXTRA_FID_READ_TESTS

static inline u16 prism2_read_fid_reg(struct net_device *dev, u16 reg)
{
#ifdef EXTRA_FID_READ_TESTS
	u16 val, val2, val3;
	int i;

	for (i = 0; i < 10; i++) {
		val = HFA384X_INW(reg);
		val2 = HFA384X_INW(reg);
		val3 = HFA384X_INW(reg);

		if (val == val2 && val == val3)
			return val;

		printk(KERN_DEBUG "%s: detected fid change (try=%d, reg=%04x):"
		       " %04x %04x %04x\n",
		       dev->name, i, reg, val, val2, val3);
		if ((val == val2 || val == val3) && val != 0)
			return val;
		if (val2 == val3 && val2 != 0)
			return val2;
	}
	printk(KERN_WARNING "%s: Uhhuh.. could not read good fid from reg "
	       "%04x (%04x %04x %04x)\n", dev->name, reg, val, val2, val3);
	return val;
#else /* EXTRA_FID_READ_TESTS */
	return HFA384X_INW(reg);
#endif /* EXTRA_FID_READ_TESTS */
}


/* Called only as a tasklet (software IRQ) */
static void prism2_rx(local_info_t *local)
{
	struct net_device *dev = local->dev;
	int res, rx_pending = 0;
	u16 len, hdr_len, rxfid, status, macport;
	struct net_device_stats *stats;
	struct hfa384x_rx_frame rxdesc;
	struct sk_buff *skb = NULL;

	prism2_callback(local, PRISM2_CALLBACK_RX_START);
	stats = hostap_get_stats(dev);

	rxfid = prism2_read_fid_reg(dev, HFA384X_RXFID_OFF);
#ifndef final_version
	if (rxfid == 0) {
		rxfid = HFA384X_INW(HFA384X_RXFID_OFF);
		printk(KERN_DEBUG "prism2_rx: rxfid=0 (next 0x%04x)\n",
		       rxfid);
		if (rxfid == 0) {
			PRISM2_SCHEDULE_TASK(&local->reset_queue);
			goto rx_dropped;
		}
		/* try to continue with the new rxfid value */
	}
#endif

	spin_lock(&local->baplock);
	res = hfa384x_setup_bap(dev, BAP0, rxfid, 0);
	if (!res)
		res = hfa384x_from_bap(dev, BAP0, &rxdesc, sizeof(rxdesc));

	if (res) {
		spin_unlock(&local->baplock);
		printk(KERN_DEBUG "%s: copy from BAP0 failed %d\n", dev->name,
		       res);
		if (res == -ETIMEDOUT) {
			PRISM2_SCHEDULE_TASK(&local->reset_queue);
		}
		goto rx_dropped;
	}

	len = le16_to_cpu(rxdesc.data_len);
	hdr_len = sizeof(rxdesc);
	status = le16_to_cpu(rxdesc.status);
	macport = (status >> 8) & 0x07;

	/* Drop frames with too large reported payload length. Monitor mode
	 * seems to sometimes pass frames (e.g., ctrl::ack) with signed and
	 * negative value, so allow also values 65522 .. 65534 (-14 .. -2) for
	 * macport 7 */
	if (len > PRISM2_DATA_MAXLEN + 8 /* WEP */) {
		if (macport == 7 && local->iw_mode == IW_MODE_MONITOR) {
			if (len >= (u16) -14) {
				hdr_len -= 65535 - len;
				hdr_len--;
			}
			len = 0;
		} else {
			spin_unlock(&local->baplock);
			printk(KERN_DEBUG "%s: Received frame with invalid "
			       "length 0x%04x\n", dev->name, len);
			hostap_dump_rx_header(dev->name, &rxdesc);
			goto rx_dropped;
		}
	}

	skb = dev_alloc_skb(len + hdr_len);
	if (!skb) {
		spin_unlock(&local->baplock);
		printk(KERN_DEBUG "%s: RX failed to allocate skb\n",
		       dev->name);
		goto rx_dropped;
	}
	skb->dev = dev;
	memcpy(skb_put(skb, hdr_len), &rxdesc, hdr_len);

#if defined(PRISM2_PCI) && defined(PRISM2_BUS_MASTER)
	if (len >= local->bus_master_threshold_rx) {
		unsigned long addr;

		hfa384x_events_no_bap1(dev);

		local->rx_skb = skb;
		/* Internal BAP0 offset points to the byte following rxdesc;
		 * copy rest of the data using bus master */
		addr = virt_to_phys(skb_put(skb, len));
		HFA384X_OUTW((addr & 0xffff0000) >> 16,
			     HFA384X_PCI_M0_ADDRH_OFF);
		HFA384X_OUTW(addr & 0x0000ffff, HFA384X_PCI_M0_ADDRL_OFF);
		if (len & 1)
			len++;
		HFA384X_OUTW(len / 2, HFA384X_PCI_M0_LEN_OFF);
		HFA384X_OUTW(HFA384X_PCI_CTL_FROM_BAP, HFA384X_PCI_M0_CTL_OFF);

		/* pci_bus_m1 event will be generated when data transfer is
		 * complete and the frame will then be added to rx_list and
		 * rx_tasklet is scheduled */
		rx_pending = 1;

		/* Have to release baplock before returning, although BAP0
		 * should really not be used before DMA transfer has been
		 * completed. */
		spin_unlock(&local->baplock);
	} else
#endif /* PRISM2_PCI and PRISM2_BUS_MASTER */
	{
		if (len > 0)
			res = hfa384x_from_bap(dev, BAP0, skb_put(skb, len),
					       len);
		spin_unlock(&local->baplock);
		if (res) {
			printk(KERN_DEBUG "%s: RX failed to read "
			       "frame data\n", dev->name);
			goto rx_dropped;
		}

		skb_queue_tail(&local->rx_list, skb);
		tasklet_schedule(&local->rx_tasklet);
	}

 rx_exit:
	prism2_callback(local, PRISM2_CALLBACK_RX_END);
	if (!rx_pending) {
		HFA384X_OUTW(HFA384X_EV_RX, HFA384X_EVACK_OFF);
	}

	return;

 rx_dropped:
	stats->rx_dropped++;
	if (skb)
		dev_kfree_skb(skb);
	goto rx_exit;
}


/* Called only as a tasklet (software IRQ) */
static void hostap_rx_skb(local_info_t *local, struct sk_buff *skb)
{
	struct hfa384x_rx_frame *rxdesc;
	struct net_device *dev = skb->dev;
	struct hostap_80211_rx_status stats;
	int hdrlen, rx_hdrlen;

	rx_hdrlen = sizeof(*rxdesc);
	if (skb->len < sizeof(*rxdesc)) {
		/* Allow monitor mode to receive shorter frames */
		if (local->iw_mode == IW_MODE_MONITOR &&
		    skb->len >= sizeof(*rxdesc) - 30) {
			rx_hdrlen = skb->len;
		} else {
			dev_kfree_skb(skb);
			return;
		}
	}

	rxdesc = (struct hfa384x_rx_frame *) skb->data;

	if (local->frame_dump & PRISM2_DUMP_RX_HDR &&
	    skb->len >= sizeof(*rxdesc))
		hostap_dump_rx_header(dev->name, rxdesc);

	if (le16_to_cpu(rxdesc->status) & HFA384X_RX_STATUS_FCSERR &&
	    (!local->monitor_allow_fcserr ||
	     local->iw_mode != IW_MODE_MONITOR))
		goto drop;

	if (skb->len > PRISM2_DATA_MAXLEN) {
		printk(KERN_DEBUG "%s: RX: len(%d) > MAX(%d)\n",
		       dev->name, skb->len, PRISM2_DATA_MAXLEN);
		goto drop;
	}

	stats.mac_time = le32_to_cpu(rxdesc->time);
	stats.signal = HFA384X_RSSI_LEVEL_TO_dBm(rxdesc->signal);
	stats.noise = HFA384X_RSSI_LEVEL_TO_dBm(rxdesc->silence);
	stats.rate = rxdesc->rate;

	/* Convert Prism2 RX structure into IEEE 802.11 header */
	hdrlen = hostap_80211_get_hdrlen(le16_to_cpu(rxdesc->frame_control));
	if (hdrlen > rx_hdrlen)
		hdrlen = rx_hdrlen;

	memmove(skb_pull(skb, rx_hdrlen - hdrlen),
		&rxdesc->frame_control, hdrlen);

	hostap_80211_rx(dev, skb, &stats);
	return;

 drop:
	dev_kfree_skb(skb);
}


/* Called only as a tasklet (software IRQ) */
static void hostap_rx_tasklet(unsigned long data)
{
	local_info_t *local = (local_info_t *) data;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&local->rx_list)) != NULL)
		hostap_rx_skb(local, skb);
}


/* Called only from hardware IRQ */
static void prism2_alloc_ev(struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	int idx;
	u16 fid;

	fid = prism2_read_fid_reg(dev, HFA384X_ALLOCFID_OFF);

	PDEBUG(DEBUG_FID, "FID: interrupt: ALLOC - fid=0x%04x\n", fid);

	spin_lock(&local->txfidlock);
	idx = local->next_alloc;

	do {
		if (local->txfid[idx] == fid) {
			PDEBUG(DEBUG_FID, "FID: found matching txfid[%d]\n",
			       idx);

#ifndef final_version
			if (local->intransmitfid[idx] == PRISM2_TXFID_EMPTY)
				printk("Already released txfid found at idx "
				       "%d\n", idx);
			if (local->intransmitfid[idx] == PRISM2_TXFID_RESERVED)
				printk("Already reserved txfid found at idx "
				       "%d\n", idx);
#endif
			local->intransmitfid[idx] = PRISM2_TXFID_EMPTY;
			idx++;
			local->next_alloc = idx >= PRISM2_TXFID_COUNT ? 0 :
				idx;

			if (!test_bit(HOSTAP_BITS_TRANSMIT, &local->bits) &&
			    netif_queue_stopped(dev))
				hostap_netif_wake_queues(dev);

			spin_unlock(&local->txfidlock);
			return;
		}

		idx++;
		if (idx >= PRISM2_TXFID_COUNT)
			idx = 0;
	} while (idx != local->next_alloc);

	printk(KERN_WARNING "%s: could not find matching txfid (0x%04x, new "
	       "read 0x%04x) for alloc event\n", dev->name, fid,
	       HFA384X_INW(HFA384X_ALLOCFID_OFF));
	printk(KERN_DEBUG "TXFIDs:");
	for (idx = 0; idx < PRISM2_TXFID_COUNT; idx++)
		printk(" %04x[%04x]", local->txfid[idx],
		       local->intransmitfid[idx]);
	printk("\n");
	spin_unlock(&local->txfidlock);

	/* FIX: should probably schedule reset; reference to one txfid was lost
	 * completely.. Bad things will happen if we run out of txfids
	 * Actually, this will cause netdev watchdog to notice TX timeout and
	 * then card reset after all txfids have been leaked. */
}


/* Called only as a tasklet (software IRQ) */
static void hostap_tx_callback(local_info_t *local,
			       struct hfa384x_tx_frame *txdesc, int ok,
			       char *payload)
{
	u16 sw_support, hdrlen, len;
	struct sk_buff *skb;
	struct hostap_tx_callback_info *cb;

	/* Make sure that frame was from us. */
	if (memcmp(txdesc->addr2, local->dev->dev_addr, ETH_ALEN)) {
		printk(KERN_DEBUG "%s: TX callback - foreign frame\n",
		       local->dev->name);
		return;
	}

	sw_support = le16_to_cpu(txdesc->sw_support);

	spin_lock(&local->lock);
	cb = local->tx_callback;
	while (cb != NULL && cb->idx != sw_support)
		cb = cb->next;
	spin_unlock(&local->lock);

	if (cb == NULL) {
		printk(KERN_DEBUG "%s: could not find TX callback (idx %d)\n",
		       local->dev->name, sw_support);
		return;
	}

	hdrlen = hostap_80211_get_hdrlen(le16_to_cpu(txdesc->frame_control));
	len = le16_to_cpu(txdesc->data_len);
	skb = dev_alloc_skb(hdrlen + len);
	if (skb == NULL) {
		printk(KERN_DEBUG "%s: hostap_tx_callback failed to allocate "
		       "skb\n", local->dev->name);
		return;
	}

	memcpy(skb_put(skb, hdrlen), (void *) &txdesc->frame_control, hdrlen);
	if (payload)
		memcpy(skb_put(skb, len), payload, len);

	skb->dev = local->dev;
	skb->mac.raw = skb->data;

	cb->func(skb, ok, cb->data);
}


/* Called only as a tasklet (software IRQ) */
static int hostap_tx_compl_read(local_info_t *local, int error,
				struct hfa384x_tx_frame *txdesc,
				char **payload)
{
	u16 fid, len;
	int res, ret = 0;
	struct net_device *dev = local->dev;

	fid = prism2_read_fid_reg(dev, HFA384X_TXCOMPLFID_OFF);

	PDEBUG(DEBUG_FID, "interrupt: TX (err=%d) - fid=0x%04x\n", fid, error);

	spin_lock(&local->baplock);
	res = hfa384x_setup_bap(dev, BAP0, fid, 0);
	if (!res)
		res = hfa384x_from_bap(dev, BAP0, txdesc, sizeof(*txdesc));
	if (res) {
		PDEBUG(DEBUG_EXTRA, "%s: TX (err=%d) - fid=0x%04x - could not "
		       "read txdesc\n", dev->name, error, fid);
		if (res == -ETIMEDOUT) {
			PRISM2_SCHEDULE_TASK(&local->reset_queue);
		}
		ret = -1;
		goto fail;
	}
	if (txdesc->sw_support) {
		len = le16_to_cpu(txdesc->data_len);
		if (len < PRISM2_DATA_MAXLEN) {
			*payload = (char *) kmalloc(len, GFP_ATOMIC);
			if (*payload == NULL ||
			    hfa384x_from_bap(dev, BAP0, *payload, len)) {
				PDEBUG(DEBUG_EXTRA, "%s: could not read TX "
				       "frame payload\n", dev->name);
				kfree(*payload);
				*payload = NULL;
				ret = -1;
				goto fail;
			}
		}
	}

 fail:
	spin_unlock(&local->baplock);

	return ret;
}


/* Called only as a tasklet (software IRQ) */
static void prism2_tx_ev(local_info_t *local)
{
	struct net_device *dev = local->dev;
	char *payload = NULL;
	struct hfa384x_tx_frame txdesc;

	if (hostap_tx_compl_read(local, 0, &txdesc, &payload))
		goto fail;

	if (local->frame_dump & PRISM2_DUMP_TX_HDR) {
		PDEBUG(DEBUG_EXTRA, "%s: TX - status=0x%04x "
		       "retry_count=%d tx_rate=%d seq_ctrl=%d "
		       "duration_id=%d\n",
		       dev->name, le16_to_cpu(txdesc.status),
		       txdesc.retry_count, txdesc.tx_rate,
		       le16_to_cpu(txdesc.seq_ctrl),
		       le16_to_cpu(txdesc.duration_id));
	}

	if (txdesc.sw_support)
		hostap_tx_callback(local, &txdesc, 1, payload);
	kfree(payload);

 fail:
	HFA384X_OUTW(HFA384X_EV_TX, HFA384X_EVACK_OFF);
}


/* Called only as a tasklet (software IRQ) */
static void hostap_sta_tx_exc_tasklet(unsigned long data)
{
	local_info_t *local = (local_info_t *) data;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&local->sta_tx_exc_list)) != NULL) {
		struct hfa384x_tx_frame *txdesc =
			(struct hfa384x_tx_frame *) skb->data;
		hostap_handle_sta_tx_exc(local, txdesc);
		dev_kfree_skb(skb);
	}
}


/* Called only as a tasklet (software IRQ) */
static void prism2_txexc(local_info_t *local)
{
	struct net_device *dev = local->dev;
	u16 status, fc;
	int show_dump, res;
	char *payload = NULL;
	struct hfa384x_tx_frame txdesc;

	show_dump = local->frame_dump & PRISM2_DUMP_TXEXC_HDR;
	local->stats.tx_errors++;

	res = hostap_tx_compl_read(local, 1, &txdesc, &payload);
	HFA384X_OUTW(HFA384X_EV_TXEXC, HFA384X_EVACK_OFF);
	if (res)
		return;

	status = le16_to_cpu(txdesc.status);

#if WIRELESS_EXT > 13
	/* We produce a TXDROP event only for retry or lifetime
	 * exceeded, because that's the only status that really mean
	 * that this particular node went away.
	 * Other errors means that *we* screwed up. - Jean II */
	if (status & (HFA384X_TX_STATUS_RETRYERR | HFA384X_TX_STATUS_AGEDERR))
	{
		union iwreq_data wrqu;

		/* Copy 802.11 dest address. */
		memcpy(wrqu.addr.sa_data, txdesc.addr1, ETH_ALEN);
		wrqu.addr.sa_family = ARPHRD_ETHER;
		wireless_send_event(dev, IWEVTXDROP, &wrqu, NULL);
	} else
		show_dump = 1;
#endif /* WIRELESS_EXT > 13 */

	if (local->iw_mode == IW_MODE_MASTER ||
	    local->iw_mode == IW_MODE_REPEAT ||
	    local->wds_type & HOSTAP_WDS_AP_CLIENT) {
		struct sk_buff *skb;
		skb = dev_alloc_skb(sizeof(txdesc));
		if (skb) {
			memcpy(skb_put(skb, sizeof(txdesc)), &txdesc,
			       sizeof(txdesc));
			skb_queue_tail(&local->sta_tx_exc_list, skb);
			tasklet_schedule(&local->sta_tx_exc_tasklet);
		}
	}

	if (txdesc.sw_support)
		hostap_tx_callback(local, &txdesc, 0, payload);
	kfree(payload);

	if (!show_dump)
		return;

	PDEBUG(DEBUG_EXTRA, "%s: TXEXC - status=0x%04x (%s%s%s%s)"
	       " tx_control=%04x\n",
	       dev->name, status,
	       status & HFA384X_TX_STATUS_RETRYERR ? "[RetryErr]" : "",
	       status & HFA384X_TX_STATUS_AGEDERR ? "[AgedErr]" : "",
	       status & HFA384X_TX_STATUS_DISCON ? "[Discon]" : "",
	       status & HFA384X_TX_STATUS_FORMERR ? "[FormErr]" : "",
	       le16_to_cpu(txdesc.tx_control));

	fc = le16_to_cpu(txdesc.frame_control);
	PDEBUG(DEBUG_EXTRA, "   retry_count=%d tx_rate=%d fc=0x%04x "
	       "(%s%s%s::%d%s%s)\n",
	       txdesc.retry_count, txdesc.tx_rate, fc,
	       WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT ? "Mgmt" : "",
	       WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_CTRL ? "Ctrl" : "",
	       WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_DATA ? "Data" : "",
	       WLAN_FC_GET_STYPE(fc),
	       fc & WLAN_FC_TODS ? " ToDS" : "",
	       fc & WLAN_FC_FROMDS ? " FromDS" : "");
	PDEBUG(DEBUG_EXTRA, "   A1=" MACSTR " A2=" MACSTR " A3="
	       MACSTR " A4=" MACSTR "\n",
	       MAC2STR(txdesc.addr1), MAC2STR(txdesc.addr2),
	       MAC2STR(txdesc.addr3), MAC2STR(txdesc.addr4));
}


/* Called only as a tasklet (software IRQ) */
static void hostap_info_tasklet(unsigned long data)
{
	local_info_t *local = (local_info_t *) data;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&local->info_list)) != NULL) {
		hostap_info_process(local, skb);
		dev_kfree_skb(skb);
	}
}


/* Called only as a tasklet (software IRQ) */
static void prism2_info(local_info_t *local)
{
	struct net_device *dev = local->dev;
	u16 fid;
	int res, left;
	struct hfa384x_info_frame info;
	struct sk_buff *skb;

	fid = HFA384X_INW(HFA384X_INFOFID_OFF);

	spin_lock(&local->baplock);
	res = hfa384x_setup_bap(dev, BAP0, fid, 0);
	if (!res)
		res = hfa384x_from_bap(dev, BAP0, &info, sizeof(info));
	if (res) {
		spin_unlock(&local->baplock);
		printk(KERN_DEBUG "Could not get info frame (fid=0x%04x)\n",
		       fid);
		if (res == -ETIMEDOUT) {
			PRISM2_SCHEDULE_TASK(&local->reset_queue);
		}
		goto out;
	}

	le16_to_cpus(&info.len);
	le16_to_cpus(&info.type);
	left = (info.len - 1) * 2;

	if (info.len & 0x8000 || info.len == 0 || left > 2060) {
		/* data register seems to give 0x8000 in some error cases even
		 * though busy bit is not set in offset register;
		 * in addition, length must be at least 1 due to type field */
		spin_unlock(&local->baplock);
		printk(KERN_DEBUG "%s: Received info frame with invalid "
		       "length 0x%04x (type 0x%04x)\n", dev->name, info.len,
		       info.type);
		goto out;
	}

	skb = dev_alloc_skb(sizeof(info) + left);
	if (skb == NULL) {
		spin_unlock(&local->baplock);
		printk(KERN_DEBUG "%s: Could not allocate skb for info "
		       "frame\n", dev->name);
		goto out;
	}

	memcpy(skb_put(skb, sizeof(info)), &info, sizeof(info));
	if (left > 0 && hfa384x_from_bap(dev, BAP0, skb_put(skb, left), left))
	{
		spin_unlock(&local->baplock);
		printk(KERN_WARNING "%s: Info frame read failed (fid=0x%04x, "
		       "len=0x%04x, type=0x%04x\n",
		       dev->name, fid, info.len, info.type);
		dev_kfree_skb(skb);
		goto out;
	}
	spin_unlock(&local->baplock);

	skb_queue_tail(&local->info_list, skb);
	tasklet_schedule(&local->info_tasklet);

 out:
	HFA384X_OUTW(HFA384X_EV_INFO, HFA384X_EVACK_OFF);
}


/* Called only as a tasklet (software IRQ) */
static void hostap_bap_tasklet(unsigned long data)
{
	local_info_t *local = (local_info_t *) data;
	struct net_device *dev = local->dev;
	u16 ev;
	int frames = 30;

	if (local->func->card_present && !local->func->card_present(local))
		return;

	set_bit(HOSTAP_BITS_BAP_TASKLET, &local->bits);

	/* Process all pending BAP events without generating new interrupts
	 * for them */
	while (frames-- > 0) {
		ev = HFA384X_INW(HFA384X_EVSTAT_OFF);
		if (ev == 0xffff || !(ev & HFA384X_BAP0_EVENTS))
			break;
		if (ev & HFA384X_EV_RX)
			prism2_rx(local);
		if (ev & HFA384X_EV_INFO)
			prism2_info(local);
		if (ev & HFA384X_EV_TX)
			prism2_tx_ev(local);
		if (ev & HFA384X_EV_TXEXC)
			prism2_txexc(local);
	}

	set_bit(HOSTAP_BITS_BAP_TASKLET2, &local->bits);
	clear_bit(HOSTAP_BITS_BAP_TASKLET, &local->bits);

	/* Enable interrupts for new BAP events */
	hfa384x_events_all(dev);
	clear_bit(HOSTAP_BITS_BAP_TASKLET2, &local->bits);
}


#if defined(PRISM2_PCI) && defined(PRISM2_BUS_MASTER)
/* Called only from hardware IRQ */
static void prism2_bus_master_ev(struct net_device *dev, int bap)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	if (bap == BAP1) {
		/* FIX: frame payload was DMA'd to skb->data; might need to
		 * invalidate data cache for that memory area */
		skb_queue_tail(&local->rx_list, local->rx_skb);
		tasklet_schedule(&local->rx_tasklet);
		HFA384X_OUTW(HFA384X_EV_RX, HFA384X_EVACK_OFF);
	} else {
		if (prism2_transmit(dev, local->bus_m0_tx_idx)) {
			printk(KERN_DEBUG "%s: prism2_transmit() failed "
			       "when called from bus master event\n",
			       dev->name);
			local->intransmitfid[local->bus_m0_tx_idx] =
				PRISM2_TXFID_EMPTY;
			PRISM2_SCHEDULE_TASK(&local->reset_queue);
		}
	}
}
#endif /* PRISM2_PCI and PRISM2_BUS_MASTER */


/* Called only from hardware IRQ */
static void prism2_infdrop(struct net_device *dev)
{
	static unsigned long last_inquire = 0;

	PDEBUG(DEBUG_EXTRA, "%s: INFDROP event\n", dev->name);

	/* some firmware versions seem to get stuck with
	 * full CommTallies in high traffic load cases; every
	 * packet will then cause INFDROP event and CommTallies
	 * info frame will not be sent automatically. Try to
	 * get out of this state by inquiring CommTallies. */
	if (!last_inquire || time_after(jiffies, last_inquire + HZ)) {
		hfa384x_cmd_callback(dev, HFA384X_CMDCODE_INQUIRE,
				     HFA384X_INFO_COMMTALLIES, NULL, NULL);
		last_inquire = jiffies;
	}
}


/* Called only from hardware IRQ */
static void prism2_ev_tick(struct net_device *dev)
{
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	u16 evstat, inten;
	static int prev_stuck = 0;

	if (time_after(jiffies, local->last_tick_timer + 5 * HZ) &&
	    local->last_tick_timer) {
		evstat = HFA384X_INW(HFA384X_EVSTAT_OFF);
		inten = HFA384X_INW(HFA384X_INTEN_OFF);
		if (!prev_stuck) {
			printk(KERN_INFO "%s: SW TICK stuck? "
			       "bits=0x%lx EvStat=%04x IntEn=%04x\n",
			       dev->name, local->bits, evstat, inten);
		}
		local->sw_tick_stuck++;
		if ((evstat & HFA384X_BAP0_EVENTS) &&
		    (inten & HFA384X_BAP0_EVENTS)) {
			printk(KERN_INFO "%s: trying to recover from IRQ "
			       "hang\n", dev->name);
			hfa384x_events_no_bap0(dev);
		}
		prev_stuck = 1;
	} else
		prev_stuck = 0;
}


/* Called only from hardware IRQ */
static inline void prism2_check_magic(local_info_t *local)
{
	/* at least PCI Prism2.5 with bus mastering seems to sometimes
	 * return 0x0000 in SWSUPPORT0 for unknown reason, but re-reading the
	 * register once or twice seems to get the correct value.. PCI cards
	 * cannot anyway be removed during normal operation, so there is not
	 * really any need for this verification with them. */

#ifndef PRISM2_PCI
#ifndef final_version
	static unsigned long last_magic_err = 0;
	struct net_device *dev = local->dev;

	if (HFA384X_INW(HFA384X_SWSUPPORT0_OFF) != HFA384X_MAGIC) {
		if (!local->hw_ready)
			return;
		HFA384X_OUTW(0xffff, HFA384X_EVACK_OFF);
		if (time_after(jiffies, last_magic_err + 10 * HZ)) {
			printk("%s: Interrupt, but SWSUPPORT0 does not match: "
			       "%04X != %04X - card removed?\n", dev->name,
			       HFA384X_INW(HFA384X_SWSUPPORT0_OFF),
			       HFA384X_MAGIC);
			last_magic_err = jiffies;
		} else if (net_ratelimit()) {
			printk(KERN_DEBUG "%s: interrupt - SWSUPPORT0=%04x "
			       "MAGIC=%04x\n", dev->name,
			       HFA384X_INW(HFA384X_SWSUPPORT0_OFF),
			       HFA384X_MAGIC);
		}
		if (HFA384X_INW(HFA384X_SWSUPPORT0_OFF) != 0xffff)
			PRISM2_SCHEDULE_TASK(&local->reset_queue);
		return;
	}
#endif /* final_version */
#endif /* !PRISM2_PCI */
}


/* Called only from hardware IRQ */
static irqreturn_t prism2_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	struct net_device *dev = (struct net_device *) dev_id;
	struct hostap_interface *iface = dev->priv;
	local_info_t *local = iface->local;
	int events = 0;
	u16 ev;

	prism2_io_debug_add(dev, PRISM2_IO_DEBUG_CMD_INTERRUPT, 0, 0);

	if (local->func->card_present && !local->func->card_present(local)) {
		printk(KERN_DEBUG "%s: Interrupt, but dev not OK\n",
		       dev->name);
		return IRQ_HANDLED;
	}

	prism2_check_magic(local);

	for (;;) {
		ev = HFA384X_INW(HFA384X_EVSTAT_OFF);
		if (ev == 0xffff) {
			if (local->shutdown)
				return IRQ_HANDLED;
			HFA384X_OUTW(0xffff, HFA384X_EVACK_OFF);
			printk(KERN_DEBUG "%s: prism2_interrupt: ev=0xffff\n",
			       dev->name);
			return IRQ_HANDLED;
		}

		ev &= HFA384X_INW(HFA384X_INTEN_OFF);
		if (ev == 0)
			break;

		if (ev & HFA384X_EV_CMD) {
			prism2_cmd_ev(dev);
		}

		/* Above events are needed even before hw is ready, but other
		 * events should be skipped during initialization. This may
		 * change for AllocEv if allocate_fid is implemented without
		 * busy waiting. */
		if (!local->hw_ready || local->hw_resetting ||
		    !local->dev_enabled) {
			ev = HFA384X_INW(HFA384X_EVSTAT_OFF);
			if (ev & HFA384X_EV_CMD)
				goto next_event;
			if ((ev & HFA384X_EVENT_MASK) == 0)
				return IRQ_HANDLED;
			if (local->dev_enabled && (ev & ~HFA384X_EV_TICK) &&
			    net_ratelimit()) {
				printk(KERN_DEBUG "%s: prism2_interrupt: hw "
				       "not ready; skipping events 0x%04x "
				       "(IntEn=0x%04x)%s%s%s\n",
				       dev->name, ev,
				       HFA384X_INW(HFA384X_INTEN_OFF),
				       !local->hw_ready ? " (!hw_ready)" : "",
				       local->hw_resetting ?
				       " (hw_resetting)" : "",
				       !local->dev_enabled ?
				       " (!dev_enabled)" : "");
			}
			HFA384X_OUTW(ev, HFA384X_EVACK_OFF);
			return IRQ_HANDLED;
		}

		if (ev & HFA384X_EV_TICK) {
			prism2_ev_tick(dev);
			HFA384X_OUTW(HFA384X_EV_TICK, HFA384X_EVACK_OFF);
		}

#if defined(PRISM2_PCI) && defined(PRISM2_BUS_MASTER)
		if (ev & HFA384X_EV_PCI_M0) {
			prism2_bus_master_ev(dev, BAP0);
			HFA384X_OUTW(HFA384X_EV_PCI_M0, HFA384X_EVACK_OFF);
		}

		if (ev & HFA384X_EV_PCI_M1) {
			/* previous RX has been copied can be ACKed now */
			HFA384X_OUTW(HFA384X_EV_RX, HFA384X_EVACK_OFF);

			prism2_bus_master_ev(dev, BAP1);
			HFA384X_OUTW(HFA384X_EV_PCI_M1, HFA384X_EVACK_OFF);
		}
#endif /* PRISM2_PCI and PRISM2_BUS_MASTER */

		if (ev & HFA384X_EV_ALLOC) {
			prism2_alloc_ev(dev);
			HFA384X_OUTW(HFA384X_EV_ALLOC, HFA384X_EVACK_OFF);
		}

		/* Reading data from the card is quite time consuming, so do it
		 * in tasklets. TX, TXEXC, RX, and INFO events will be ACKed
		 * and unmasked after needed data has been read completely. */
		if (ev & HFA384X_BAP0_EVENTS) {
			hfa384x_events_no_bap0(dev);
			tasklet_schedule(&local->bap_tasklet);
		}

#ifndef final_version
		if (ev & HFA384X_EV_WTERR) {
			PDEBUG(DEBUG_EXTRA, "%s: WTERR event\n", dev->name);
			HFA384X_OUTW(HFA384X_EV_WTERR, HFA384X_EVACK_OFF);
		}
#endif /* final_version */

		if (ev & HFA384X_EV_INFDROP) {
			prism2_infdrop(dev);
			HFA384X_OUTW(HFA384X_EV_INFDROP, HFA384X_EVACK_OFF);
		}

	next_event:
		events++;
		if (events >= PRISM2_MAX_INTERRUPT_EVENTS) {
			PDEBUG(DEBUG_EXTRA, "prism2_interrupt: >%d events "
			       "(EvStat=0x%04x)\n",
			       PRISM2_MAX_INTERRUPT_EVENTS,
			       HFA384X_INW(HFA384X_EVSTAT_OFF));
			break;
		}
	}
	prism2_io_debug_add(dev, PRISM2_IO_DEBUG_CMD_INTERRUPT, 0, 1);
	return IRQ_RETVAL(events);
}


static void prism2_check_sta_fw_version(local_info_t *local)
{
	struct hfa384x_comp_ident comp;
	int id, variant, major, minor;

	if (hfa384x_get_rid(local->dev, HFA384X_RID_STAID,
			    &comp, sizeof(comp), 1) < 0)
		return;

	local->fw_ap = 0;
	id = le16_to_cpu(comp.id);
	if (id != HFA384X_COMP_ID_STA) {
		if (id == HFA384X_COMP_ID_FW_AP)
			local->fw_ap = 1;
		return;
	}

	major = __le16_to_cpu(comp.major);
	minor = __le16_to_cpu(comp.minor);
	variant = __le16_to_cpu(comp.variant);
	local->sta_fw_ver = PRISM2_FW_VER(major, minor, variant);

	/* Station firmware versions before 1.4.x seem to have a bug in
	 * firmware-based WEP encryption when using Host AP mode, so use
	 * host_encrypt as a default for them. Firmware version 1.4.9 is the
	 * first one that has been seen to produce correct encryption, but the
	 * bug might be fixed before that (although, at least 1.4.2 is broken).
	 */
	local->fw_encrypt_ok = local->sta_fw_ver >= PRISM2_FW_VER(1,4,9);

	if (local->iw_mode == IW_MODE_MASTER && !local->host_encrypt &&
	    !local->fw_encrypt_ok) {
		printk(KERN_DEBUG "%s: defaulting to host-based encryption as "
		       "a workaround for firmware bug in Host AP mode WEP\n",
		       local->dev->name);
		local->host_encrypt = 1;
	}

	/* IEEE 802.11 standard compliant WDS frames (4 addresses) were broken
	 * in station firmware versions before 1.5.x. With these versions, the
	 * driver uses a workaround with bogus frame format (4th address after
	 * the payload). This is not compatible with other AP devices. Since
	 * the firmware bug is fixed in the latest station firmware versions,
	 * automatically enable standard compliant mode for cards using station
	 * firmware version 1.5.0 or newer. */
	if (local->sta_fw_ver >= PRISM2_FW_VER(1,5,0))
		local->wds_type |= HOSTAP_WDS_STANDARD_FRAME;
	else {
		printk(KERN_DEBUG "%s: defaulting to bogus WDS frame as a "
		       "workaround for firmware bug in Host AP mode WDS\n",
		       local->dev->name);
	}

	hostap_check_sta_fw_version(local->ap, local->sta_fw_ver);
}


static void prism2_crypt_deinit_entries(local_info_t *local, int force)
{
	struct list_head *ptr, *n;
	struct prism2_crypt_data *entry;

	for (ptr = local->crypt_deinit_list.next, n = ptr->next;
	     ptr != &local->crypt_deinit_list; ptr = n, n = ptr->next) {
		entry = list_entry(ptr, struct prism2_crypt_data, list);

		if (atomic_read(&entry->refcnt) != 0 && !force)
			continue;

		list_del(ptr);

		if (entry->ops)
			entry->ops->deinit(entry->priv);
		kfree(entry);
	}
}


static void prism2_crypt_deinit_handler(unsigned long data)
{
	local_info_t *local = (local_info_t *) data;
	unsigned long flags;

	spin_lock_irqsave(&local->lock, flags);
	prism2_crypt_deinit_entries(local, 0);
	if (!list_empty(&local->crypt_deinit_list)) {
		printk(KERN_DEBUG "%s: entries remaining in delayed crypt "
		       "deletion list\n", local->dev->name);
		local->crypt_deinit_timer.expires = jiffies + HZ;
		add_timer(&local->crypt_deinit_timer);
	}
	spin_unlock_irqrestore(&local->lock, flags);

}


static void hostap_passive_scan(unsigned long data)
{
	local_info_t *local = (local_info_t *) data;
	struct net_device *dev = local->dev;
	u16 channel;

	if (local->passive_scan_interval <= 0)
		return;

	if (local->passive_scan_state == PASSIVE_SCAN_LISTEN) {
		int max_tries = 16;

		/* Even though host system does not really know when the WLAN
		 * MAC is sending frames, try to avoid changing channels for
		 * passive scanning when a host-generated frame is being
		 * transmitted */
		if (test_bit(HOSTAP_BITS_TRANSMIT, &local->bits)) {
			printk(KERN_DEBUG "%s: passive scan detected pending "
			       "TX - delaying\n", dev->name);
			local->passive_scan_timer.expires = jiffies + HZ / 10;
			add_timer(&local->passive_scan_timer);
			return;
		}

		do {
			local->passive_scan_channel++;
			if (local->passive_scan_channel > 14)
				local->passive_scan_channel = 1;
			max_tries--;
		} while (!(local->channel_mask &
			   (1 << (local->passive_scan_channel - 1))) &&
			 max_tries > 0);

		if (max_tries == 0) {
			printk(KERN_INFO "%s: no allowed passive scan channels"
			       " found\n", dev->name);
			return;
		}

		printk(KERN_DEBUG "%s: passive scan channel %d\n",
		       dev->name, local->passive_scan_channel);
		channel = local->passive_scan_channel;
		local->passive_scan_state = PASSIVE_SCAN_WAIT;
		local->passive_scan_timer.expires = jiffies + HZ / 10;
	} else {
		channel = local->channel;
		local->passive_scan_state = PASSIVE_SCAN_LISTEN;
		local->passive_scan_timer.expires = jiffies +
			local->passive_scan_interval * HZ;
	}

	if (hfa384x_cmd_callback(dev, HFA384X_CMDCODE_TEST |
				 (HFA384X_TEST_CHANGE_CHANNEL << 8),
				 channel, NULL, NULL))
		printk(KERN_ERR "%s: passive scan channel set %d "
		       "failed\n", dev->name, channel);

	add_timer(&local->passive_scan_timer);
}


/* Software watchdog - called as a timer. Hardware interrupt (Tick event) is
 * used to monitor that local->last_tick_timer is being updated. If not,
 * interrupt busy-loop is assumed and driver tries to recover by masking out
 * some events. */
static void hostap_tick_timer(unsigned long data)
{
	static unsigned long last_inquire = 0;
	local_info_t *local = (local_info_t *) data;
	local->last_tick_timer = jiffies;

	/* Inquire CommTallies every 10 seconds to keep the statistics updated
	 * more often during low load and when using 32-bit tallies. */
	if ((!last_inquire || time_after(jiffies, last_inquire + 10 * HZ)) &&
	    !local->hw_downloading && local->hw_ready &&
	    !local->hw_resetting && local->dev_enabled) {
		hfa384x_cmd_callback(local->dev, HFA384X_CMDCODE_INQUIRE,
				     HFA384X_INFO_COMMTALLIES, NULL, NULL);
		last_inquire = jiffies;
	}

	local->tick_timer.expires = jiffies + 2 * HZ;
	add_timer(&local->tick_timer);
}


#ifndef PRISM2_NO_PROCFS_DEBUG
static int prism2_registers_proc_read(char *page, char **start, off_t off,
				      int count, int *eof, void *data)
{
	char *p = page;
	local_info_t *local = (local_info_t *) data;

	if (off != 0) {
		*eof = 1;
		return 0;
	}

#define SHOW_REG(n) \
p += sprintf(p, #n "=%04x\n", hfa384x_read_reg(local->dev, HFA384X_##n##_OFF))

	SHOW_REG(CMD);
	SHOW_REG(PARAM0);
	SHOW_REG(PARAM1);
	SHOW_REG(PARAM2);
	SHOW_REG(STATUS);
	SHOW_REG(RESP0);
	SHOW_REG(RESP1);
	SHOW_REG(RESP2);
	SHOW_REG(INFOFID);
	SHOW_REG(CONTROL);
	SHOW_REG(SELECT0);
	SHOW_REG(SELECT1);
	SHOW_REG(OFFSET0);
	SHOW_REG(OFFSET1);
	SHOW_REG(RXFID);
	SHOW_REG(ALLOCFID);
	SHOW_REG(TXCOMPLFID);
	SHOW_REG(SWSUPPORT0);
	SHOW_REG(SWSUPPORT1);
	SHOW_REG(SWSUPPORT2);
	SHOW_REG(EVSTAT);
	SHOW_REG(INTEN);
	SHOW_REG(EVACK);
	/* Do not read data registers, because they change the state of the
	 * MAC (offset += 2) */
	/* SHOW_REG(DATA0); */
	/* SHOW_REG(DATA1); */
	SHOW_REG(AUXPAGE);
	SHOW_REG(AUXOFFSET);
	/* SHOW_REG(AUXDATA); */
#ifdef PRISM2_PCI
	SHOW_REG(PCICOR);
	SHOW_REG(PCIHCR);
	SHOW_REG(PCI_M0_ADDRH);
	SHOW_REG(PCI_M0_ADDRL);
	SHOW_REG(PCI_M0_LEN);
	SHOW_REG(PCI_M0_CTL);
	SHOW_REG(PCI_STATUS);
	SHOW_REG(PCI_M1_ADDRH);
	SHOW_REG(PCI_M1_ADDRL);
	SHOW_REG(PCI_M1_LEN);
	SHOW_REG(PCI_M1_CTL);
#endif /* PRISM2_PCI */

	return (p - page);
}
#endif /* PRISM2_NO_PROCFS_DEBUG */


static struct net_device *
prism2_init_local_data(struct prism2_helper_functions *funcs, int card_idx)
{
	struct net_device *dev;
	struct hostap_interface *iface;
	struct local_info *local;
	int len, i;

	if (funcs == NULL)
		return NULL;

	len = sizeof(struct hostap_interface) +
		3 + sizeof(struct local_info) +
		3 + sizeof(struct ap_data);

	dev = alloc_etherdev(len);
	if (dev == NULL)
		return NULL;

	iface = dev->priv;
	local = (struct local_info *) ((((long) (iface + 1)) + 3) & ~3);
	local->ap = (struct ap_data *) ((((long) (local + 1)) + 3) & ~3);
	local->dev = iface->dev = dev;
	iface->local = local;
	iface->type = HOSTAP_INTERFACE_MAIN;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0))
	dev->name = iface->name;
#endif
	INIT_LIST_HEAD(&local->hostap_interfaces);
	list_add(&iface->list, &local->hostap_interfaces);

	local->hw_module = THIS_MODULE;

#ifdef PRISM2_IO_DEBUG
	local->io_debug_enabled = 1;
#endif /* PRISM2_IO_DEBUG */

#if defined(PRISM2_PCI) && defined(PRISM2_BUS_MASTER)
	local->bus_m0_buf = (u8 *) kmalloc(sizeof(struct hfa384x_tx_frame) +
					   PRISM2_DATA_MAXLEN, GFP_DMA);
	if (local->bus_m0_buf == NULL)
		goto fail;
#endif /* PRISM2_PCI and PRISM2_BUS_MASTER */

	local->func = funcs;
	local->func->cmd = hfa384x_cmd;
	local->func->read_regs = hfa384x_read_regs;
	local->func->get_rid = hfa384x_get_rid;
	local->func->set_rid = hfa384x_set_rid;
	local->func->hw_enable = prism2_hw_enable;
	local->func->hw_config = prism2_hw_config;
	local->func->hw_reset = prism2_hw_reset;
	local->func->hw_shutdown = prism2_hw_shutdown;
	local->func->reset_port = prism2_reset_port;
	local->func->tx = prism2_tx;
	local->func->schedule_reset = prism2_schedule_reset;
#ifdef PRISM2_DOWNLOAD_SUPPORT
	local->func->download = prism2_download;
#endif /* PRISM2_DOWNLOAD_SUPPORT */
	local->func->tx_80211 = prism2_tx_80211;

	local->disable_on_close = disable_on_close;
	local->mtu = mtu;

	rwlock_init(&local->iface_lock);
	spin_lock_init(&local->txfidlock);
	spin_lock_init(&local->cmdlock);
	spin_lock_init(&local->baplock);
	spin_lock_init(&local->lock);
	init_MUTEX(&local->rid_bap_sem);

	if (card_idx < 0 || card_idx >= MAX_PARM_DEVICES)
		card_idx = 0;
	local->card_idx = card_idx;

	i = essid[card_idx] == NULL ? 0 : card_idx;
	len = strlen(essid[i]);
	memcpy(local->essid, essid[i],
	       len > MAX_SSID_LEN ? MAX_SSID_LEN : len);
	local->essid[MAX_SSID_LEN] = '\0';
	i = GET_INT_PARM(iw_mode, card_idx);
	if ((i >= IW_MODE_ADHOC && i <= IW_MODE_REPEAT) ||
	    i == IW_MODE_MONITOR) {
		local->iw_mode = i;
	} else {
		printk(KERN_WARNING "prism2: Unknown iw_mode %d; using "
		       "IW_MODE_MASTER\n", i);
		local->iw_mode = IW_MODE_MASTER;
	}
	local->channel = GET_INT_PARM(channel, card_idx);
	local->beacon_int = GET_INT_PARM(beacon_int, card_idx);
	local->dtim_period = GET_INT_PARM(dtim_period, card_idx);
	local->wds_max_connections = 16;
	local->tx_control = HFA384X_TX_CTRL_FLAGS;
	local->manual_retry_count = -1;
	local->rts_threshold = 2347;
	local->fragm_threshold = 2346;
	local->auth_algs = PRISM2_AUTH_OPEN | PRISM2_AUTH_SHARED_KEY;
#if defined(PRISM2_PCI) && defined(PRISM2_BUS_MASTER)
	local->bus_master_threshold_rx = GET_INT_PARM(bus_master_threshold_rx,
						      card_idx);
	local->bus_master_threshold_tx = GET_INT_PARM(bus_master_threshold_tx,
						      card_idx);
#endif /* PRISM2_PCI and PRISM2_BUS_MASTER */

	/* Initialize task queue structures */
	INIT_WORK(&local->reset_queue, handle_reset_queue, local);
	INIT_WORK(&local->set_multicast_list_queue,
		  hostap_set_multicast_list_queue, local->dev);

	/* Initialize tasklets for handling hardware IRQ related operations
	 * outside hw IRQ handler */
	HOSTAP_TASKLET_INIT(&local->bap_tasklet, hostap_bap_tasklet,
			    (unsigned long) local);

	HOSTAP_TASKLET_INIT(&local->info_tasklet, hostap_info_tasklet,
			    (unsigned long) local);
	hostap_info_init(local);

	HOSTAP_TASKLET_INIT(&local->rx_tasklet,
			    hostap_rx_tasklet, (unsigned long) local);
	skb_queue_head_init(&local->rx_list);

	HOSTAP_TASKLET_INIT(&local->sta_tx_exc_tasklet,
			    hostap_sta_tx_exc_tasklet, (unsigned long) local);
	skb_queue_head_init(&local->sta_tx_exc_list);

	INIT_LIST_HEAD(&local->cmd_queue);
	init_waitqueue_head(&local->hostscan_wq);
	INIT_LIST_HEAD(&local->crypt_deinit_list);
	init_timer(&local->crypt_deinit_timer);
	local->crypt_deinit_timer.data = (unsigned long) local;
	local->crypt_deinit_timer.function = prism2_crypt_deinit_handler;

	init_timer(&local->passive_scan_timer);
	local->passive_scan_timer.data = (unsigned long) local;
	local->passive_scan_timer.function = hostap_passive_scan;

	init_timer(&local->tick_timer);
	local->tick_timer.data = (unsigned long) local;
	local->tick_timer.function = hostap_tick_timer;
	local->tick_timer.expires = jiffies + 2 * HZ;
	add_timer(&local->tick_timer);

	hostap_setup_dev(dev, local, 1);

	local->saved_eth_header_parse = dev->hard_header_parse;

	return dev;

#if defined(PRISM2_PCI) && defined(PRISM2_BUS_MASTER)
 fail:
	kfree(local->bus_m0_buf);
	free_netdev(dev);
	return NULL;
#endif /* PRISM2_PCI and PRISM2_BUS_MASTER */
}


static int prism2_init_dev(local_info_t *local)
{
	struct net_device *dev = local->dev;
	int len, ret;

	len = strlen(dev_template);
	if (len >= IFNAMSIZ || strstr(dev_template, "%d") == NULL) {
		printk(KERN_WARNING "hostap: Invalid dev_template='%s'\n",
		       dev_template);
		return 1;
	}

	rtnl_lock();
	ret = dev_alloc_name(dev, dev_template);
	if (ret >= 0)
		ret = register_netdevice(dev);
	rtnl_unlock();
	if (ret < 0) {
		printk(KERN_WARNING "%s: register netdevice failed!\n",
		       dev_info);
		return 1;
	}
	printk(KERN_INFO "%s: Registered netdevice %s\n", dev_info, dev->name);

	hostap_init_proc(local);
#ifndef PRISM2_NO_PROCFS_DEBUG
	create_proc_read_entry("registers", 0, local->proc,
			       prism2_registers_proc_read, local);
#endif /* PRISM2_NO_PROCFS_DEBUG */
	hostap_init_data(local);

	return 0;
}


static void prism2_free_local_data(struct net_device *dev)
{
	struct hostap_tx_callback_info *tx_cb, *tx_cb_prev;
	int i;
	struct sk_buff *skb;
	struct hostap_interface *iface;
	struct local_info *local;
	struct list_head *ptr, *n;

	if (dev == NULL)
		return;

	iface = dev->priv;
	local = iface->local;

	flush_scheduled_work();

	if (timer_pending(&local->crypt_deinit_timer))
		del_timer(&local->crypt_deinit_timer);
	prism2_crypt_deinit_entries(local, 1);

	if (timer_pending(&local->passive_scan_timer))
		del_timer(&local->passive_scan_timer);

	if (timer_pending(&local->tick_timer))
		del_timer(&local->tick_timer);

	prism2_clear_cmd_queue(local);

	while ((skb = skb_dequeue(&local->info_list)) != NULL)
		dev_kfree_skb(skb);

	while ((skb = skb_dequeue(&local->rx_list)) != NULL)
		dev_kfree_skb(skb);

	while ((skb = skb_dequeue(&local->sta_tx_exc_list)) != NULL)
		dev_kfree_skb(skb);

	if (local->dev_enabled)
		prism2_callback(local, PRISM2_CALLBACK_DISABLE);

	if (local->crypt) {
		if (local->crypt->ops)
			local->crypt->ops->deinit(local->crypt->priv);
		kfree(local->crypt);
		local->crypt = NULL;
	}

	if (local->ap != NULL)
		hostap_free_data(local->ap);

#ifndef PRISM2_NO_PROCFS_DEBUG
	if (local->proc != NULL)
		remove_proc_entry("registers", local->proc);
#endif /* PRISM2_NO_PROCFS_DEBUG */
	hostap_remove_proc(local);

	tx_cb = local->tx_callback;
	while (tx_cb != NULL) {
		tx_cb_prev = tx_cb;
		tx_cb = tx_cb->next;
		kfree(tx_cb_prev);
	}

	hostap_set_hostapd(local, 0, 0);

	for (i = 0; i < PRISM2_FRAG_CACHE_LEN; i++) {
		if (local->frag_cache[i].skb != NULL)
			dev_kfree_skb(local->frag_cache[i].skb);
	}

#ifdef PRISM2_DOWNLOAD_SUPPORT
	prism2_download_free_data(local->dl_pri);
	prism2_download_free_data(local->dl_sec);
#endif /* PRISM2_DOWNLOAD_SUPPORT */

	list_for_each_safe(ptr, n, &local->hostap_interfaces) {
		iface = list_entry(ptr, struct hostap_interface, list);
		if (iface->type == HOSTAP_INTERFACE_MAIN) {
			/* special handling for this interface below */
			continue;
		}
		hostap_remove_interface(iface->dev, 0, 1);
	}

#if defined(PRISM2_PCI) && defined(PRISM2_BUS_MASTER)
	kfree(local->bus_m0_buf);
#endif /* PRISM2_PCI and PRISM2_BUS_MASTER */
	kfree(local->pda);
	kfree(local->last_scan_results);

	unregister_netdev(local->dev);
	free_netdev(local->dev);
}


/* These might at some point be compiled separately and used as separate
 * kernel modules or linked into one */
#ifdef PRISM2_DOWNLOAD_SUPPORT
#include "hostap_download.c"
#endif /* PRISM2_DOWNLOAD_SUPPORT */

#ifdef PRISM2_CALLBACK
/* External hostap_callback.c file can be used to, e.g., blink activity led.
 * This can use platform specific code and must define prism2_callback()
 * function (if PRISM2_CALLBACK is not defined, these function calls are not
 * used. */
#include "hostap_callback.c"
#endif /* PRISM2_CALLBACK */
