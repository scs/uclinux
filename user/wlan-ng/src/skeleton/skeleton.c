/* src/skeleton/skeleton.c
*
* Test/example Mac specific driver
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
* This file is intended to provide a skeleton for a pcmcia driver
* that uses the services of p80211 and also a test fixture for
* the p80211 interfaces.  Most of the pcmcia stuff is simulated since
* we don't have an actual pcmcia device in this case.
*
* --------------------------------------------------------------------
*/

/*================================================================*/
/* System Includes */

#include <linux/config.h>
#include <linux/version.h>
#include <wlan/wlan_compat.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/netdevice.h>

#include <pcmcia/config.h>
#include <pcmcia/k_compat.h>
#include <pcmcia/version.h>
#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/ds.h>
#include <pcmcia/cisreg.h>
#include <pcmcia/driver_ops.h>

/*================================================================*/
/* Project Includes */

#include <wlan/version.h>
#include <wlan/p80211types.h>
#include <wlan/p80211hdr.h>
#include <wlan/p80211mgmt.h>
#include <wlan/p80211conv.h>
#include <wlan/p80211msg.h>
#include <wlan/p80211netdev.h>
#include <wlan/p80211metastruct.h>
#include <wlan/p80211metadef.h>
#include <wlan/p80211req.h>

/*================================================================*/
/* Local Constants */


/*================================================================*/
/* Local Macros */


/*================================================================*/
/* Local Types */

typedef struct skelpriv
{
	dev_node_t	node;
	int		a_private_var;
} skelpriv_t;

/*================================================================*/
/* Local Static Definitions */

static char		*version = "skelwlan_cs.o: " WLAN_RELEASE;
static dev_info_t	dev_info = "skelwlan_cs";
static dev_link_t	*dev_list = NULL;	/* head of instance list */

/*----------------------------------------------------------------*/
/* --Module Parameters */

int	wlan_debug=0;		/* Debug output level, */
MODULE_PARM( wlan_debug, "i");	/* extern'd in wlan_compat.h */


/*================================================================*/
/* Local Function Declarations */

int		init_module(void);
void		cleanup_module(void);
dev_link_t	*wlanskel_attach(void);
/* static void	wlanskel_detach(dev_link_t *link); */
static void	wlanskel_config(dev_link_t *link);
static void	wlanskel_release(UINT32 arg);

static int	wlanskel_open(wlandevice_t *wlandev);
static int	wlanskel_close(wlandevice_t *wlandev);
static void	wlanskel_reset(wlandevice_t *wlandev );
static int	wlanskel_txframe(wlandevice_t *wlandev, wlan_pb_t *pb);
static int	wlanskel_mlmerequest(wlandevice_t *wlandev, p80211msg_t *msg);


/*================================================================*/
/* Function Definitions */

#if  0
static void cs_error(client_handle_t handle, int func, int ret)
{
#if CS_RELEASE_CODE < 0x2911
	CardServices(ReportError, dev_info, (void *)func, (void *)ret);
#else
	error_info_t err = { func, ret };
	CardServices(ReportError, handle, &err);
#endif
}
#endif

int wlanskel_open(wlandevice_t *wlandev)
{
	WLAN_LOG_DEBUG0(1, "skeleton open method called\n");
	return 0;
}


int wlanskel_close(wlandevice_t *wlandev)
{
	WLAN_LOG_DEBUG0(1, "skeleton close method called\n");
	return 0;
}


void wlanskel_reset(wlandevice_t *wlandev )
{
	WLAN_LOG_DEBUG0(1, "skeleton reset method called\n");
	return;
}


int wlanskel_txframe(wlandevice_t *wlandev, wlan_pb_t *pb )
{
	WLAN_LOG_DEBUG0(1, "skeleton txframe method called.\n");
	return 0;
}


int wlanskel_mlmerequest(wlandevice_t *wlandev, p80211msg_t *msg)
{
	struct sk_buff				*skb;
	p80211msg_dot11ind_disassociate_t	*ind;
	int					skblen;
	WLAN_LOG_DEBUG1(1, "Received msg, cmd=0x%08x\n", (int)msg->msgcode);
	
	skblen = sizeof(p80211msg_dot11ind_disassociate_t);
	skb = alloc_skb(skblen, GFP_ATOMIC);
	skb_put(skb, skblen);

	ind = (p80211msg_dot11ind_disassociate_t*)skb->data;
	ind->msgcode = DIDmsg_dot11ind_disassociate;
	ind->msglen = sizeof(p80211msg_dot11ind_disassociate_t);
	strcpy(ind->devname, wlandev->name); 

	ind->peerstaaddress.did = DIDmsg_dot11ind_disassociate_peerstaaddress;
	ind->peerstaaddress.status = 0;
	ind->peerstaaddress.len = 7;
	ind->peerstaaddress.data.len = 6;
	memset(ind->peerstaaddress.data.data, 0xab, 6);

	ind->reasoncode.did = DIDmsg_dot11ind_disassociate_reasoncode;
	ind->reasoncode.status = 0;
	ind->reasoncode.len = 4;
	ind->reasoncode.data = 1;

#ifdef CONFIG_NETLINK
	p80211ind_mlme(wlandev, skb);
#endif

	return 0;
}



/*----------------------------------------------------------------
* wlanskel_attach
*
* Half of the attach/detach pair.  Creates and registers a device
* instance with Card Services.  In this case, it also creates the
* wlandev structure and device private structure.  These are 
* linked to the device instance via its priv member.  For the
* purposes of this skeleton, most of the pcmcia stuff is commented
* out.
*
* Arguments:
*	none
*
* Returns: 
*	A valid ptr to dev_link_t on success, NULL otherwise
*
* Side effects:
*	
*
* Call context:
*	process thread (insmod/init_module/register_pccard_driver)
----------------------------------------------------------------*/
dev_link_t *wlanskel_attach(void)
{
	#if 0
	client_reg_t	client_reg;
	int		i;
	int		ret;
	#endif
	dev_link_t	*link;
	wlandevice_t	*wlandev;


	DBFENTER;

	/* Create the PC card device object. */
	link = kmalloc(sizeof(struct dev_link_t), GFP_KERNEL);
	if ( link == NULL ) {
		return NULL;
	}
	memset(link, 0, sizeof(struct dev_link_t));
	link->release.function = &wlanskel_release;
	link->release.data = (u_long)link;
	link->io.NumPorts1 = 32;
	link->io.Attributes1 = IO_DATA_PATH_WIDTH_16;
	link->io.IOAddrLines = 5;
	link->irq.Attributes = IRQ_TYPE_EXCLUSIVE | IRQ_HANDLE_PRESENT;
	link->irq.IRQInfo1 = IRQ_INFO2_VALID|IRQ_LEVEL_ID;

	#if 0
	if (irq_list[0] == -1) {
		link->irq.IRQInfo2 = irq_mask;
	} else {
		for (i = 0; i < 4; i++) {
			link->irq.IRQInfo2 |= 1 << irq_list[i];
		}
	}
	link->irq.Handler = &skel_interrupt;
	link->conf.Attributes = CONF_ENABLE_IRQ;
	link->conf.Vcc = 50;
	link->conf.IntType = INT_MEMORY_AND_IO;
	link->conf.ConfigIndex = 1;
	link->conf.Present = PRESENT_OPTION;
	#endif

	/* Create the network device object. */
	wlandev = kmalloc(sizeof(wlandevice_t), GFP_KERNEL);
	if ( wlandev == NULL ) {
		kfree_s(link, sizeof(dev_link_t));
		return NULL;
	}
	memset(wlandev, 0, sizeof(wlandevice_t));

	/* Make up a device private data structure. */
	wlandev->priv = kmalloc(sizeof(skelpriv_t), GFP_KERNEL);
	if ( wlandev->priv == NULL ) {
		kfree_s(wlandev, sizeof(wlandevice_t));
		kfree_s(link, sizeof(dev_link_t));
		return NULL;
	}
	memset(wlandev->priv, 0, sizeof(skelpriv_t));

	/* Set our entries in the wlandev */
	wlandev->open = &wlanskel_open;
	wlandev->close = &wlanskel_close;
	wlandev->reset = &wlanskel_reset;
	wlandev->txframe = &wlanskel_txframe;
	wlandev->mlmerequest = &wlanskel_mlmerequest;

	/* Set up the remaining entries in the wlan common way */
	wlandev->name = ((skelpriv_t*)wlandev->priv)->node.dev_name;
	wlan_setup(wlandev);

	link->priv = wlandev;
#if CS_RELEASE_CODE > 0x2911
	link->irq.Instance = wlandev;
#endif

	/* Link in to the list of devices managed by this driver */
	link->next = dev_list;
	dev_list = link;	

	#if 0	/* blocked out because we have no real device */
	/* Register with Card Services */
	client_reg.dev_info = &dev_info;
	client_reg.Attributes = INFO_IO_CLIENT | INFO_CARD_SHARE;
	client_reg.EventMask =
		CS_EVENT_CARD_INSERTION | CS_EVENT_CARD_REMOVAL |
		CS_EVENT_RESET_PHYSICAL | CS_EVENT_CARD_RESET |
		CS_EVENT_PM_SUSPEND | CS_EVENT_PM_RESUME;
	client_reg.event_handler = &wlanskel_event;
	client_reg.Version = 0x0210;
	client_reg.event_callback_args.client_data = link;

	ret = CardServices(RegisterClient, &link->handle, &client_reg);
	if (ret != 0) {
		cs_error(link->handle, RegisterClient, ret);
		wlanskel_detach(link);
		return NULL;
	}
	#endif

	return link;
}



/*----------------------------------------------------------------
* wlanskel_detach
*
* Remove one of the device instances managed by this driver.
*   Search the list for the given instance, 
*   check our flags for a waiting timer'd release call
*   call release
*   Deregister the instance with Card Services
*   (netdevice) unregister the network device.
*   unlink the instance from the list
*   free the link, priv, and priv->priv memory
* Note: the dev_list variable is a driver scoped static used to
*	maintain a list of device instances managed by this
*	driver.
*
* Arguments:
*	link	ptr to the instance to detach
*
* Returns: 
*	nothing
*
* Side effects:
*	the link structure is gone, the netdevice is gone
*
* Call context:
*	Might be interrupt, don't block.
----------------------------------------------------------------*/
#if 0
void wlanskel_detach(dev_link_t *link)
{
	dev_link_t	**linkp;
	UINT32		flags;
	wlandevice_t	*wlandev;

	DBFENTER;

	/* Locate device structure */
	for (linkp = &dev_list; *linkp; linkp = &(*linkp)->next) {
		if (*linkp == link) break;
	}

	if (*linkp != NULL) {
		/* Get rid of any timer'd release call */	
		save_flags(flags);
		cli();
		if (link->state & DEV_RELEASE_PENDING) {
			del_timer(&link->release);
			link->state &= ~DEV_RELEASE_PENDING;
		}
		restore_flags(flags);
		
		/* If link says we're still config'd, call release */
		if (link->state & DEV_CONFIG) {
			wlanskel_release((u_long)link);
			if (link->state & DEV_STALE_CONFIG) {
				link->state |= DEV_STALE_LINK;
				return;
			}
		}
		
		/* Tell Card Services we're not around any more */
		if (link->handle) {
			CardServices(DeregisterClient, link->handle);
		}	

		/* Unlink device structure, free bits */
		*linkp = link->next;
		if ( link->priv != NULL ) {
			wlandev = (wlandevice_t*)link->priv;
			if (link->dev != NULL) {
				unregister_wlandev(wlandev);
			}
			wlan_unsetup(wlandev);
			if (wlandev->priv) {
				kfree_s(wlandev->priv, sizeof(skelpriv_t));
			}
			kfree_s(link->priv, sizeof(wlandevice_t));
		}
		kfree_s(link, sizeof(struct dev_link_t));
	}

	DBFEXIT;
	return;
}
#endif

/*----------------------------------------------------------------
* wlanskel_config
*
* Half of the config/release pair.  Usually called in response to
* a card insertion event.  At this point, we _know_ there's some
* physical device present.  That means we can start poking around
* at the CIS and at any device specific config data we want.
*
* Note the gotos and the macros.  I recoded this once without
* them, and it got incredibly ugly.  It's actually simpler with
* them.
*
* Arguments:
*	link	the dev_link_t structure created in attach that 
*		represents this device instance.
*
* Returns: 
*	nothing
*
* Side effects:
*	Resources (irq, io, mem) are allocated
*	The pcmcia dev_link->node->name is set
*	(For netcards) The device structure is finished and,
*	  most importantly, registered.  This means that there
*	  is now a _named_ device that can be configured from
*	  userland.
*
* Call context:
*	May be called from a timer.  Don't block!
----------------------------------------------------------------*/
#define CS_CHECK(fn, args...) \
while ((last_ret=CardServices(last_fn=(fn), args))!=0) goto cs_failed

void wlanskel_config(dev_link_t *link)
{
	client_handle_t	handle;
	wlandevice_t	*wlandev;
	skelpriv_t	*skelpriv;

	#if 0
	int		last_fn;
	int		last_ret;
	tuple_t		tuple;
	cisparse_t	parse;
	UINT16		buf[32];
	int		i;
	int		j;
	int		ioaddr;
	char		*cardname;
	#endif

	DBFENTER;

	handle = link->handle;
	wlandev = (wlandevice_t*)link->priv;

	/* Initialize the CIS parse */
	#if 0
	tuple.Attributes = 0;
	tuple.DesiredTuple = CISTPL_CONFIG;
	CS_CHECK(GetFirstTuple, handle, &tuple);
	tuple.TupleData = (cisdata_t *)buf;
	tuple.TupleDataMax = 64;
	tuple.TupleOffset = 0;
	CS_CHECK(GetTupleData, handle, &tuple);
	CS_CHECK(ParseTuple, handle, &tuple, &parse);
	link->conf.ConfigBase = parse.config.base;
	link->conf.Present = parse.config.rmask[0];
	#endif

	/* Configure card */
	link->state |= DEV_CONFIG;
	
	#if 0
	for (i = j = 0; j < 0x400; j += 0x20) {
		link->io.BasePort1 = j ^ 0x300;
		i = CardServices(RequestIO, link->handle, &link->io);
		if (i == CS_SUCCESS) break;
	}
	if (i != CS_SUCCESS) {
		cs_error(link->handle, RequestIO, i);
		goto failed;
	}
	CS_CHECK(RequestIRQ, link->handle, &link->irq);
	CS_CHECK(RequestConfiguration, link->handle, &link->conf);
	#endif

	wlandev->irq = 0;	/* link->irq.AssignedIRQ; */
	wlandev->iobase = 0;	/* link->io.BasePort1; */

	/* Register the network device and get assigned a name */
	if (register_wlandev(wlandev) != 0) {
		WLAN_LOG_NOTICE0("wlanskel_cs: register_wlandev() failed.\n");
		goto failed;
	}

	link->state &= ~DEV_CONFIG_PENDING;

	skelpriv = (skelpriv_t*)wlandev->priv;	/* collect the device priv ptr */
	link->dev = &skelpriv->node;		/* now pcmcia knows the device name */

	/* Any device custom config/query stuff should be done here */
	/* For a netdevice, we should at least grab the mac address */

	return;
#if 0
cs_failed:
	cs_error(link->handle, last_fn, last_ret);
#endif

failed:
	wlanskel_release((UINT32)link);
	return;
}




/*----------------------------------------------------------------
* wlanskel_release
*
* Half of the config/release pair.  Usually called in response to 
* a card ejection event.  Checks to make sure no higher layers
* are still (or think they are) using the card via the link->open
* field.  
*
* NOTE: Don't forget to increment the link->open variable in the 
*  device_open method, and decrement it in the device_close 
*  method.
*
* Arguments:
*	arg	a generic 32 bit variable...we assume it's a 
*               ptr to a dev_link.
*
* Returns: 
*	nothing
*
* Side effects:
*	All resources should be released after this function
*	executes and finds the device !open.
*
* Call context:
*	Possibly in a timer context.  Don't do anything that'll
*	block.
----------------------------------------------------------------*/
void wlanskel_release(UINT32 arg)
{
        dev_link_t	*link = (dev_link_t *)arg;

	DBFENTER;

        if (link->open) {
                WLAN_LOG_DEBUG1(1, "wlanskel_cs: release postponed, '%s' still open\n",
                          link->dev->dev_name);
                link->state |= DEV_STALE_CONFIG;
                return;
        }

	/*
        CardServices(ReleaseConfiguration, link->handle);
        CardServices(ReleaseIO, link->handle, &link->io);
        CardServices(ReleaseIRQ, link->handle, &link->irq);
        if (link->win) {
                iounmap((void *)(dev->mem_start - 0x800));
                CardServices(ReleaseWindow, link->win);
        }
	*/

        link->state &= ~(DEV_CONFIG | DEV_RELEASE_PENDING);

	DBFEXIT;
}



/*----------------------------------------------------------------
* init_module
*
* Module initialization routine, called once at module load time.
* This one simulates some of the pcmcia calls.
*
* Arguments:
*	none
*
* Returns: 
*	0	- success 
*	~0	- failure, module is unloaded.
*
* Side effects:
*	TODO: define
*
* Call context:
*	process thread (insmod or modprobe)
----------------------------------------------------------------*/
int init_module(void)
{
	int		result = 0;
	dev_link_t 	*link;

        DBFENTER;

        WLAN_LOG_NOTICE1("%s Loaded\n", version);
        WLAN_LOG_NOTICE1("dev_info is: %s\n", dev_info);

	/* register_driver( &dev_info, &wlanskel_attach, &wlanskel_detach  */
	/*  simulated with call to wlanskel_attach */
	if ((link = wlanskel_attach()) == NULL ) {
		result = 1;
	} else {
		/* After attach finishes, pcmcia-cs usually calls    */
		/* the wlanskel_event function signaling an INSERT   */
		/* event This results in a call to the driver defined*/
		/* wlanskel_config function.  We'll just call it.    */
		wlanskel_config(link);
	}
	
        DBFEXIT;
        return result;
}


/*----------------------------------------------------------------
* cleanup_module
*
* Called at module unload time.  This is our last chance to
* clean up after ourselves.
*
* Arguments:
*	none
*
* Returns: 
*	nothing
*
* Side effects:
*	TODO: define
*
* Call context:
*	process thread
*
----------------------------------------------------------------*/
void cleanup_module(void)
{
	dev_link_t *link = dev_list;
	wlandevice_t *wlandev = (wlandevice_t *)link->priv;

        DBFENTER;

	
	if (link->dev != NULL) {
		unregister_wlandev(wlandev);
	}
	wlan_unsetup(wlandev);
	if (wlandev->priv) {
		kfree_s(wlandev->priv, sizeof(skelpriv_t));
	}
	kfree_s(wlandev, sizeof(wlandevice_t));
	kfree_s(link, sizeof(struct dev_link_t));

        printk(KERN_NOTICE "%s Unloaded\n", version);

        DBFEXIT;
        return;
}
