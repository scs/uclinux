/* src/prism2/driver/hfa384x_usb.c
*
* Functions that talk to the USB variantof the Intersil hfa384x MAC
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
* This file implements functions that correspond to the prism2/hfa384x
* 802.11 MAC hardware and firmware host interface.
*
* The functions can be considered to represent several levels of 
* abstraction.  The lowest level functions are simply C-callable wrappers
* around the register accesses.  The next higher level represents C-callable
* prism2 API functions that match the Intersil documentation as closely
* as is reasonable.  The next higher layer implements common sequences 
* of invokations of the API layer (e.g. write to bap, followed by cmd).
*
* Common sequences:
* hfa384x_drvr_xxx	Highest level abstractions provided by the 
*			hfa384x code.  They are driver defined wrappers 
*			for common sequences.  These functions generally
*			use the services of the lower levels.
*
* hfa384x_drvr_xxxconfig  An example of the drvr level abstraction. These
*			functions are wrappers for the RID get/set 
*			sequence. They 	call copy_[to|from]_bap() and 
*			cmd_access().	These functions operate on the 
*			RIDs and buffers without validation.  The caller
*			is responsible for that.
*
* API wrapper functions:
* hfa384x_cmd_xxx	functions that provide access to the f/w commands.  
*			The function arguments correspond to each command
*			argument, even command arguments that get packed
*			into single registers.  These functions _just_
*			issue the command by setting the cmd/parm regs
*			& reading the status/resp regs.  Additional
*			activities required to fully use a command
*			(read/write from/to bap, get/set int status etc.)
*			are implemented separately.  Think of these as
*			C-callable prism2 commands.
*
* Lowest Layer Functions:
* hfa384x_docmd_xxx	These functions implement the sequence required
*			to issue any prism2 command.  Primarily used by the
*			hfa384x_cmd_xxx functions.
*
* hfa384x_bap_xxx	BAP read/write access functions.
*			Note: we usually use BAP0 for non-interrupt context
*			 and BAP1 for interrupt context.
*
* hfa384x_dl_xxx	download related functions.
*                 	
* Driver State Issues:
* Note that there are two pairs of functions that manage the
* 'initialized' and 'running' states of the hw/MAC combo.  The four
* functions are create(), destroy(), start(), and stop().  create()
* sets up the data structures required to support the hfa384x_*
* functions and destroy() cleans them up.  The start() function gets
* the actual hardware running and enables the interrupts.  The stop()
* function shuts the hardware down.  The sequence should be:
* create()
* start()
*  .
*  .  Do interesting things w/ the hardware
*  .
* stop()
* destroy()
*
* Note that destroy() can be called without calling stop() first.
* --------------------------------------------------------------------
*/

/*================================================================*/
/* System Includes */
#define __NO_VERSION__

#include <linux/config.h>
#define WLAN_DBVAR	prism2_debug
#include <linux/version.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/wireless.h>
#include <linux/netdevice.h>
#include <linux/timer.h>
#include <asm/semaphore.h>
#include <asm/io.h>
#include <linux/delay.h>
#include <asm/byteorder.h>

#include <wlan/wlan_compat.h>

#if ((WLAN_HOSTIF == WLAN_PCMCIA) || (WLAN_HOSTIF == WLAN_PLX) || (WLAN_HOSTIF == WLAN_PCI))
#error "This file is specific to USB"
#endif

#if (WLAN_HOSTIF == WLAN_USB)
#include <linux/usb.h>
#endif

/*================================================================*/
/* Project Includes */

#include <wlan/version.h>
#include <wlan/p80211types.h>
#include <wlan/p80211hdr.h>
#include <wlan/p80211mgmt.h>
#include <wlan/p80211conv.h>
#include <wlan/p80211msg.h>
#include <wlan/p80211netdev.h>
#include <wlan/p80211req.h>
#include <wlan/p80211metadef.h>
#include <wlan/p80211metastruct.h>
#include <prism2/hfa384x.h>
#include <prism2/prism2mgmt.h>

/*================================================================*/
/* Local Constants */

#define	DOWAIT		1
#define DOASYNC		0

/*================================================================*/
/* Local Macros */

#define ROUNDUP64(a) (((a)+63)&~63)

/*================================================================*/
/* Local Types */

/*================================================================*/
/* Local Static Definitions */
extern int prism2_debug;

/*================================================================*/
/* Local Function Declarations */

#if 0
static void 
dbprint_urb(struct urb* urb);
#endif

static int	
hfa384x_rx_typedrop( wlandevice_t *wlandev, UINT16 fc);

static void
hfa384x_int_rxmonitor( 
	wlandevice_t *wlandev, 
	hfa384x_usb_rxfrm_t *rxfrm);

/*---------------------------------------------------*/
/* BULKOUT Callbacks */
static void 
hfa384x_usbout_callback(struct urb *urb);

/*---------------------------------------------------*/
/* BULKIN Callbacks */
static void	
hfa384x_usbin_callback(struct urb *urb);

static void
hfa384x_usbin_txcompl(wlandevice_t *wlandev, hfa384x_usbin_t *usbin);

static void
hfa384x_usbin_rx(wlandevice_t *wlandev, hfa384x_usbin_t *usbin);

static void
hfa384x_usbin_info(wlandevice_t *wlandev, hfa384x_usbin_t *usbin);

static void
hfa384x_usbout_tx(wlandevice_t *wlandev, hfa384x_usbout_t *usbout);

static void
hfa384x_usbin_ctlx(wlandevice_t *wlandev, struct urb *urb);

/*---------------------------------------------------*/
/* Functions to support the prism2 usb command queue */
static hfa384x_usbctlx_t*
hfa384x_usbctlxq_dequeue(hfa384x_usbctlxq_t *ctlxq);

static void 
hfa384x_usbctlxq_enqueue_run(
	hfa384x_usbctlxq_t *ctlxq,
	hfa384x_usbctlx_t *ctlx);

static void 
hfa384x_usbctlxq_run(hfa384x_usbctlxq_t *ctlxq);

static void 
hfa384x_usbctlx_reqtimerfn(unsigned long data);

static void 
hfa384x_usbctlx_resptimerfn(unsigned long data);

static void 
hfa384x_usbctlx_submit_wait(
	hfa384x_t		*hw, 
	hfa384x_usbctlx_t	*ctlx);

void 
hfa384x_usbctlx_submit_async(
	hfa384x_t		*hw, 
	hfa384x_usbctlx_t	*ctlx,
	ctlx_usercb_t		usercb,
	void			*usercb_data);

static void 
hfa384x_usbctlx_complete(hfa384x_usbctlx_t *ctlx);

static void
hfa384x_cbcmd(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx);

static void
hfa384x_cbrrid(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx);

static void
hfa384x_cbwrid(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx);

static void
hfa384x_cbrmem(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx);

static void
hfa384x_cbwmem(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx);


/*---------------------------------------------------*/
/* Low level req/resp CTLX formatters and submitters */
static int
hfa384x_docmd( 
	hfa384x_t *hw, 
	UINT	wait,
	hfa384x_metacmd_t *cmd,
	ctlx_usercb_t usercb,
	void	*usercb_data);

static int
hfa384x_dorrid(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	rid,
	void	*riddata,
	UINT	riddatalen,
	ctlx_usercb_t usercb,
	void	*usercb_data);

static int
hfa384x_dowrid(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	rid,
	void	*riddata,
	UINT	riddatalen,
	ctlx_usercb_t usercb,
	void	*usercb_data);

static int
hfa384x_dormem(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	page,
	UINT16	offset,
	void	*data,
	UINT	len,
	ctlx_usercb_t usercb,
	void	*usercb_data);

static int
hfa384x_dowmem(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	page,
	UINT16	offset,
	void	*data,
	UINT	len,
	ctlx_usercb_t usercb,
	void	*usercb_data);

static int
hfa384x_isgood_pdrcode(UINT16 pdrcode);

/*================================================================*/
/* Function Definitions */

#if 0
void
dbprint_urb(struct urb* urb)
{
	WLAN_LOG_DEBUG(3,"urb->pipe=0x%08x\n", urb->pipe);
	WLAN_LOG_DEBUG(3,"urb->status=0x%08x\n", urb->status);
	WLAN_LOG_DEBUG(3,"urb->transfer_flags=0x%08x\n", urb->transfer_flags);
	WLAN_LOG_DEBUG(3,"urb->transfer_buffer=0x%08x\n", (UINT)urb->transfer_buffer);
	WLAN_LOG_DEBUG(3,"urb->transfer_buffer_length=0x%08x\n", urb->transfer_buffer_length);
	WLAN_LOG_DEBUG(3,"urb->actual_length=0x%08x\n", urb->actual_length);
	WLAN_LOG_DEBUG(3,"urb->bandwidth=0x%08x\n", urb->bandwidth);
	WLAN_LOG_DEBUG(3,"urb->setup_packet(ctl)=0x%08x\n", (UINT)urb->setup_packet);
	WLAN_LOG_DEBUG(3,"urb->start_frame(iso/irq)=0x%08x\n", urb->start_frame);
	WLAN_LOG_DEBUG(3,"urb->interval(irq)=0x%08x\n", urb->interval);
	WLAN_LOG_DEBUG(3,"urb->error_count(iso)=0x%08x\n", urb->error_count);
	WLAN_LOG_DEBUG(3,"urb->timeout=0x%08x\n", urb->timeout);
	WLAN_LOG_DEBUG(3,"urb->context=0x%08x\n", (UINT)urb->context);
	WLAN_LOG_DEBUG(3,"urb->complete=0x%08x\n", (UINT)urb->complete);
}
#endif


/*----------------------------------------------------------------
* hfa384x_create
*
* Sets up the hfa384x_t data structure for use.  Note this
* does _not_ intialize the actual hardware, just the data structures
* we use to keep track of its state.
*
* Arguments:
*	hw		device structure
*	irq		device irq number
*	iobase		i/o base address for register access
*	membase		memory base address for register access
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
void
hfa384x_create( hfa384x_t *hw, struct usb_device *usb, void *usbcontext)

{
	DBFENTER;

	memset(hw, 0, sizeof(hfa384x_t));
	hw->usb = usb;
	hw->usbcontext = usbcontext;  /* this is actually a wlandev */
	hw->endp_in = -1;
	hw->endp_out = -1;

	/* Set up the waitq */
	init_waitqueue_head(&hw->cmdq);

	/* Initialize the command queue */
	spin_lock_init(&hw->ctlxq.lock);

#ifdef DECLARE_TASKLET
	tasklet_init(&hw->link_bh,
		     prism2sta_linkstatus_defer,
		     (unsigned long) hw);
#else
	INIT_TQUEUE(&hw->link_bh,
		    prism2sta_linkstatus_defer,
		    (void *) hw);
#endif

/* We need to make sure everything is set up to do USB transfers after this
 * function is complete.
 * Normally, Initialize will be called after this is set up.
 */
	hw->state = HFA384x_STATE_INIT;

	DBFEXIT;
	return;
}

/*----------------------------------------------------------------
* hfa384x_destroy
*
* Partner to hfa384x_create().  This function cleans up the hw
* structure so that it can be freed by the caller using a simple
* kfree.  Currently, this function is just a placeholder.  If, at some
* point in the future, an hw in the 'shutdown' state requires a 'deep'
* kfree, this is where it should be done.  Note that if this function
* is called on a _running_ hw structure, the drvr_stop() function is
* called.
*
* Arguments:
*	hw		device structure
*
* Returns: 
*	nothing, this function is not allowed to fail.
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
void
hfa384x_destroy( hfa384x_t *hw)
{
	DBFENTER;

	if ( hw->state == HFA384x_STATE_RUNNING ) {
		hfa384x_drvr_stop(hw);
	}
	hw->state = HFA384x_STATE_PREINIT;		
			
	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_cbcmd
*
* Ctlx_complete handler for async CMD type control exchanges.
* mark the hw struct as such.
*
* Note: If the handling is changed here, it should probably be 
*       changed in docmd as well.
*
* Arguments:
*	hw		hw struct
*	ctlx		complete CTLX
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_cbcmd(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx)
{
	UINT				result;
	hfa384x_async_cmdresult_t	cmdresult;

	DBFENTER;
	if ( ctlx->usercb != NULL ) {
		memset(&cmdresult, 0, sizeof(cmdresult));
		result = ctlx->state;
		if (ctlx->state == HFA384x_USBCTLX_COMPLETE) {
			cmdresult.status = 
				hfa384x2host_16(ctlx->inbuf.cmdresp.status);
			cmdresult.resp0 = 
				hfa384x2host_16(ctlx->inbuf.cmdresp.resp0);
			cmdresult.resp1 = 
				hfa384x2host_16(ctlx->inbuf.cmdresp.resp1);
			cmdresult.resp2 = 
				hfa384x2host_16(ctlx->inbuf.cmdresp.resp2);
		}
	
		(*ctlx->usercb)(hw, result, &cmdresult, ctlx->usercb_data);
	}

	kfree(ctlx);
	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_cbrrid
*
* CTLX completion handler for async RRID type control exchanges.
* 
* Note: If the handling is changed here, it should probably be 
*       changed in dowrid as well.
*
* Arguments:
*	hw		hw struct
*	ctlx		complete CTLX
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_cbrrid(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx)
{
	UINT				result;
	hfa384x_async_rridresult_t	rridresult;

	DBFENTER;
	if ( ctlx->usercb != NULL ) {
		memset(&rridresult, 0, sizeof(rridresult));
		result = ctlx->state;
	
		if (ctlx->state == HFA384x_USBCTLX_COMPLETE) {
			rridresult.rid = 
				hfa384x2host_16(ctlx->inbuf.rridresp.rid);
			rridresult.riddata = ctlx->inbuf.rridresp.data;
			rridresult.riddata_len = 
			((hfa384x2host_16(ctlx->inbuf.rridresp.frmlen)-1)*2);
		}

		(*ctlx->usercb)(hw, result, &rridresult, ctlx->usercb_data);
	}
	kfree(ctlx);
	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_cbwrid
*
* CTLX completion handler for async WRID type control exchanges.
*
* Note: If the handling is changed here, it should probably be 
*       changed in dowrid as well.
*
* Arguments:
*	hw		hw struct
*	ctlx		complete CTLX
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_cbwrid(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx)
{
	UINT				result;
	hfa384x_async_wridresult_t	wridresult;

	DBFENTER;
	if ( ctlx->usercb != NULL ) {
		memset(&wridresult, 0, sizeof(wridresult));
		result = ctlx->state;
		if (ctlx->state == HFA384x_USBCTLX_COMPLETE) {
			wridresult.status = 
				hfa384x2host_16(ctlx->inbuf.wridresp.status);
			wridresult.resp0 = 
				hfa384x2host_16(ctlx->inbuf.wridresp.resp0);
			wridresult.resp1 = 
				hfa384x2host_16(ctlx->inbuf.wridresp.resp1);
			wridresult.resp2 = 
				hfa384x2host_16(ctlx->inbuf.wridresp.resp2);
		}

		(*ctlx->usercb)(hw, result, &wridresult, ctlx->usercb_data);
	}
	kfree(ctlx);

	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_cbrmem
*
* CTLX completion handler for async RMEM type control exchanges.
*
* Note: If the handling is changed here, it should probably be 
*       changed in dormem as well.
*
* Arguments:
*	hw		hw struct
*	ctlx		complete CTLX
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_cbrmem(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx)
{
	DBFENTER;

	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_cbwmem
*
* CTLX completion handler for async WMEM type control exchanges.
*
* Note: If the handling is changed here, it should probably be 
*       changed in dowmem as well.
*
* Arguments:
*	hw		hw struct
*	ctlx		complete CTLX
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_cbwmem(hfa384x_t *hw, hfa384x_usbctlx_t *ctlx)
{
	DBFENTER;

	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_cmd_initialize
*
* Issues the initialize command and sets the hw->state based
* on the result.
*
* Arguments:
*	hw		device structure
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process
----------------------------------------------------------------*/
int
hfa384x_cmd_initialize(hfa384x_t *hw)
{
	int	result = 0;
	int	i;
	hfa384x_metacmd_t cmd;

	DBFENTER;


	cmd.cmd = HFA384x_CMDCODE_INIT;
	cmd.parm0 = 0;
	cmd.parm1 = 0;
	cmd.parm2 = 0;

	result = hfa384x_docmd(hw, DOWAIT, &cmd, NULL, NULL);


	WLAN_LOG_DEBUG(3,"cmdresp.init: "
		"status=0x%04x, resp0=0x%04x, "
		"resp1=0x%04x, resp2=0x%04x\n",
		cmd.status, cmd.resp0, cmd.resp1, cmd.resp2);
	if ( result == 0 ) {
		for ( i = 0; i < HFA384x_NUMPORTS_MAX; i++) {
			hw->port_enabled[i] = 0;
		}
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_cmd_disable
*
* Issues the disable command to stop communications on one of 
* the MACs 'ports'.
*
* Arguments:
*	hw		device structure
*	macport		MAC port number (host order)
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_cmd_disable(hfa384x_t *hw, UINT16 macport)
{
	int	result = 0;
	hfa384x_metacmd_t cmd;

	DBFENTER;

	cmd.cmd = HFA384x_CMD_CMDCODE_SET(HFA384x_CMDCODE_DISABLE) |
		  HFA384x_CMD_MACPORT_SET(macport);
	cmd.parm0 = 0;
	cmd.parm1 = 0;
	cmd.parm2 = 0;

	result = hfa384x_docmd(hw, DOWAIT, &cmd, NULL, NULL);

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_cmd_enable
*
* Issues the enable command to enable communications on one of 
* the MACs 'ports'.
*
* Arguments:
*	hw		device structure
*	macport		MAC port number
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_cmd_enable(hfa384x_t *hw, UINT16 macport)
{
	int	result = 0;
	hfa384x_metacmd_t cmd;

	DBFENTER;

	cmd.cmd = HFA384x_CMD_CMDCODE_SET(HFA384x_CMDCODE_ENABLE) |
		  HFA384x_CMD_MACPORT_SET(macport);
	cmd.parm0 = 0;
	cmd.parm1 = 0;
	cmd.parm2 = 0;

	result = hfa384x_docmd(hw, DOWAIT, &cmd, NULL, NULL);

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_cmd_notify
*
* Sends an info frame to the firmware to alter the behavior
* of the f/w asynch processes.  Can only be called when the MAC
* is in the enabled state.
*
* Arguments:
*	hw		device structure
*	reclaim		[0|1] indicates whether the given FID will
*			be handed back (via Alloc event) for reuse.
*			(host order)
*	fid		FID of buffer containing the frame that was
*			previously copied to MAC memory via the bap.
*			(host order)
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*	hw->resp0 will contain the FID being used by async notify
*	process.  If reclaim==0, resp0 will be the same as the fid
*	argument.  If reclaim==1, resp0 will be the different.
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_cmd_notify(hfa384x_t *hw, UINT16 reclaim, UINT16 fid, 
		       void *buf, UINT16 len)
{
#if 0
	int	result = 0;
	UINT16	cmd;
	DBFENTER;
	cmd =	HFA384x_CMD_CMDCODE_SET(HFA384x_CMDCODE_NOTIFY) |
		HFA384x_CMD_RECL_SET(reclaim);
	result = hfa384x_docmd_wait(hw, cmd, fid, 0, 0);
	
	DBFEXIT;
	return result;
#endif
return 0;
}


/*----------------------------------------------------------------
* hfa384x_cmd_inquiry
*
* Requests an info frame from the firmware.  The info frame will
* be delivered asynchronously via the Info event.
*
* Arguments:
*	hw		device structure
*	fid		FID of the info frame requested. (host order)
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_cmd_inquiry(hfa384x_t *hw, UINT16 fid)
{
	int	result = 0;
	hfa384x_metacmd_t cmd;

	DBFENTER;

	cmd.cmd = HFA384x_CMD_CMDCODE_SET(HFA384x_CMDCODE_INQ);
	cmd.parm0 = 0;
	cmd.parm1 = 0;
	cmd.parm2 = 0;

	result = hfa384x_docmd(hw, DOWAIT, &cmd, NULL, NULL);
	
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_cmd_monitor
*
* Enables the 'monitor mode' of the MAC.  Here's the description of
* monitor mode that I've received thus far:
*
*  "The "monitor mode" of operation is that the MAC passes all 
*  frames for which the PLCP checks are correct. All received 
*  MPDUs are passed to the host with MAC Port = 7, with a  
*  receive status of good, FCS error, or undecryptable. Passing 
*  certain MPDUs is a violation of the 802.11 standard, but useful 
*  for a debugging tool."  Normal communication is not possible
*  while monitor mode is enabled.
*
* Arguments:
*	hw		device structure
*	enable		a code (0x0b|0x0f) that enables/disables
*			monitor mode. (host order)
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_cmd_monitor(hfa384x_t *hw, UINT16 enable)
{
	int	result = 0;
	hfa384x_metacmd_t cmd;

	DBFENTER;

	cmd.cmd = HFA384x_CMD_CMDCODE_SET(HFA384x_CMDCODE_MONITOR) |
		HFA384x_CMD_AINFO_SET(enable);
	cmd.parm0 = 0;
	cmd.parm1 = 0;
	cmd.parm2 = 0;

	result = hfa384x_docmd(hw, DOWAIT, &cmd, NULL, NULL);
	
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_cmd_download
*
* Sets the controls for the MAC controller code/data download
* process.  The arguments set the mode and address associated 
* with a download.  Note that the aux registers should be enabled
* prior to setting one of the download enable modes.
*
* Arguments:
*	hw		device structure
*	mode		0 - Disable programming and begin code exec
*			1 - Enable volatile mem programming
*			2 - Enable non-volatile mem programming
*			3 - Program non-volatile section from NV download
*			    buffer. 
*			(host order)
*	lowaddr		
*	highaddr	For mode 1, sets the high & low order bits of 
*			the "destination address".  This address will be
*			the execution start address when download is
*			subsequently disabled.
*			For mode 2, sets the high & low order bits of 
*			the destination in NV ram.
*			For modes 0 & 3, should be zero. (host order)
*			NOTE: these are CMD format.
*	codelen		Length of the data to write in mode 2, 
*			zero otherwise. (host order)
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_cmd_download(hfa384x_t *hw, UINT16 mode, UINT16 lowaddr, 
				UINT16 highaddr, UINT16 codelen)
{
	int	result = 0;
	hfa384x_metacmd_t cmd;

	DBFENTER;
	WLAN_LOG_DEBUG(5,
		"mode=%d, lowaddr=0x%04x, highaddr=0x%04x, codelen=%d\n",
		mode, lowaddr, highaddr, codelen);

	cmd.cmd = (HFA384x_CMD_CMDCODE_SET(HFA384x_CMDCODE_DOWNLD) |
		   HFA384x_CMD_PROGMODE_SET(mode));

	cmd.parm0 = lowaddr;
	cmd.parm1 = highaddr;
	cmd.parm2 = codelen;

	result = hfa384x_docmd(hw, DOWAIT, &cmd, NULL, NULL);

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_copy_from_aux
*
* Copies a collection of bytes from the controller memory.  The
* Auxiliary port MUST be enabled prior to calling this function.
* We _might_ be in a download state.
*
* Arguments:
*	hw		device structure
*	cardaddr	address in hfa384x data space to read
*	auxctl		address space select
*	buf		ptr to destination host buffer
*	len		length of data to transfer (in bytes)
*
* Returns: 
*	nothing
*
* Side effects:
*	buf contains the data copied
*
* Call context:
*	process
*	interrupt
----------------------------------------------------------------*/
void 
hfa384x_copy_from_aux(
	hfa384x_t *hw, UINT32 cardaddr, UINT32 auxctl, void *buf, UINT len)
{
	DBFENTER;
	WLAN_LOG_ERROR0("not used in USB.\n");
	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_copy_to_aux
*
* Copies a collection of bytes to the controller memory.  The
* Auxiliary port MUST be enabled prior to calling this function.
* We _might_ be in a download state.
*
* Arguments:
*	hw		device structure
*	cardaddr	address in hfa384x data space to read
*	auxctl		address space select
*	buf		ptr to destination host buffer
*	len		length of data to transfer (in bytes)
*
* Returns: 
*	nothing
*
* Side effects:
*	Controller memory now contains a copy of buf
*
* Call context:
*	process
*	interrupt
----------------------------------------------------------------*/
void 
hfa384x_copy_to_aux(
	hfa384x_t *hw, UINT32 cardaddr, UINT32 auxctl, void *buf, UINT len)
{
	DBFENTER;
	WLAN_LOG_ERROR0("not used in USB.\n");
	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_corereset
*
* Perform a reset of the hfa38xx MAC core.  We assume that the hw 
* structure is in its "created" state.  That is, it is initialized
* with proper values.  Note that if a reset is done after the 
* device has been active for awhile, the caller might have to clean 
* up some leftover cruft in the hw structure.
*
* Arguments:
*	hw		device structure
*	holdtime	how long (in ms) to hold the reset
*	settletime	how long (in ms) to wait after releasing
*			the reset
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_corereset( hfa384x_t *hw, int holdtime, int settletime)
{
	struct usb_device	*parent = hw->usb->parent;
	int			i;
	int 			result = 0;
	int			port = -1;

#define P2_USB_RT_PORT		(USB_TYPE_CLASS | USB_RECIP_OTHER)
#define P2_USB_FEAT_RESET	4
#define P2_USB_FEAT_C_RESET	20

	DBFENTER;

	/* Find the hub port */
	for ( i = 0; i < parent->maxchild; i++) {
		if (parent->children[i] == hw->usb) {
			port = i;
			break;
		}
	}
	if (port < 0) return -ENOENT;

	/* Set and clear the reset */
	usb_control_msg(parent, usb_sndctrlpipe(parent, 0), 
		USB_REQ_SET_FEATURE, P2_USB_RT_PORT, P2_USB_FEAT_RESET, 
		port+1, NULL, 0, 1*HZ);
	wait_ms(holdtime);
	usb_control_msg(parent, usb_sndctrlpipe(parent, 0), 
		USB_REQ_CLEAR_FEATURE, P2_USB_RT_PORT, P2_USB_FEAT_C_RESET, 
		port+1, NULL, 0, 1*HZ);
	wait_ms(settletime);

	/* Set the device address */
	result=usb_set_address(hw->usb);
	if (result < 0) {
		WLAN_LOG_ERROR("reset_usbdev: Dev not accepting address, "
			"result=%d\n", result);
		clear_bit(hw->usb->devnum, &hw->usb->bus->devmap.devicemap);
		hw->usb->devnum = -1;
		goto done;
	}
	/* Let the address settle */
	wait_ms(20);

	/* Assume we're reusing the original descriptor data */
	
	/* Set the configuration. */
	WLAN_LOG_DEBUG(3, "Setting Configuration %d\n", 
		hw->usb->config[0].bConfigurationValue);
	result=usb_set_configuration(hw->usb, hw->usb->config[0].bConfigurationValue);
	if ( result ) {
		WLAN_LOG_ERROR("usb_set_configuration() failed, result=%d.\n",
				result);
		goto done;
	}	
	/* Let the configuration settle */
	wait_ms(20);

done:	
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_docmd
*
* Constructs a command CTLX and submits it.
*
* NOTE: Any changes to the 'post-submit' code in this function 
*       need to be carried over to hfa384x_cbcmd() since the handling
*       is virtually identical.
*
* Arguments:
*	hw		device structure
*	wait		1=wait for completion, 0=async
*       cmd             cmd structure.  Includes all arguments and result
*                       data points.  All in host order. in host order

*	usercb		user callback for async calls, NULL for wait==1 calls
*	usercb_data	user supplied data pointer for async calls, NULL
*			for wait==1 calls
*
* Returns: 
*	0		success
*	-EIO		CTLX failure
*	-ERESTARTSYS	Awakened on signal
*	>0		command indicated error, Status and Resp0-2 are
*			in hw structure.
*
* Side effects:
*	
*
* Call context:
*	process 
----------------------------------------------------------------*/
int 
hfa384x_docmd( 
	hfa384x_t *hw, 
	UINT	wait,
	hfa384x_metacmd_t *cmd,
	ctlx_usercb_t	usercb,
	void	*usercb_data)
{
	int			result = 0;
	hfa384x_usbctlx_t	*ctlx;
	
	DBFENTER;
	ctlx = kmalloc(sizeof(*ctlx), GFP_ATOMIC);
	if ( ctlx == NULL ) {
		result = -ENOMEM;
		goto done;
	}
	memset(ctlx, 0, sizeof(*ctlx));
	ctlx->state = HFA384x_USBCTLX_START;

	/* Initialize the command */
	ctlx->outbuf.cmdreq.type = 	host2hfa384x_16(HFA384x_USB_CMDREQ);
	ctlx->outbuf.cmdreq.cmd =	host2hfa384x_16(cmd->cmd);
	ctlx->outbuf.cmdreq.parm0 =	host2hfa384x_16(cmd->parm0);
	ctlx->outbuf.cmdreq.parm1 =	host2hfa384x_16(cmd->parm1);
	ctlx->outbuf.cmdreq.parm2 =	host2hfa384x_16(cmd->parm2);

	WLAN_LOG_DEBUG(4, "cmdreq: cmd=0x%04x "
		"parm0=0x%04x parm1=0x%04x parm2=0x%04x\n",
		cmd->cmd,
		cmd->parm0,
		cmd->parm1,
		cmd->parm2);

	/* Fill the out packet */
	FILL_BULK_URB( &(ctlx->outurb), hw->usb,
		usb_sndbulkpipe(hw->usb, hw->endp_out),
		&(ctlx->outbuf), ROUNDUP64(sizeof(ctlx->outbuf.cmdreq)),
		hfa384x_usbout_callback, hw->usbcontext);
	ctlx->outurb.transfer_flags |= USB_ASYNC_UNLINK | USB_QUEUE_BULK;

	if ( wait ) {
		hfa384x_usbctlx_submit_wait(hw, ctlx);
	} else {
		hfa384x_usbctlx_submit_async(hw, ctlx, usercb, usercb_data);
		goto done;
	}

	/* All of the following is skipped for async calls */
	/* On reawakening, check the ctlx status */
	switch(ctlx->state) { 
	case HFA384x_USBCTLX_COMPLETE:
		result = hfa384x2host_16(ctlx->inbuf.cmdresp.status);
		result &= HFA384x_STATUS_RESULT;

		cmd->status = hfa384x2host_16(ctlx->inbuf.cmdresp.status);
		cmd->resp0 = hfa384x2host_16(ctlx->inbuf.cmdresp.resp0);
		cmd->resp1 = hfa384x2host_16(ctlx->inbuf.cmdresp.resp1);
		cmd->resp2 = hfa384x2host_16(ctlx->inbuf.cmdresp.resp2);
		WLAN_LOG_DEBUG(4, "cmdresp:status=0x%04x "
			"resp0=0x%04x resp1=0x%04x resp2=0x%04x\n",
			cmd->status,
			cmd->resp0,
			cmd->resp1,
			cmd->resp2);
		break;
	case HFA384x_USBCTLX_REQSUBMIT_FAIL:
		WLAN_LOG_WARNING0("ctlx failure=REQSUBMIT_FAIL\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_REQ_TIMEOUT:
		WLAN_LOG_WARNING0("ctlx failure=REQ_TIMEOUT\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_REQ_FAILED:
		WLAN_LOG_WARNING0("ctlx failure=REQ_FAILED\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_RESP_TIMEOUT:
		WLAN_LOG_WARNING0("ctlx failure=RESP_TIMEOUT\n");
		result = -EIO;
		break;
	default:
		/* The ctlx is still running and probably still in the queue 
		 * We were probably awakened by a signal.  Return an error  
		 * and DO NOT free the ctlx.  Let the ctlx finish and it will
		 * just be leaked.  At least we won't crash that way.
		 * TODO: we need a ctlx_cancel function 
		 */
		result = -ERESTARTSYS;
		goto done;
		break;
	}

	kfree(ctlx);
done:
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_dorrid
*
* Constructs a read rid CTLX and issues it.
*
* NOTE: Any changes to the 'post-submit' code in this function 
*       need to be carried over to hfa384x_cbrrid() since the handling
*       is virtually identical.
*
* Arguments:
*	hw		device structure
*	wait		1=wait for completion, 0=async
*	rid		Read RID number (host order)
*	riddata		Caller supplied buffer that MAC formatted RID.data 
*			record will be written to for wait==1 calls. Should
*			be NULL for wait==0 calls.
*	riddatalen	Buffer length for wait==1 calls. Zero for wait==0 calls.
*	usercb		user callback for async calls, NULL for wait==1 calls
*	usercb_data	user supplied data pointer for async calls, NULL
*			for wait==1 calls
*
* Returns: 
*	0		success
*	-EIO		CTLX failure
*	-ERESTARTSYS	Awakened on signal
*	-ENODATA	riddatalen != macdatalen
*	>0		command indicated error, Status and Resp0-2 are
*			in hw structure.
*
* Side effects:
*	
* Call context:
*	interrupt (wait==0)
*	process (wait==0 || wait==1)
----------------------------------------------------------------*/
int
hfa384x_dorrid(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	rid,
	void	*riddata,
	UINT	riddatalen,
	ctlx_usercb_t usercb,
	void	*usercb_data)
{
	int			result = 0;
	hfa384x_usbctlx_t	*ctlx;
	UINT			maclen;
	
	DBFENTER;
	ctlx = kmalloc(sizeof(*ctlx), GFP_ATOMIC);
	if ( ctlx == NULL ) {
		result = -ENOMEM;
		goto done;
	}
	memset(ctlx, 0, sizeof(*ctlx));
	ctlx->state = HFA384x_USBCTLX_START;

	/* Initialize the command */
	ctlx->outbuf.rridreq.type =   host2hfa384x_16(HFA384x_USB_RRIDREQ);
	ctlx->outbuf.rridreq.frmlen = 
		host2hfa384x_16(sizeof(ctlx->outbuf.rridreq.rid));
	ctlx->outbuf.rridreq.rid =    host2hfa384x_16(rid);

	/* Fill the out packet */
	FILL_BULK_URB( &(ctlx->outurb), hw->usb,
		usb_sndbulkpipe(hw->usb, hw->endp_out),
		&(ctlx->outbuf), ROUNDUP64(sizeof(ctlx->outbuf.rridreq)),
		hfa384x_usbout_callback, hw->usbcontext);
	ctlx->outurb.transfer_flags |= USB_ASYNC_UNLINK | USB_QUEUE_BULK;

	/* Submit the CTLX */
	if ( wait ) {
		hfa384x_usbctlx_submit_wait(hw, ctlx);
	} else {
		hfa384x_usbctlx_submit_async(hw, ctlx, usercb, usercb_data);
		goto done;
	}

	/* All of the following is skipped for async calls */
	/* On reawakening, check the ctlx status */
	switch(ctlx->state) { 
	case HFA384x_USBCTLX_COMPLETE:
		/* The results are in ctlx->outbuf */
		/* Validate the length, note body len calculation in bytes */
		maclen = ((hfa384x2host_16(ctlx->inbuf.rridresp.frmlen)-1)*2);
		if ( maclen != riddatalen ) {  
			WLAN_LOG_WARNING(
			"RID len mismatch, rid=0x%04x hlen=%d fwlen=%d\n",
			rid, riddatalen, maclen);
			result = -ENODATA;
			break;
		}
		memcpy( riddata, ctlx->inbuf.rridresp.data, riddatalen);
		result = 0;
		break;

	case HFA384x_USBCTLX_REQSUBMIT_FAIL:
		WLAN_LOG_WARNING0("ctlx failure=REQSUBMIT_FAIL\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_REQ_TIMEOUT:
		WLAN_LOG_WARNING0("ctlx failure=REQ_TIMEOUT\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_REQ_FAILED:
		WLAN_LOG_WARNING0("ctlx failure=REQ_FAILED\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_RESP_TIMEOUT:
		WLAN_LOG_WARNING0("ctlx failure=RESP_TIMEOUT\n");
		result = -EIO;
		break;
	default:
		/* The ctlx is still running and probably still in the queue 
		 * We were probably awakened by a signal.  Return an error  
		 * and DO NOT free the ctlx.  Let the ctlx finish and it will
		 * just be leaked.  At least we won't crash that way.
		 * TODO: we need a ctlx_cancel function 
		 */
		result = -ERESTARTSYS;
		goto done;
		break;
	}

	kfree(ctlx);
done:
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_dowrid
*
* Constructs a write rid CTLX and issues it.
*
* NOTE: Any changes to the 'post-submit' code in this function 
*       need to be carried over to hfa384x_cbwrid() since the handling
*       is virtually identical.
*
* Arguments:
*	hw		device structure
*	wait		1=wait for completion, 0=async
*	rid		RID code
*	riddata		Data portion of RID formatted for MAC
*	riddatalen	Length of the data portion in bytes
*	usercb		user callback for async calls, NULL for wait==1 calls
*	usercb_data	user supplied data pointer for async calls, NULL
*
* Returns: 
*	0		success
*	-ETIMEDOUT	timed out waiting for register ready or
*			command completion
*	>0		command indicated error, Status and Resp0-2 are
*			in hw structure.
*
* Side effects:
*	
* Call context:
*	interrupt (wait==0)
*	process (wait==0 || wait==1)
----------------------------------------------------------------*/
int
hfa384x_dowrid(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	rid,
	void	*riddata,
	UINT	riddatalen,
	ctlx_usercb_t usercb,
	void	*usercb_data)
{
	int			result = 0;
	hfa384x_usbctlx_t	*ctlx;
	
	DBFENTER;
	ctlx = kmalloc(sizeof(*ctlx), GFP_ATOMIC);
	if ( ctlx == NULL ) {
		result = -ENOMEM;
		goto done;
	}
	memset(ctlx, 0, sizeof(*ctlx));
	ctlx->state = HFA384x_USBCTLX_START;

	/* Initialize the command */
	ctlx->outbuf.wridreq.type =   host2hfa384x_16(HFA384x_USB_WRIDREQ);
	ctlx->outbuf.wridreq.frmlen = host2hfa384x_16(
					(sizeof(ctlx->outbuf.rridreq.rid) + 
					riddatalen + 1) / 2);
	ctlx->outbuf.wridreq.rid =    host2hfa384x_16(rid);
	memcpy(ctlx->outbuf.wridreq.data, riddata, riddatalen);

	/* Fill the out packet */
	FILL_BULK_URB( &(ctlx->outurb), hw->usb,
		usb_sndbulkpipe(hw->usb, hw->endp_out),
		&(ctlx->outbuf), 
		ROUNDUP64( sizeof(ctlx->outbuf.wridreq.type) +
			sizeof(ctlx->outbuf.wridreq.frmlen) +
			sizeof(ctlx->outbuf.wridreq.rid) +
			riddatalen),
		hfa384x_usbout_callback, 
		hw->usbcontext);
	ctlx->outurb.transfer_flags |= USB_ASYNC_UNLINK | USB_QUEUE_BULK;

	/* Submit the CTLX */
	if ( wait ) {
		hfa384x_usbctlx_submit_wait(hw, ctlx);
	} else {
		hfa384x_usbctlx_submit_async(hw, ctlx, usercb, usercb_data);
		goto done;
	}

	/* All of the following is skipped for async calls */
	/* On reawakening, check the ctlx status */
	switch(ctlx->state) { 
	case HFA384x_USBCTLX_COMPLETE:
		result = hfa384x2host_16(ctlx->inbuf.wridresp.status);
		result &= HFA384x_STATUS_RESULT;

/*
		hw->status = hfa384x2host_16(ctlx->inbuf.wridresp.status);
		hw->resp0 = hfa384x2host_16(ctlx->inbuf.wridresp.resp0);
		hw->resp1 = hfa384x2host_16(ctlx->inbuf.wridresp.resp1);
		hw->resp2 = hfa384x2host_16(ctlx->inbuf.wridresp.resp2);
*/
		break;

	case HFA384x_USBCTLX_REQSUBMIT_FAIL:
		WLAN_LOG_WARNING0("ctlx failure=REQSUBMIT_FAIL\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_REQ_TIMEOUT:
		WLAN_LOG_WARNING0("ctlx failure=REQ_TIMEOUT\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_REQ_FAILED:
		WLAN_LOG_WARNING0("ctlx failure=REQ_FAILED\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_RESP_TIMEOUT:
		WLAN_LOG_WARNING0("ctlx failure=RESP_TIMEOUT\n");
		result = -EIO;
		break;
	default:
		/* The ctlx is still running and probably still in the queue 
		 * We were probably awakened by a signal.  Return an error  
		 * and DO NOT free the ctlx.  Let the ctlx finish and it will
		 * just be leaked.  At least we won't crash that way.
		 * TODO: we need a ctlx_cancel function 
		 */
		result = -ERESTARTSYS;
		goto done;
		break;
	}

	kfree(ctlx);
done:
	DBFEXIT;
	return result;
}

/*----------------------------------------------------------------
* hfa384x_dormem
*
* Constructs a readmem CTLX and issues it.
*
* NOTE: Any changes to the 'post-submit' code in this function 
*       need to be carried over to hfa384x_cbrmem() since the handling
*       is virtually identical.
*
* Arguments:
*	hw		device structure
*	wait		1=wait for completion, 0=async
*	page		MAC address space page (CMD format)
*	offset		MAC address space offset
*	data		Ptr to data buffer to receive read
*	len		Length of the data to read (max == 2048)
*	usercb		user callback for async calls, NULL for wait==1 calls
*	usercb_data	user supplied data pointer for async calls, NULL
*
* Returns: 
*	0		success
*	-ETIMEDOUT	timed out waiting for register ready or
*			command completion
*	>0		command indicated error, Status and Resp0-2 are
*			in hw structure.
*
* Side effects:
*	
* Call context:
*	interrupt (wait==0)
*	process (wait==0 || wait==1)
----------------------------------------------------------------*/
int
hfa384x_dormem(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	page,
	UINT16	offset,
	void	*data,
	UINT	len,
	ctlx_usercb_t usercb,
	void	*usercb_data)
{
	int			result = 0;
	hfa384x_usbctlx_t	*ctlx;
	
	DBFENTER;
	ctlx = kmalloc(sizeof(*ctlx), GFP_ATOMIC);
	if ( ctlx == NULL ) {
		result = -ENOMEM;
		goto done;
	}
	memset(ctlx, 0, sizeof(*ctlx));
	ctlx->state = HFA384x_USBCTLX_START;

	/* Initialize the command */
	ctlx->outbuf.rmemreq.type =    host2hfa384x_16(HFA384x_USB_RMEMREQ);
	ctlx->outbuf.rmemreq.frmlen =  host2hfa384x_16(
					sizeof(ctlx->outbuf.rmemreq.offset) +
					sizeof(ctlx->outbuf.rmemreq.page) +
					len);
	ctlx->outbuf.rmemreq.offset =	host2hfa384x_16(offset);
	ctlx->outbuf.rmemreq.page =	host2hfa384x_16(page);

	WLAN_LOG_DEBUG(4,
		"type=0x%04x frmlen=%d offset=0x%04x page=0x%04x\n",
		ctlx->outbuf.rmemreq.type,
		ctlx->outbuf.rmemreq.frmlen,
		ctlx->outbuf.rmemreq.offset,
		ctlx->outbuf.rmemreq.page);

	WLAN_LOG_DEBUG(4,"pktsize=%d\n", 
		ROUNDUP64(sizeof(ctlx->outbuf.rmemreq)));

	/* Fill the out packet */
	FILL_BULK_URB( &(ctlx->outurb), hw->usb,
		usb_sndbulkpipe(hw->usb, hw->endp_out),
		&(ctlx->outbuf), ROUNDUP64(sizeof(ctlx->outbuf.rmemreq)),
		hfa384x_usbout_callback, hw->usbcontext);
	ctlx->outurb.transfer_flags |= USB_ASYNC_UNLINK | USB_QUEUE_BULK;

	if ( wait ) {
		hfa384x_usbctlx_submit_wait(hw, ctlx);
	} else {
		hfa384x_usbctlx_submit_async(hw, ctlx, usercb, usercb_data);
		goto done;
	}

	/* All of the following is skipped for async calls */
	/* On reawakening, check the ctlx status */
	switch(ctlx->state) { 
	case HFA384x_USBCTLX_COMPLETE:
		WLAN_LOG_DEBUG(4,"rmemresp:len=%d\n",
			ctlx->inbuf.rmemresp.frmlen);
		memcpy(data, ctlx->inbuf.rmemresp.data, len);
		result = 0;
		break;
	case HFA384x_USBCTLX_REQSUBMIT_FAIL:
		WLAN_LOG_WARNING0("ctlx failure=REQSUBMIT_FAIL\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_REQ_TIMEOUT:
		WLAN_LOG_WARNING0("ctlx failure=REQ_TIMEOUT\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_REQ_FAILED:
		WLAN_LOG_WARNING0("ctlx failure=REQ_FAILED\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_RESP_TIMEOUT:
		WLAN_LOG_WARNING0("ctlx failure=RESP_TIMEOUT\n");
		result = -EIO;
		break;
	default:
		/* The ctlx is still running and probably still in the queue 
		 * We were probably awakened by a signal.  Return an error  
		 * and DO NOT free the ctlx.  Let the ctlx finish and it will
		 * just be leaked.  At least we won't crash that way.
		 * TODO: we need a ctlx_cancel function 
		 */
		result = -ERESTARTSYS;
		goto done;
		break;
	}

	kfree(ctlx);
done:
	DBFEXIT;
	return result;
}


	
/*----------------------------------------------------------------
* hfa384x_dowmem
*
* Constructs a writemem CTLX and issues it.
*
* NOTE: Any changes to the 'post-submit' code in this function 
*       need to be carried over to hfa384x_cbwmem() since the handling
*       is virtually identical.
*
* Arguments:
*	hw		device structure
*	wait		1=wait for completion, 0=async
*	page		MAC address space page (CMD format)
*	offset		MAC address space offset
*	data		Ptr to data buffer containing write data
*	len		Length of the data to read (max == 2048)
*	usercb		user callback for async calls, NULL for wait==1 calls
*	usercb_data	user supplied data pointer for async calls, NULL
*
* Returns: 
*	0		success
*	-ETIMEDOUT	timed out waiting for register ready or
*			command completion
*	>0		command indicated error, Status and Resp0-2 are
*			in hw structure.
*
* Side effects:
*	
* Call context:
*	interrupt (wait==0)
*	process (wait==0 || wait==1)
----------------------------------------------------------------*/
int
hfa384x_dowmem(
	hfa384x_t *hw, 
	UINT	wait,
	UINT16	page,
	UINT16	offset,
	void	*data,
	UINT	len,
	ctlx_usercb_t usercb,
	void	*usercb_data)
{
	int			result = 0;
	hfa384x_usbctlx_t	*ctlx;
	
	DBFENTER;
	WLAN_LOG_DEBUG(5, "page=0x%04x offset=0x%04x len=%d\n",
		page,offset,len);

	ctlx = kmalloc(sizeof(*ctlx), GFP_ATOMIC);
	if ( ctlx == NULL ) {
		result = -ENOMEM;
		goto done;
	}
	memset(ctlx, 0, sizeof(*ctlx));
	ctlx->state = HFA384x_USBCTLX_START;

	/* Initialize the command */
	ctlx->outbuf.wmemreq.type =   host2hfa384x_16(HFA384x_USB_WMEMREQ);
	ctlx->outbuf.wmemreq.frmlen = host2hfa384x_16(
					sizeof(ctlx->outbuf.wmemreq.offset) +
					sizeof(ctlx->outbuf.wmemreq.page) +
					len);
	ctlx->outbuf.wmemreq.offset = host2hfa384x_16(offset);
	ctlx->outbuf.wmemreq.page =   host2hfa384x_16(page);
	memcpy(ctlx->outbuf.wmemreq.data, data, len);

	/* Fill the out packet */
	FILL_BULK_URB( &(ctlx->outurb), hw->usb,
		usb_sndbulkpipe(hw->usb, hw->endp_out),
		&(ctlx->outbuf), 
		ROUNDUP64( sizeof(ctlx->outbuf.wmemreq.type) +
			sizeof(ctlx->outbuf.wmemreq.frmlen) +
			sizeof(ctlx->outbuf.wmemreq.offset) +
			sizeof(ctlx->outbuf.wmemreq.page) +
			len),
		hfa384x_usbout_callback, 
		hw->usbcontext);
	ctlx->outurb.transfer_flags |= USB_ASYNC_UNLINK | USB_QUEUE_BULK;

	if ( wait ) {
		hfa384x_usbctlx_submit_wait(hw, ctlx);
	} else {
		hfa384x_usbctlx_submit_async(hw, ctlx, usercb, usercb_data);
		goto done;
	}

	/* All of the following is skipped for async calls */
	/* On reawakening, check the ctlx status */
	switch(ctlx->state) { 
	case HFA384x_USBCTLX_COMPLETE:
		result = hfa384x2host_16(ctlx->inbuf.wmemresp.status);
/*
		hw->status = hfa384x2host_16(ctlx->inbuf.wmemresp.status);
		hw->resp0 = hfa384x2host_16(ctlx->inbuf.wmemresp.resp0);
		hw->resp1 = hfa384x2host_16(ctlx->inbuf.wmemresp.resp1);
		hw->resp2 = hfa384x2host_16(ctlx->inbuf.wmemresp.resp2);
*/
		break;
	case HFA384x_USBCTLX_REQSUBMIT_FAIL:
		WLAN_LOG_WARNING0("ctlx failure=REQSUBMIT_FAIL\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_REQ_TIMEOUT:
		WLAN_LOG_WARNING0("ctlx failure=REQ_TIMEOUT\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_REQ_FAILED:
		WLAN_LOG_WARNING0("ctlx failure=REQ_FAILED\n");
		result = -EIO;
		break;
	case HFA384x_USBCTLX_RESP_TIMEOUT:
		WLAN_LOG_WARNING0("ctlx failure=RESP_TIMEOUT\n");
		result = -EIO;
		break;
	default:
		/* The ctlx is still running and probably still in the queue 
		 * We were probably awakened by a signal.  Return an error  
		 * and DO NOT free the ctlx.  Let the ctlx finish and it will
		 * just be leaked.  At least we won't crash that way.
		 * TODO: we need a ctlx_cancel function 
		 */
		result = -ERESTARTSYS;
		goto done;
		break;
	}

	kfree(ctlx);
done:
	DBFEXIT;
	return result;
}

	
/*----------------------------------------------------------------
* hfa384x_drvr_commtallies
*
* Send a commtallies inquiry to the MAC.  Note that this is an async
* call that will result in an info frame arriving sometime later.
*
* Arguments:
*	hw		device structure
*
* Returns: 
*	zero		success.
*
* Side effects:
*
* Call context:
*	process
----------------------------------------------------------------*/
int hfa384x_drvr_commtallies( hfa384x_t *hw )
{
	hfa384x_metacmd_t cmd;

	DBFENTER;

	cmd.cmd = HFA384x_CMDCODE_INQ;
	cmd.parm0 = HFA384x_IT_COMMTALLIES;
	cmd.parm1 = 0;
	cmd.parm2 = 0;

	hfa384x_docmd(hw, DOASYNC, &cmd, NULL, NULL);
	
	DBFEXIT;
	return 0;
}


/*----------------------------------------------------------------
* hfa384x_drvr_disable
*
* Issues the disable command to stop communications on one of 
* the MACs 'ports'.  Only macport 0 is valid  for stations.
* APs may also disable macports 1-6.  Only ports that have been
* previously enabled may be disabled.
*
* Arguments:
*	hw		device structure
*	macport		MAC port number (host order)
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_disable(hfa384x_t *hw, UINT16 macport)
{
	int	result = 0;

	DBFENTER;
	if ((!hw->isap && macport != 0) || 
	    (hw->isap && !(macport <= HFA384x_PORTID_MAX)) ||
	    !(hw->port_enabled[macport]) ){
		result = -EINVAL;
	} else {
		result = hfa384x_cmd_disable(hw, macport);
		if ( result == 0 ) {
			hw->port_enabled[macport] = 0;
		}
	}
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_enable
*
* Issues the enable command to enable communications on one of 
* the MACs 'ports'.  Only macport 0 is valid  for stations.
* APs may also enable macports 1-6.  Only ports that are currently
* disabled may be enabled.
*
* Arguments:
*	hw		device structure
*	macport		MAC port number
*
* Returns: 
*	0		success
*	>0		f/w reported failure - f/w status code
*	<0		driver reported error (timeout|bad arg)
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_enable(hfa384x_t *hw, UINT16 macport)
{
	int	result = 0;

	DBFENTER;
	if ((!hw->isap && macport != 0) || 
	    (hw->isap && !(macport <= HFA384x_PORTID_MAX)) ||
	    (hw->port_enabled[macport]) ){
		result = -EINVAL;
	} else {
		result = hfa384x_cmd_enable(hw, macport);
		if ( result == 0 ) {
			hw->port_enabled[macport] = 1;
		}
	}
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_flashdl_enable
*
* Begins the flash download state.  Checks to see that we're not
* already in a download state and that a port isn't enabled.
* Sets the download state and retrieves the flash download
* buffer location, buffer size, and timeout length.
*
* Arguments:
*	hw		device structure
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_flashdl_enable(hfa384x_t *hw)
{
	int		result = 0;
	int		i;

	DBFENTER;
	/* Check that a port isn't active */
	for ( i = 0; i < HFA384x_PORTID_MAX; i++) {
		if ( hw->port_enabled[i] ) {
			WLAN_LOG_DEBUG0(1,"called when port enabled.\n");
			return -EINVAL; 
		}
	}

	/* Check that we're not already in a download state */
	if ( hw->dlstate != HFA384x_DLSTATE_DISABLED ) {
		return -EINVAL;
	}

	/* Retrieve the buffer loc&size and timeout */
	if ( (result = hfa384x_drvr_getconfig(hw, HFA384x_RID_DOWNLOADBUFFER, 
				&(hw->bufinfo), sizeof(hw->bufinfo))) ) {
		return result;
	}
	hw->bufinfo.page = hfa384x2host_16(hw->bufinfo.page);
	hw->bufinfo.offset = hfa384x2host_16(hw->bufinfo.offset);
	hw->bufinfo.len = hfa384x2host_16(hw->bufinfo.len);
	if ( (result = hfa384x_drvr_getconfig16(hw, HFA384x_RID_MAXLOADTIME, 
				&(hw->dltimeout))) ) {
		return result;
	}
	hw->dltimeout = hfa384x2host_16(hw->dltimeout);

#if 0
WLAN_LOG_DEBUG0(1,"flashdl_enable\n");
hw->dlstate = HFA384x_DLSTATE_FLASHENABLED;
#endif
	hw->dlstate = HFA384x_DLSTATE_FLASHENABLED;
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_flashdl_disable
*
* Ends the flash download state.  Note that this will cause the MAC
* firmware to restart.
*
* Arguments:
*	hw		device structure
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_flashdl_disable(hfa384x_t *hw)
{
	DBFENTER;
	/* Check that we're already in the download state */
	if ( hw->dlstate != HFA384x_DLSTATE_FLASHENABLED ) {
		return -EINVAL;
	}

	WLAN_LOG_DEBUG0(1,"flashdl_enable\n");

	/* There isn't much we can do at this point, so I don't */
	/*  bother  w/ the return value */
	hfa384x_cmd_download(hw, HFA384x_PROGMODE_DISABLE, 0, 0 , 0);
	hw->dlstate = HFA384x_DLSTATE_DISABLED;

	DBFEXIT;
	return 0;
}


/*----------------------------------------------------------------
* hfa384x_drvr_flashdl_write
*
* Performs a FLASH download of a chunk of data. First checks to see
* that we're in the FLASH download state, then sets the download
* mode, uses the aux functions to 1) copy the data to the flash
* buffer, 2) sets the download 'write flash' mode, 3) readback and 
* compare.  Lather rinse, repeat as many times an necessary to get
* all the given data into flash.  
* When all data has been written using this function (possibly 
* repeatedly), call drvr_flashdl_disable() to end the download state
* and restart the MAC.
*
* Arguments:
*	hw		device structure
*	daddr		Card address to write to. (host order)
*	buf		Ptr to data to write.
*	len		Length of data (host order).
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int
hfa384x_drvr_flashdl_write(
	hfa384x_t	*hw, 
	UINT32		daddr, 
	void		*buf, 
	UINT32		len)
{
	int		result = 0;
	UINT8		*verbuf;
	UINT32		dlbufaddr;
	int		nburns;
	UINT32		burnlen;
	UINT32		burndaddr;
	UINT16		burnlo;
	UINT16		burnhi;
	int		nwrites;
	UINT8		*writebuf;
	UINT16		writepage;
	UINT16		writeoffset;
	UINT32		writelen;
	int		i;
	int		j;

	DBFENTER;
	WLAN_LOG_DEBUG(5,"daddr=0x%08lx len=%ld\n", daddr, len);

	/* Check that we're in the flash download state */
	if ( hw->dlstate != HFA384x_DLSTATE_FLASHENABLED ) {
		return -EINVAL;
	}

	WLAN_LOG_INFO("Download %ld bytes to flash @0x%06lx\n", len, daddr);

	/* Convert to flat address for arithmetic */
	/* NOTE: dlbuffer RID stores the address in AUX format */
	dlbufaddr = HFA384x_ADDR_AUX_MKFLAT(
			hw->bufinfo.page, hw->bufinfo.offset);
	WLAN_LOG_DEBUG(5,
		"dlbuf.page=0x%04x dlbuf.offset=0x%04x dlbufaddr=0x%08lx\n",
		hw->bufinfo.page, hw->bufinfo.offset, dlbufaddr);

	verbuf = kmalloc(hw->bufinfo.len, GFP_ATOMIC);

	if ( verbuf == NULL ) {
		WLAN_LOG_ERROR0("Failed to allocate flash verify buffer\n");
		return 1;
	}

#if 0
WLAN_LOG_WARNING("dlbuf@0x%06lx len=%d to=%d\n", dlbufaddr, hw->bufinfo.len, hw->dltimeout);
#endif
	/* Calculations to determine how many fills of the dlbuffer to do
	 * and how many USB wmemreq's to do for each fill.  At this point
	 * in time, the dlbuffer size and the wmemreq size are the same.
	 * Therefore, nwrites should always be 1.  The extra complexity
	 * here is a hedge against future changes.
	 */

	/* Figure out how many times to do the flash programming */
	nburns = len / hw->bufinfo.len;
	nburns += (len % hw->bufinfo.len) ? 1 : 0;

	/* For each flash program cycle, how many USB wmemreq's are needed? */
	nwrites = hw->bufinfo.len / HFA384x_USB_RWMEM_MAXLEN;
	nwrites += (hw->bufinfo.len % HFA384x_USB_RWMEM_MAXLEN) ? 1 : 0;

	/* For each burn */
	for ( i = 0; i < nburns; i++) {
		/* Get the dest address and len */
		burnlen = (len - (hw->bufinfo.len * i)) > hw->bufinfo.len ?
				hw->bufinfo.len : 
				(len - (hw->bufinfo.len * i));
		burndaddr = daddr + (hw->bufinfo.len * i);
		burnlo = HFA384x_ADDR_CMD_MKOFF(burndaddr);
		burnhi = HFA384x_ADDR_CMD_MKPAGE(burndaddr);

		WLAN_LOG_INFO("Writing %ld bytes to flash @0x%06lx\n", 
			burnlen, burndaddr);

		/* Set the download mode */
		result = hfa384x_cmd_download(hw, HFA384x_PROGMODE_NV, 
				burnlo, burnhi, burnlen);
		if ( result ) {
			WLAN_LOG_ERROR("download(NV,lo=%x,hi=%x,len=%lx) "
				"cmd failed, result=%d. Aborting d/l\n",
				burnlo, burnhi, burnlen, result);
			goto exit_proc;
		}

		/* copy the data to the flash download buffer */
		for ( j=0; j < nwrites; j++) {
			writebuf = buf + 
				(i*hw->bufinfo.len) + 
				(j*HFA384x_USB_RWMEM_MAXLEN);
			
			writepage = HFA384x_ADDR_CMD_MKPAGE(
					dlbufaddr + 
					(j*HFA384x_USB_RWMEM_MAXLEN));
			writeoffset = HFA384x_ADDR_CMD_MKOFF(
					dlbufaddr + 
					(j*HFA384x_USB_RWMEM_MAXLEN));

			writelen = burnlen-(j*HFA384x_USB_RWMEM_MAXLEN);
			writelen = writelen  > HFA384x_USB_RWMEM_MAXLEN ?
					HFA384x_USB_RWMEM_MAXLEN :
					writelen;

			result = hfa384x_dowmem( hw, DOWAIT,
					writepage, 
					writeoffset, 
					writebuf, 
					writelen, 
					NULL, NULL);
#if 0

Comment out for debugging, assume the write was successful.
			if (result) {
				WLAN_LOG_ERROR(
					"Write to dl buffer failed, "
					"result=0x%04x. Aborting.\n", 
					result);
				goto exit_proc;
			}
#endif

		}

		/* set the download 'write flash' mode */
		result = hfa384x_cmd_download(hw, 
				HFA384x_PROGMODE_NVWRITE, 
				0,0,0);
		if ( result ) {
			WLAN_LOG_ERROR(
				"download(NVWRITE,lo=%x,hi=%x,len=%lx) "
				"cmd failed, result=%d. Aborting d/l\n",
				burnlo, burnhi, burnlen, result);
			goto exit_proc;
		}

		/* TODO: We really should do a readback and compare. */
	}

exit_proc:

	/* Leave the firmware in the 'post-prog' mode.  flashdl_disable will */
	/*  actually disable programming mode.  Remember, that will cause the */
	/*  the firmware to effectively reset itself. */
	
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_getconfig
*
* Performs the sequence necessary to read a config/info item.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (host order)
*	buf		host side record buffer.  Upon return it will
*			contain the body portion of the record (minus the 
*			RID and len).
*	len		buffer length (in bytes, should match record length)
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*	-ENODATA 	length mismatch between argument and retrieved
*			record.
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_getconfig(hfa384x_t *hw, UINT16 rid, void *buf, UINT16 len)
{
	int 			result = 0;
	DBFENTER;

	result = hfa384x_dorrid(hw, DOWAIT, rid, buf, len, NULL, NULL);

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_getconfig16
*
* Performs the sequence necessary to read a 16 bit config/info item
* and convert it to host order.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (in host order)
*	val		ptr to 16 bit buffer to receive value (in host order)
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_getconfig16(hfa384x_t *hw, UINT16 rid, void *val)
{
	int		result = 0;
	DBFENTER;
	result = hfa384x_drvr_getconfig(hw, rid, val, sizeof(UINT16));
	if ( result == 0 ) {
		*((UINT16*)val) = hfa384x2host_16(*((UINT16*)val));
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_getconfig32
*
* Performs the sequence necessary to read a 32 bit config/info item
* and convert it to host order.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (in host order)
*	val		ptr to 32 bit buffer to receive value (in host order)
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_getconfig32(hfa384x_t *hw, UINT16 rid, void *val)
{
	int		result = 0;
	DBFENTER;
	result = hfa384x_drvr_getconfig(hw, rid, val, sizeof(UINT32));
	if ( result == 0 ) {
		*((UINT32*)val) = hfa384x2host_32(*((UINT32*)val));
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_getconfig_async
*
* Performs the sequence necessary to perform an async read of
* of a config/info item.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (host order)
*	buf		host side record buffer.  Upon return it will
*			contain the body portion of the record (minus the 
*			RID and len).
*	len		buffer length (in bytes, should match record length)
*	cbfn		caller supplied callback, called when the command 
*			is done (successful or not).
*	cbfndata	pointer to some caller supplied data that will be
*			passed in as an argument to the cbfn.
*
* Returns: 
*	nothing		the cbfn gets a status argument identifying if
*			any errors occur.
* Side effects:
*	Queues an hfa384x_usbcmd_t for subsequent execution.
*
* Call context:
*	Any
----------------------------------------------------------------*/
void
hfa384x_drvr_getconfig_async(
	hfa384x_t		*hw, 
	UINT16			rid, 
	ctlx_usercb_t		usercb, 
	void			*usercb_data)
{
	DBFENTER;

	hfa384x_dorrid(hw, DOASYNC, rid, NULL, 0, usercb, usercb_data);

	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_drvr_handover
*
* Sends a handover notification to the MAC.
*
* Arguments:
*	hw		device structure
*	addr		address of station that's left
*
* Returns: 
*	zero		success.
*	-ERESTARTSYS	received signal while waiting for semaphore.
*	-EIO		failed to write to bap, or failed in cmd.
*
* Side effects:
*
* Call context:
*	process
----------------------------------------------------------------*/
int hfa384x_drvr_handover( hfa384x_t *hw, UINT8 *addr)
{
        DBFENTER;
	WLAN_LOG_ERROR0("Not currently supported in USB!\n");
	DBFEXIT;
	return -EIO;
}

/*----------------------------------------------------------------
* hfa384x_drvr_low_level
*
* Write test commands to the card.  Some test commands don't make
* sense without prior set-up.  For example, continous TX isn't very
* useful until you set the channel.  That functionality should be
*
* Side effects:
*
* Call context:
*      process thread 
* -----------------------------------------------------------------*/
int hfa384x_drvr_low_level(hfa384x_t *hw, hfa384x_metacmd_t *cmd)
{
	int             result = 0;
	DBFENTER;
	
	/* Do i need a host2hfa... conversion ? */
#if 0
	printk(KERN_INFO "%#x %#x %#x %#x\n", cmd->cmd, cmd->param0, cmd->param1, cmd->param2);
#endif

#warning "WTF is this?"
	result = hfa384x_drvr_low_level(hw, cmd);

	DBFEXIT;
	return result;
}

/*----------------------------------------------------------------
* hfa384x_drvr_mmi_read
*
* Read mmi registers.  mmi is intersil-speak for the baseband
* processor registers.
*
* Arguments:
*       hw              device structure
*       register        The test register to be accessed (must be even #).
*
* Returns:
*       0               success
*       >0              f/w reported error - f/w status code
*       <0              driver reported error
*
* Side effects:
*
* Call context:
*       process
----------------------------------------------------------------*/
int hfa384x_drvr_mmi_read(hfa384x_t *hw, UINT32 addr, UINT32 *resp)
{
#if 0
        int             result = 0;
        UINT16  cmd_code = (UINT16) 0x30;
        UINT16 param = (UINT16) addr;
        DBFENTER;

        /* Do i need a host2hfa... conversion ? */
        result = hfa384x_docmd_wait(hw, cmd_code, param, 0, 0);

        DBFEXIT;
        return result;
#endif
return 0;
}

/*----------------------------------------------------------------
* hfa384x_drvr_mmi_write
*
* Read mmi registers.  mmi is intersil-speak for the baseband
* processor registers.
*
* Arguments:
*       hw              device structure
*       addr            The test register to be accessed (must be even #).
*       data            The data value to write to the register.
*
* Returns:
*       0               success
*       >0              f/w reported error - f/w status code
*       <0              driver reported error
*
* Side effects:
*
* Call context:
*       process
----------------------------------------------------------------*/

int
hfa384x_drvr_mmi_write(hfa384x_t *hw, UINT32 addr, UINT32 data)
{
#if 0
        int             result = 0;
        UINT16  cmd_code = (UINT16) 0x31;
        UINT16 param0 = (UINT16) addr;
        UINT16 param1 = (UINT16) data;
        DBFENTER;

        WLAN_LOG_DEBUG(1,"mmi write : addr = 0x%08lx\n", addr);
        WLAN_LOG_DEBUG(1,"mmi write : data = 0x%08lx\n", data);

        /* Do i need a host2hfa... conversion ? */
        result = hfa384x_docmd_wait(hw, cmd_code, param0, param1, 0);

        DBFEXIT;
        return result;
#endif
return 0;
}


/*----------------------------------------------------------------
* hfa384x_drvr_ramdl_disable
*
* Ends the ram download state.
*
* Arguments:
*	hw		device structure
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int 
hfa384x_drvr_ramdl_disable(hfa384x_t *hw)
{
	DBFENTER;
	/* Check that we're already in the download state */
	if ( hw->dlstate != HFA384x_DLSTATE_RAMENABLED ) {
		return -EINVAL;
	}

	WLAN_LOG_DEBUG0(3,"ramdl_disable()\n");

	/* There isn't much we can do at this point, so I don't */
	/*  bother  w/ the return value */
	hfa384x_cmd_download(hw, HFA384x_PROGMODE_DISABLE, 0, 0 , 0);
	hw->dlstate = HFA384x_DLSTATE_DISABLED;

	DBFEXIT;
	return 0;
}


/*----------------------------------------------------------------
* hfa384x_drvr_ramdl_enable
*
* Begins the ram download state.  Checks to see that we're not
* already in a download state and that a port isn't enabled.
* Sets the download state and calls cmd_download with the 
* ENABLE_VOLATILE subcommand and the exeaddr argument.
*
* Arguments:
*	hw		device structure
*	exeaddr		the card execution address that will be 
*                       jumped to when ramdl_disable() is called
*			(host order).
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int
hfa384x_drvr_ramdl_enable(hfa384x_t *hw, UINT32 exeaddr)
{
	int		result = 0;
	UINT16		lowaddr;
	UINT16		hiaddr;
	int		i;
	DBFENTER;
	/* Check that a port isn't active */
	for ( i = 0; i < HFA384x_PORTID_MAX; i++) {
		if ( hw->port_enabled[i] ) {
			WLAN_LOG_ERROR0(
				"Can't download with a macport enabled.\n");
			return -EINVAL; 
		}
	}

	/* Check that we're not already in a download state */
	if ( hw->dlstate != HFA384x_DLSTATE_DISABLED ) {
		WLAN_LOG_ERROR0(
			"Download state not disabled.\n");
		return -EINVAL;
	}

	WLAN_LOG_DEBUG(3,"ramdl_enable, exeaddr=0x%08lx\n", exeaddr);

	/* Call the download(1,addr) function */
	lowaddr = HFA384x_ADDR_CMD_MKOFF(exeaddr);
	hiaddr =  HFA384x_ADDR_CMD_MKPAGE(exeaddr);

	result = hfa384x_cmd_download(hw, HFA384x_PROGMODE_RAM, 
			lowaddr, hiaddr, 0);

	if ( result == 0) {
		/* Set the download state */
		hw->dlstate = HFA384x_DLSTATE_RAMENABLED;
	} else {
		WLAN_LOG_DEBUG(1,
			"cmd_download(0x%04x, 0x%04x) failed, result=%d.\n",
			lowaddr,
			hiaddr, 
			result);
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_ramdl_write
*
* Performs a RAM download of a chunk of data. First checks to see
* that we're in the RAM download state, then uses the [read|write]mem USB
* commands to 1) copy the data, 2) readback and compare.  The download
* state is unaffected.  When all data has been written using
* this function, call drvr_ramdl_disable() to end the download state
* and restart the MAC.
*
* Arguments:
*	hw		device structure
*	daddr		Card address to write to. (host order)
*	buf		Ptr to data to write.
*	len		Length of data (host order).
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int
hfa384x_drvr_ramdl_write(hfa384x_t *hw, UINT32 daddr, void* buf, UINT32 len)
{
	int		result = 0;
	int		nwrites;
	UINT8		*data = buf;
	int		i;
	UINT32		curraddr;
	UINT16		currpage;
	UINT16		curroffset;
	UINT16		currlen;
	DBFENTER;
	/* Check that we're in the ram download state */
	if ( hw->dlstate != HFA384x_DLSTATE_RAMENABLED ) {
		return -EINVAL;
	}

	WLAN_LOG_INFO("Writing %ld bytes to ram @0x%06lx\n", len, daddr);

	/* How many dowmem calls?  */
	nwrites = len / HFA384x_USB_RWMEM_MAXLEN;
	nwrites += len % HFA384x_USB_RWMEM_MAXLEN ? 1 : 0;

	/* Do blocking wmem's */
	for(i=0; i < nwrites; i++) {
		/* make address args */
		curraddr = daddr + (i * HFA384x_USB_RWMEM_MAXLEN);
		currpage = HFA384x_ADDR_CMD_MKPAGE(curraddr);
		curroffset = HFA384x_ADDR_CMD_MKOFF(curraddr);
		currlen = len - (i * HFA384x_USB_RWMEM_MAXLEN);
		if ( currlen > HFA384x_USB_RWMEM_MAXLEN) {
			currlen = HFA384x_USB_RWMEM_MAXLEN;
		}

	 	/* Do blocking ctlx */
		result = hfa384x_dowmem( hw, DOWAIT,
				currpage, 
				curroffset, 
				data + (i*HFA384x_USB_RWMEM_MAXLEN), 
				currlen, 
				NULL, NULL);

		if (result) break;

		/* TODO: We really should have a readback. */
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_readpda
*
* Performs the sequence to read the PDA space.  Note there is no
* drvr_writepda() function.  Writing a PDA is
* generally implemented by a calling component via calls to 
* cmd_download and writing to the flash download buffer via the 
* aux regs.
*
* Arguments:
*	hw		device structure
*	buf		buffer to store PDA in
*	len		buffer length
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*	-ETIMEOUT	timout waiting for the cmd regs to become
*			available, or waiting for the control reg
*			to indicate the Aux port is enabled.
*	-ENODATA	the buffer does NOT contain a valid PDA.
*			Either the card PDA is bad, or the auxdata
*			reads are giving us garbage.

*
* Side effects:
*
* Call context:
*	process or non-card interrupt.
----------------------------------------------------------------*/
int hfa384x_drvr_readpda(hfa384x_t *hw, void *buf, UINT len)
{
	int		result = 0;
	UINT16		*pda = buf;
	int		pdaok = 0;
	int		morepdrs = 1;
	int		currpdr = 0;	/* word offset of the current pdr */
	int		i;
	UINT16		pdrlen;		/* pdr length in bytes, host order */
	UINT16		pdrcode;	/* pdr code, host order */
	UINT16		currpage;
	UINT16		curroffset;
	struct pdaloc {
		UINT32	cardaddr;
		UINT16	auxctl;
	} pdaloc[] =
	{
		{ HFA3842_PDA_BASE,		0},
		{ HFA3841_PDA_BASE,		0}, 
		{ HFA3841_PDA_BOGUS_BASE,	0}
	};

	DBFENTER;

	/* Read the pda from each known address.  */
	for ( i = 0; i < (sizeof(pdaloc)/sizeof(pdaloc[0])); i++) {
		/* Make address */
		currpage = HFA384x_ADDR_CMD_MKPAGE(pdaloc[i].cardaddr);
		curroffset = HFA384x_ADDR_CMD_MKOFF(pdaloc[i].cardaddr);
	
		result = hfa384x_dormem(hw, DOWAIT,
			currpage,
			curroffset,
			buf,
			len,		/* units of bytes */
			NULL, NULL);

		if (result) {
			WLAN_LOG_WARNING(
					  "Read from index %d failed, continuing\n",
				i );
			if ( i >= (sizeof(pdaloc)/sizeof(pdaloc[0])) ){
				break;
			} else {
				continue;
			}
		}

		/* Test for garbage */
		pdaok = 1;	/* intially assume good */
		morepdrs = 1;
		while ( pdaok && morepdrs ) {
			pdrlen = hfa384x2host_16(pda[currpdr]) * 2;
			pdrcode = hfa384x2host_16(pda[currpdr+1]);
			/* Test the record length */
			if ( pdrlen > HFA384x_PDR_LEN_MAX || pdrlen == 0) {
				WLAN_LOG_ERROR("pdrlen invalid=%d\n", 
					pdrlen);
				pdaok = 0;
				break;
			}
			/* Test the code */
			if ( !hfa384x_isgood_pdrcode(pdrcode) ) {
				WLAN_LOG_ERROR("pdrcode invalid=%d\n", 
					pdrcode);
				pdaok = 0;
				break;
			}
			/* Test for completion */
			if ( pdrcode == HFA384x_PDR_END_OF_PDA) {
				morepdrs = 0;
			}
	
			/* Move to the next pdr (if necessary) */
			if ( morepdrs ) {
				/* note the access to pda[], need words here */
				currpdr += hfa384x2host_16(pda[currpdr]) + 1;
			}
		}	
		if ( pdaok ) {
			WLAN_LOG_DEBUG(2,
				"PDA Read from 0x%08lx in %s space.\n",
				pdaloc[i].cardaddr, 
				pdaloc[i].auxctl == 0 ? "EXTDS" :
				pdaloc[i].auxctl == 1 ? "NV" :
				pdaloc[i].auxctl == 2 ? "PHY" :
				pdaloc[i].auxctl == 3 ? "ICSRAM" : 
				"<bogus auxctl>");
			break;
		} 
	}
	result = pdaok ? 0 : -ENODATA;

	if ( result ) {
		WLAN_LOG_DEBUG0(3,"Failure: pda is not okay\n");
	}

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_setconfig
*
* Performs the sequence necessary to write a config/info item.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (in host order)
*	buf		host side record buffer
*	len		buffer length (in bytes)
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_setconfig(hfa384x_t *hw, UINT16 rid, void *buf, UINT16 len)
{
	int 		result = 0;
	DBFENTER;

	result = hfa384x_dowrid(hw, DOWAIT, rid, buf, len, NULL, NULL);

	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_setconfig16
*
* Performs the sequence necessary to write a 16 bit config/info item.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (in host order)
*	val		16 bit value to store (in host order)
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_setconfig16(hfa384x_t *hw, UINT16 rid, UINT16 *val)
{
	int	result;
	UINT16	value;

	DBFENTER;

	value = host2hfa384x_16(*val);
	result = hfa384x_drvr_setconfig(hw, rid, &value, sizeof(UINT16));

	DBFEXIT;

	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_setconfig32
*
* Performs the sequence necessary to write a 32 bit config/info item.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (in host order)
*	val		32 bit value to store (in host order)
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_setconfig32(hfa384x_t *hw, UINT16 rid, UINT32 *val)
{
	int	result;
	UINT32	value;

	DBFENTER;

	value = host2hfa384x_32(*val);
	result = hfa384x_drvr_setconfig(hw, rid, &value, sizeof(UINT32));

	DBFEXIT;

	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_setconfig_async
*
* Performs the sequence necessary to write a config/info item.
*
* Arguments:
*	hw		device structure
*	rid		config/info record id (in host order)
*	buf		host side record buffer
*	len		buffer length (in bytes)
*	usercb		completion callback
*	usercb_data	completion callback argument
*
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
void
hfa384x_drvr_setconfig_async(
	hfa384x_t	*hw,
	UINT16		rid,
	void		*buf,
	UINT16		len,
	ctlx_usercb_t	usercb,
	void		*usercb_data)
{
	int 		result = 0;
	DBFENTER;
	
	result = hfa384x_dowrid(hw, 
			DOASYNC, rid, buf, len, usercb, usercb_data);

	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_drvr_start
*
* Issues the MAC initialize command, sets up some data structures,
* and enables the interrupts.  After this function completes, the
* low-level stuff should be ready for any/all commands.
*
* Arguments:
*	hw		device structure
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int hfa384x_drvr_start(hfa384x_t *hw)
{
	int	result = 0;
	DBFENTER;

	if (usb_clear_halt(hw->usb, usb_rcvbulkpipe(hw->usb, hw->endp_in))) {
		WLAN_LOG_ERROR0(
			"Failed to reset bulk in endpoint.\n");
	}

	if (usb_clear_halt(hw->usb, usb_sndbulkpipe(hw->usb, hw->endp_out))) {
		WLAN_LOG_ERROR0(
			"Failed to reset bulk out endpoint.\n");
	}

	/* Post the IN urb */
	if (!hw->rxurb_posted) {
		/* Post the rx urb */
		FILL_BULK_URB(&hw->rx_urb, hw->usb, 
				usb_rcvbulkpipe(hw->usb, hw->endp_in),
				&hw->rxbuff, sizeof(hw->rxbuff),
				hfa384x_usbin_callback, hw->usbcontext);
		hw->rx_urb.transfer_flags |= USB_ASYNC_UNLINK;

		if ((result = usb_submit_urb(&hw->rx_urb))) {
			WLAN_LOG_ERROR(
				"Fatal, usb_submit_urb() failed, result=%d\n",
				result);
			goto done;
		}
		hw->rxurb_posted = 1;
	}

	/* call initialize */
	result = hfa384x_cmd_initialize(hw);
	if (result != 0) {
		usb_unlink_urb(&hw->rx_urb);
		hw->rxurb_posted = 0;
		WLAN_LOG_ERROR(
			"cmd_initialize() failed, result=%d\n",
			result);
		goto done;
	}

	hw->state = HFA384x_STATE_RUNNING;
	
done:
	DBFEXIT;
	return result;
}


/*----------------------------------------------------------------
* hfa384x_drvr_stop
*
* Shuts down the MAC to the point where it is safe to unload the
* driver.  Any subsystem that may be holding a data or function
* ptr into the driver must be cleared/deinitialized.
*
* Arguments:
*	hw		device structure
* Returns: 
*	0		success
*	>0		f/w reported error - f/w status code
*	<0		driver reported error
*
* Side effects:
*
* Call context:
*	process 
----------------------------------------------------------------*/
int
hfa384x_drvr_stop(hfa384x_t *hw)
{
	int	result = 0;
	int	i;
	DBFENTER;

#ifdef DECLARE_TASKLET
	tasklet_kill(&hw->link_bh);
#else
#warning "We aren't cleaning up the link_bh cleanly!"
#endif

	/* Call initialize to leave the MAC in its 'reset' state */
	hfa384x_cmd_initialize(hw);

	/* Clear all the port status */
	hw->state = HFA384x_STATE_INIT;
	for ( i = 0; i < HFA384x_NUMPORTS_MAX; i++) {
		hw->port_enabled[i] = 0;
	}

	wait_ms(100);

	/* Cancel the rxurb */
	if (hw->rxurb_posted) {
		usb_unlink_urb(&hw->rx_urb);
		hw->rxurb_posted = 0;
	}

	/* TODO: Make sure there aren't any layabout tx urbs or ctlx urbs 
	 *       for now, we assume there aren't.
	 * XXXXX fixme?
	 * MFK: that's apparently what's causing panic on hot-unplug...
	 */
	DBFEXIT;
	return result;
}

/*----------------------------------------------------------------
* hfa384x_drvr_txframe
*
* Takes a frame from prism2sta and queues it for transmission.
*
* Arguments:
*	hw		device structure
*	skb		packet buffer struct.  Contains an 802.11
*			data frame.
*       p80211_hdr      points to the 802.11 header for the packet.
* Returns: 
*	0		Success and more buffs available
*	1		Success but no more buffs
*	2		Allocation failure
*	4		Buffer full or queue busy
*
* Side effects:
*
* Call context:
*	process
----------------------------------------------------------------*/
int hfa384x_drvr_txframe(hfa384x_t *hw, struct sk_buff *skb, p80211_hdr_t *p80211_hdr, p80211_metawep_t *p80211_wep)

{
	int			usbpktlen = sizeof(hfa384x_tx_frame_t);
	int			result = 0;
	char                    *ptr;
	DBFENTER;

#if 0
	if (hw->usbflags & HFA384x_USBFLAG_TXURB_BUSY) {
		WLAN_LOG_ERROR0(
			"txframe() called w/ txurb busy, this is bad.\n");
		return 1;
	}
	hw->usbflags |= HFA384x_USBFLAG_TXURB_BUSY;
#endif

	/* Build Tx frame structure */
	/* Set up the control field */
	memset(&hw->txbuff.txfrm.desc, 0, sizeof(hw->txbuff.txfrm.desc));

	/* Setup the usb type field */
	hw->txbuff.type = host2hfa384x_16(HFA384x_USB_TXFRM);

	/* Set up the sw_support field to identify this frame */
	hw->txbuff.txfrm.desc.sw_support = host2hfa384x_32(0x0123);

/* Tx complete and Tx exception disable per dleach.  Might be causing 
 * buf depletion 
 * XXXX fixme?
 * MFK: on USB, it will also eat up the USB bus bandwidth...
 */
#if 0		
	hw->txbuff.txfrm.desc.tx_control = 
		HFA384x_TX_MACPORT_SET(0) | HFA384x_TX_STRUCTYPE_SET(1) | 
		HFA384x_TX_TXEX_SET(1) | HFA384x_TX_TXOK_SET(1);	
#else
	hw->txbuff.txfrm.desc.tx_control = 
		HFA384x_TX_MACPORT_SET(0) | HFA384x_TX_STRUCTYPE_SET(1) |
		HFA384x_TX_TXEX_SET(0) | HFA384x_TX_TXOK_SET(0);	
#endif

	hw->txbuff.txfrm.desc.tx_control = 
		host2hfa384x_16(hw->txbuff.txfrm.desc.tx_control);

	/* copy the header over to the txdesc */
	memcpy(&(hw->txbuff.txfrm.desc.frame_control), p80211_hdr, sizeof(p80211_hdr_t));

	/* if we're using host WEP, increase size by IV+ICV */
	if (p80211_wep->data) {
		hw->txbuff.txfrm.desc.data_len = host2hfa384x_16(skb->len+8);
		// hw->txbuff.txfrm.desc.tx_control |= HFA384x_TX_NOENCRYPT_SET(1);
		usbpktlen+=8;
	} else {
		hw->txbuff.txfrm.desc.data_len = host2hfa384x_16(skb->len);
	}

	usbpktlen += skb->len;

	/* copy over the WEP IV if we are using host WEP */
	ptr = hw->txbuff.txfrm.data;
	if (p80211_wep->data) {
		memcpy(ptr, p80211_wep->iv, sizeof(p80211_wep->iv));
		ptr+= sizeof(p80211_wep->iv);
		memcpy(ptr, p80211_wep->data, skb->len);
	} else {
		memcpy(ptr, skb->data, skb->len);
	}
	/* copy over the packet data */
	ptr+= skb->len;

	/* copy over the WEP ICV if we are using host WEP */
	if (p80211_wep->data) {
		memcpy(ptr, p80211_wep->icv, sizeof(p80211_wep->icv));
	}

	/* Send the USB packet */	
	FILL_BULK_URB( &(hw->tx_urb), hw->usb,
		usb_sndbulkpipe(hw->usb, hw->endp_out),
		&(hw->txbuff), ROUNDUP64(usbpktlen),
		hfa384x_usbout_callback, hw->usbcontext);
	hw->tx_urb.transfer_flags |= USB_QUEUE_BULK;

	if ( (result = usb_submit_urb(&hw->tx_urb)) ) {
		WLAN_LOG_ERROR(
			"submit_urb() failed, result=%d\n", result);
#if 0
		hw->usbflags &= ~HFA384x_USBFLAG_TXURB_BUSY;
#endif
		result = 1;
	}
	result = 1;

	DBFEXIT;
	return result;
}

/*----------------------------------------------------------------
* hfa384x_rx_typedrop
*
* Classifies the frame, increments the appropriate counter, and
* returns 0|1 indicating whether the driver should handle or
* drop the frame
*
* Arguments:
*	wlandev		wlan device structure
*	fc		frame control field
*
* Returns: 
*	zero if the frame should be handled by the driver,
*	non-zero otherwise.
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
int 
hfa384x_rx_typedrop( wlandevice_t *wlandev, UINT16 fc)
{
	UINT16	ftype;
	UINT16	fstype;
	int	drop = 0;
	/* Classify frame, increment counter */
	ftype = WLAN_GET_FC_FTYPE(fc);
	fstype = WLAN_GET_FC_FSTYPE(fc);
#if 0
	WLAN_LOG_DEBUG(4, 
		"rx_typedrop : ftype=%d fstype=%d.\n", ftype, fstype);
#endif
	switch ( ftype ) {
	case WLAN_FTYPE_MGMT:
		if ((wlandev->netdev->flags & IFF_PROMISC) ||
			(wlandev->netdev->flags & IFF_ALLMULTI)) {
			drop = 1;
			break;
		}
		WLAN_LOG_DEBUG0(3, "prism2sta_ev_rx(): rx'd mgmt:\n");
		wlandev->rx.mgmt++;
		switch( fstype ) {
		case WLAN_FSTYPE_ASSOCREQ:
			/* printk("assocreq"); */
			wlandev->rx.assocreq++;
			break;
		case WLAN_FSTYPE_ASSOCRESP:
			/* printk("assocresp"); */
			wlandev->rx.assocresp++;
			break;
		case WLAN_FSTYPE_REASSOCREQ:
			/* printk("reassocreq"); */
			wlandev->rx.reassocreq++;
			break;
		case WLAN_FSTYPE_REASSOCRESP:
			/* printk("reassocresp"); */
			wlandev->rx.reassocresp++;
			break;
		case WLAN_FSTYPE_PROBEREQ:
			/* printk("probereq"); */
			wlandev->rx.probereq++;
			break;
		case WLAN_FSTYPE_PROBERESP:
			/* printk("proberesp"); */
			wlandev->rx.proberesp++;
			break;
		case WLAN_FSTYPE_BEACON:
			/* printk("beacon"); */
			wlandev->rx.beacon++;
			break;
		case WLAN_FSTYPE_ATIM:
			/* printk("atim"); */
			wlandev->rx.atim++;
			break;
		case WLAN_FSTYPE_DISASSOC:
			/* printk("disassoc"); */
			wlandev->rx.disassoc++;
			break;
		case WLAN_FSTYPE_AUTHEN:
			/* printk("authen"); */
			wlandev->rx.authen++;
			break;
		case WLAN_FSTYPE_DEAUTHEN:
			/* printk("deauthen"); */
			wlandev->rx.deauthen++;
			break;
		default:
			/* printk("unknown"); */
			wlandev->rx.mgmt_unknown++;
			break;
		}
		/* printk("\n"); */
		drop = 2;
		break;

	case WLAN_FTYPE_CTL:
		if ((wlandev->netdev->flags & IFF_PROMISC) ||
			(wlandev->netdev->flags & IFF_ALLMULTI)) {
			drop = 1;
			break;
		}
		WLAN_LOG_DEBUG0(3, "prism2sta_ev_rx(): rx'd ctl:\n");
		wlandev->rx.ctl++;
		switch( fstype ) {
		case WLAN_FSTYPE_PSPOLL:
			/* printk("pspoll"); */
			wlandev->rx.pspoll++;
			break;
		case WLAN_FSTYPE_RTS:
			/* printk("rts"); */
			wlandev->rx.rts++;
			break;
		case WLAN_FSTYPE_CTS:
			/* printk("cts"); */
			wlandev->rx.cts++;
			break;
		case WLAN_FSTYPE_ACK:
			/* printk("ack"); */
			wlandev->rx.ack++;
			break;
		case WLAN_FSTYPE_CFEND:
			/* printk("cfend"); */
			wlandev->rx.cfend++;
			break;
		case WLAN_FSTYPE_CFENDCFACK:
			/* printk("cfendcfack"); */
			wlandev->rx.cfendcfack++;
			break;
		default:
			/* printk("unknown"); */
			wlandev->rx.ctl_unknown++;
			break;
		}
		/* printk("\n"); */
		drop = 2;
		break;

	case WLAN_FTYPE_DATA:
		wlandev->rx.data++;
		switch( fstype ) {
		case WLAN_FSTYPE_DATAONLY:
			wlandev->rx.dataonly++;
			break;
		case WLAN_FSTYPE_DATA_CFACK:
			wlandev->rx.data_cfack++;
			break;
		case WLAN_FSTYPE_DATA_CFPOLL:
			wlandev->rx.data_cfpoll++;
			break;
		case WLAN_FSTYPE_DATA_CFACK_CFPOLL:
			wlandev->rx.data__cfack_cfpoll++;
			break;
		case WLAN_FSTYPE_NULL:
			WLAN_LOG_DEBUG0(3, "prism2sta_ev_rx(): rx'd data:null\n");
			wlandev->rx.null++;
			break;
		case WLAN_FSTYPE_CFACK:
			WLAN_LOG_DEBUG0(3, "prism2sta_ev_rx(): rx'd data:cfack\n");
			wlandev->rx.cfack++;
			break;
		case WLAN_FSTYPE_CFPOLL:
			WLAN_LOG_DEBUG0(3, "prism2sta_ev_rx(): rx'd data:cfpoll\n");
			wlandev->rx.cfpoll++;
			break;
		case WLAN_FSTYPE_CFACK_CFPOLL:
			WLAN_LOG_DEBUG0(3, "prism2sta_ev_rx(): rx'd data:cfack_cfpoll\n");
			wlandev->rx.cfack_cfpoll++;
			break;
		default:
			/* printk("unknown"); */
			wlandev->rx.data_unknown++;
			break;
		}

		break;
	}
	return drop;
}


/*----------------------------------------------------------------
* hfa384x_usbctlx_complete
*
* A CTLX has completed.  It may have been successful, it may not
* have been. At this point, the CTLX should be quiescent.  The URBs
* aren't active and the timers should have been stopped.
*
* Arguments:
*	ctlx		ptr to a ctlx structure
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	Either, assume interrupt
----------------------------------------------------------------*/
void hfa384x_usbctlx_complete(hfa384x_usbctlx_t *ctlx)
{
	wlandevice_t		*wlandev = ctlx->outurb.context;
	prism2sta_priv_t	*priv = wlandev->priv;
	hfa384x_t		*hw = priv->hw;

	DBFENTER;

	if (hw->hwremoved)
		return;

	/* Timers have been stopped, and ctlx should be in 
	 * a terminal state.
	 */
	/* Dequeue the ctlx and run the queue */
	hfa384x_usbctlxq_dequeue(&hw->ctlxq);
	hfa384x_usbctlxq_run(&hw->ctlxq);

 	/* Handling depends on state */
	switch(ctlx->state) {
	case HFA384x_USBCTLX_COMPLETE:
	case HFA384x_USBCTLX_REQSUBMIT_FAIL:
	case HFA384x_USBCTLX_REQ_FAILED:
	case HFA384x_USBCTLX_REQ_TIMEOUT:
	case HFA384x_USBCTLX_RESP_TIMEOUT:
	/* Handle correct state completion
	 * Actual error handling is deferred to the awakened
	 *  sleeper or the hfa384x_cbXXX() functions 
	 */
	if ( ! ctlx->is_async ) {
		ctlx->wanna_wakeup = 1;
		wake_up_interruptible(&hw->cmdq);
	} else {
		switch(hfa384x2host_16(ctlx->outbuf.type)) {
		case HFA384x_USB_CMDREQ:
			hfa384x_cbcmd(hw, ctlx);
			break;
		case HFA384x_USB_WRIDREQ:
			hfa384x_cbwrid(hw, ctlx);
			break;
		case HFA384x_USB_RRIDREQ:
			hfa384x_cbrrid(hw, ctlx);
			break;
		case HFA384x_USB_WMEMREQ:
			hfa384x_cbwmem(hw, ctlx);
			break;
		case HFA384x_USB_RMEMREQ:
			hfa384x_cbrmem(hw, ctlx);
			break;
		default:
			WLAN_LOG_ERROR(
				"unknown reqtype=%d, ignored.\n", 
				ctlx->outbuf.type);
			kfree(ctlx);
			break;
		}
	}
	break;

	case HFA384x_USBCTLX_REQ_SUBMITTED:
	case HFA384x_USBCTLX_REQ_COMPLETE:
	case HFA384x_USBCTLX_START:
	case HFA384x_USBCTLX_QUEUED:
	case HFA384x_USBCTLX_RESP_RECEIVED:
		WLAN_LOG_ERROR0("Called, CTLX not in terminating state.\n");
		/* Things are really bad if this happens. Just leak
		 * the CTLX because it may still be linked to the 
		 * queue or the OUT urb may still be active.
		 * Just leaking at least prevents an Oops or Panic.
		 */
		goto done;
		break;
	}

done:
	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_usbctlxq_dequeue
*
* Removes the head item from the usb control exchange (CTLX) queue.
*
* Arguments:
*	ctlxq		queue structure.
*
* Returns: 
*	NULL if queue empty, ptr to old head item otherwise.
*
* Side effects:
*
* Call context:
*	any
----------------------------------------------------------------*/
hfa384x_usbctlx_t*
hfa384x_usbctlxq_dequeue(hfa384x_usbctlxq_t *ctlxq)
{
	unsigned long		flags;
	hfa384x_usbctlx_t	*ctlx;
	DBFENTER;
	
	/* acquire lock */
	spin_lock_irqsave(&ctlxq->lock, flags);

	/* Remove head item from list */
	ctlx = ctlxq->head;
	if (ctlx != NULL ) {
		ctlxq->head = ctlx->next;
		if (ctlxq->head == NULL ) {
			ctlxq->tail = NULL;
		} else {
			ctlxq->head->prev = NULL;
		}
		ctlx->prev = ctlx->next = NULL;
	}

	/* release lock */
	spin_unlock_irqrestore(&ctlxq->lock, flags);

	/* return the old head */
	DBFEXIT;
	return ctlx;
}


/*----------------------------------------------------------------
* hfa384x_usbctlxq_enqueue_run
*
* Adds a new item to the queue and makes sure there's an item 
* running.
*
* Arguments:
*	ctlxq		queue structure.
*	cmd		new command
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	any
----------------------------------------------------------------*/
void 
hfa384x_usbctlxq_enqueue_run(
	hfa384x_usbctlxq_t	*ctlxq, 
	hfa384x_usbctlx_t	*ctlx)
{
	unsigned long		flags;
	DBFENTER;

	/* acquire lock */
	spin_lock_irqsave(&ctlxq->lock, flags);

	/* Add item to the list */
	ctlx->next = NULL;	
	ctlx->prev = ctlxq->tail;
	ctlxq->tail = ctlx;
	if (ctlx->prev) {
		ctlx->prev->next = ctlx;
	} else {
		ctlxq->head = ctlx;
	}

	/* Set state to QUEUED */
	ctlx->state = HFA384x_USBCTLX_QUEUED;

	/* release lock */
	spin_unlock_irqrestore(&ctlxq->lock, flags);

	hfa384x_usbctlxq_run(ctlxq);

	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_usbctlxq_run
*
* Checks to see if the head item is running.  If not, starts it.
*
* Arguments:
*	ctlxq		queue structure.
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	any
----------------------------------------------------------------*/
void
hfa384x_usbctlxq_run(
	hfa384x_usbctlxq_t	*ctlxq)
{
	unsigned long		flags;
	int			result;
	hfa384x_usbctlx_t       *head;
	DBFENTER;

	/* acquire lock */
	spin_lock_irqsave(&ctlxq->lock, flags);

	/* we need to split this off to avoid a race condition */
	head = ctlxq->head;

	/* Run the queue: If head in non-running state, submit urb, and 
	 * set state to REQ_SUBMITTED.
	 */
	if (head != NULL && 
	    head->state == HFA384x_USBCTLX_QUEUED) {
		result = usb_submit_urb(&head->outurb);
		if (result) {
			WLAN_LOG_ERROR(
			"Fatal, failed to submit command urb. error=%d\n",
			result);
			head->state = HFA384x_USBCTLX_REQSUBMIT_FAIL;

			/* release lock */
			spin_unlock_irqrestore(&ctlxq->lock, flags);
			hfa384x_usbctlx_complete(head);
			goto done;
		}

		head->state = HFA384x_USBCTLX_REQ_SUBMITTED;

		/* Start the IN wait timer */
		init_timer(&head->resptimer);
		head->resptimer.function = 
			hfa384x_usbctlx_resptimerfn;
		head->resptimer.data = 
			(unsigned long)head;
		head->resptimer.expires = jiffies + 2*HZ;
		add_timer(&head->resptimer);

		/* Start the OUT wait timer */
		init_timer(&head->reqtimer);
		head->reqtimer.function = 
			hfa384x_usbctlx_reqtimerfn;
		head->reqtimer.data = 
			(unsigned long)head;
		head->reqtimer.expires = jiffies + HZ;
		add_timer(&head->reqtimer);
	}

	/* release lock */
	spin_unlock_irqrestore(&ctlxq->lock, flags);

	done:
	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_usbin_callback
*
* Callback for urb's on the BULKIN endpoint.
*
* Arguments:
*	urb		ptr to the completed urb
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void hfa384x_usbin_callback(struct urb *urb)
{
	
	wlandevice_t		*wlandev = urb->context;
	prism2sta_priv_t	*priv = wlandev->priv;
	hfa384x_t		*hw = priv->hw;
	hfa384x_usbin_t		*usbin = urb->transfer_buffer;
	int			result;
	UINT16			type;

	DBFENTER;

	if (hw->hwremoved)
		return;

	/* Check for and handle error conditions */
	switch (urb->status) {
	case 0:
		goto handle;
		break;
	case -EPIPE:
		WLAN_LOG_DEBUG0(3,
			"status=-EPIPE, assuming stall, try to clear\n");
		/* XXXX FIXME */
#if 0 /* usb_clear_halt cannot be called from interrupt context, it blocks */
		if (usb_clear_halt(hw->usb, usb_rcvbulkpipe(hw->usb, hw->endp_in))) {
			WLAN_LOG_DEBUG0(3,"usb_clear_halt() failed.\n");
		}
#endif
		goto resubmit;
		break;
	case -EILSEQ:
	case -ENODEV:
		WLAN_LOG_DEBUG(3,"status=%d, device removed.\n", urb->status);
		return;
		break;
	case -ENOENT:
		WLAN_LOG_DEBUG(3,"status=%d, urb explicitly unlinked.\n", urb->status);
		return;
		break;
	default:
		WLAN_LOG_DEBUG(3,"urb errstatus=%d\n", urb->status);
		goto resubmit;
		break;
	}

handle:	
	/* Check for short packet */
	if ( urb->actual_length == 0 ) {
		goto resubmit;
	}

	/* Handle a successful usbin packet */
	/* Note: the check of the sw_support field, the type field doesn't 
	 *       have bit 12 set like the docs suggest. 
	 * Note2: The txframe function is not currently setting the TxCompl
	 *        or TxExc bits so we should never get TXFRM type IN URBs.
	 */
	type = hfa384x2host_16(usbin->type);
	if (HFA384x_USB_ISTXFRM(type) || 
		usbin->txfrm.desc.sw_support == host2hfa384x_32(0x0123)) {
		hfa384x_usbin_txcompl(wlandev, usbin);
		goto resubmit;
	}
	if (HFA384x_USB_ISRXFRM(type)) {
		hfa384x_usbin_rx(wlandev, usbin);
		goto resubmit;
	}

	switch (type) {
	case HFA384x_USB_INFOFRM:
		hfa384x_usbin_info(wlandev, usbin);
		goto resubmit;
		break;
	case HFA384x_USB_CMDRESP:
	case HFA384x_USB_WRIDRESP:
	case HFA384x_USB_RRIDRESP:
	case HFA384x_USB_WMEMRESP:
	case HFA384x_USB_RMEMRESP:
		hfa384x_usbin_ctlx(wlandev, urb);
		goto resubmit;
		break;
	case HFA384x_USB_BUFAVAIL:
		WLAN_LOG_DEBUG(3,"Received BUFAVAIL packet, frmlen=%d\n",
			usbin->bufavail.frmlen);
		goto resubmit;
		break;
	case HFA384x_USB_ERROR:
		WLAN_LOG_DEBUG(3,"Received USB_ERROR packet, errortype=%d\n",
			usbin->usberror.errortype);
		goto resubmit;
		break;
	default:
		WLAN_LOG_DEBUG(3,"Unrecognized USBIN packet, type=%x\n", 
			usbin->type);
		goto resubmit;
	}

resubmit:
	FILL_BULK_URB( &(hw->rx_urb), hw->usb, 
		usb_rcvbulkpipe(hw->usb, hw->endp_in),
		&(hw->rxbuff), sizeof(hw->rxbuff),
		hfa384x_usbin_callback, hw->usbcontext);

	if ((result = usb_submit_urb(&(hw->rx_urb)))) {
		WLAN_LOG_ERROR(
			"Fatal, failed to resubmit rx_urb. error=%d\n",
			result);
		goto exit;
	}

exit:
	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_usbin_ctlx
*
* We've received a URB containing a Prism2 "response" message.
* This message needs to be matched up with the head of the queue
* and our state updated accordingly.
*
* Arguments:
*	wlandev		wlan device
*	urb		ptr to the URB
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void hfa384x_usbin_ctlx(wlandevice_t *wlandev, struct urb *urb)
{
	prism2sta_priv_t	*priv = wlandev->priv;
	hfa384x_t		*hw = priv->hw;
	hfa384x_usbin_t		*usbin = urb->transfer_buffer;
	hfa384x_usbctlx_t	*ctlx;

	DBFENTER;

	if (hw->hwremoved)
		return;

	ctlx = hw->ctlxq.head;

	/* If the queue is empty or type doesn't match head ctlx */
	if ( ctlx == NULL || 
	     ctlx->outbuf.type != (usbin->type&~host2hfa384x_16(0x8000)) ) {
		/* else, type doesn't match */
		/* ignore it */
		WLAN_LOG_WARNING0(
			"Failed to match IN URB w/ head CTLX\n");
		hfa384x_usbctlxq_run(&hw->ctlxq);
		goto done;
	}

	WLAN_LOG_DEBUG0(4,"Matched usbin w/ ctlxq->head\n");


	switch ( ctlx->state ) {
	case HFA384x_USBCTLX_REQ_SUBMITTED:
		/* Stop the intimer */
		del_timer(&ctlx->resptimer);

		/* Set the state to CTLX_RESP_RECEIVED */
		ctlx->state = HFA384x_USBCTLX_RESP_RECEIVED;

		/* Copy the URB and buffer to ctlx */
		memcpy(&ctlx->inurb, urb, sizeof(*urb));
		memcpy(&ctlx->inbuf, usbin, sizeof(*usbin));

		/* Let the machine continue running. */
		break;

	case HFA384x_USBCTLX_REQ_COMPLETE:
		/* Stop the intimer */
		del_timer(&ctlx->resptimer);

		/* Set the state to CTLX_COMPLETE */
		ctlx->state = HFA384x_USBCTLX_COMPLETE;

		/* Copy the URB and buffer to ctlx */
		memcpy(&ctlx->inurb, urb, sizeof(*urb));
		memcpy(&ctlx->inbuf, usbin, sizeof(*usbin));

		/* Call the completion handler */
		hfa384x_usbctlx_complete(ctlx);
		break;

	case HFA384x_USBCTLX_START:
	case HFA384x_USBCTLX_QUEUED:
	case HFA384x_USBCTLX_RESP_RECEIVED:
	case HFA384x_USBCTLX_REQ_TIMEOUT:
	case HFA384x_USBCTLX_REQ_FAILED:
	case HFA384x_USBCTLX_RESP_TIMEOUT:
	case HFA384x_USBCTLX_REQSUBMIT_FAIL:
	case HFA384x_USBCTLX_COMPLETE:
		WLAN_LOG_WARNING0(
			"Matched IN URB, CTLX in invalid state. "
			"Ignored.\n");
		hfa384x_usbctlxq_run(&hw->ctlxq);
		goto done;
		break;
	}

done:
	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_usbin_txcompl
*
* At this point we have the results of a previous transmit.
* NOTE: At this point in time, it appears the USB devices doesn't
*       like giving txcompletes so we have them turned off.  Hence,
*       this function isn't currently being called.
*
* Arguments:
*	wlandev		wlan device
*	usbin		ptr to the usb transfer buffer
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void hfa384x_usbin_txcompl(wlandevice_t *wlandev, hfa384x_usbin_t *usbin)
{
	UINT16			status;
	DBFENTER;

	/* Clear the sw_support field so a subsequent short packet doesn't
	 * fool us.
	 */
	usbin->txfrm.desc.sw_support = 0;


	status = hfa384x2host_16(usbin->type); /* yeah I know it says type...*/

	/* Was there an error? */
	if (HFA384x_TXSTATUS_ISERROR(status)) {
		prism2sta_ev_txexc(wlandev, status);
	} else {
		prism2sta_ev_tx(wlandev, status);
	}
	prism2sta_ev_alloc(wlandev);

	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_usbin_rx
*
* At this point we have a successful received a rx frame packet.
*
* Arguments:
*	wlandev		wlan device
*	usbin		ptr to the usb transfer buffer
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void hfa384x_usbin_rx(wlandevice_t *wlandev, hfa384x_usbin_t *usbin)
{
	int			result;
	p80211_hdr_t            *w_hdr;
	struct sk_buff          *skb = NULL;
	int                     hdrlen;
	UINT16                  fc;
	UINT8 *datap;

	DBFENTER;

	/* Byte order convert once up front. */
	usbin->rxfrm.desc.status =
		hfa384x2host_16(usbin->rxfrm.desc.status);
	usbin->rxfrm.desc.time =
		hfa384x2host_32(usbin->rxfrm.desc.time);

	/* Now handle frame based on port# */
        switch( HFA384x_RXSTATUS_MACPORT_GET(usbin->rxfrm.desc.status))
        {
	case 0:
		w_hdr = (p80211_hdr_t *) &(usbin->rxfrm.desc.frame_control);

		/* see if we should drop or ignore the frame */
		result = hfa384x_rx_typedrop(wlandev, ieee2host16(usbin->rxfrm.desc.frame_control));
		if (result) {
			if (result != 1) 
				WLAN_LOG_WARNING("Invalid frame type, fc=%04x, dropped.\n",w_hdr->a3.fc);
			
			goto done;
		}

		/* If exclude and we receive an unencrypted, drop it */
		if ( (wlandev->hostwep & HOSTWEP_EXCLUDEUNENCRYPTED) &&
		     !WLAN_GET_FC_ISWEP(ieee2host16(w_hdr->a3.fc))){
			goto done;
		}

                /* perform mcast filtering */
		/* TODO:  real hardware mcast filters */
		if (wlandev->netdev->flags & IFF_ALLMULTI) {
			UINT8 *daddr = usbin->rxfrm.desc.address1;
			/* allow my local address through */ 
			if (memcmp(daddr, wlandev->netdev->dev_addr, WLAN_ADDR_LEN) != 0) {
				/* but reject anything else that isn't multicast */
				if (!(daddr[0] & 0x01))
					goto done; 
			}
		}

		fc = ieee2host16(usbin->rxfrm.desc.frame_control);
		if ( WLAN_GET_FC_TODS(fc) && WLAN_GET_FC_FROMDS(fc) ) {
			hdrlen = WLAN_HDR_A4_LEN;
		} else {
			hdrlen = WLAN_HDR_A3_LEN;
		}

		/* Allocate the buffer, note CRC (aka FCS). pballoc */
		/* assumes there needs to be space for one */
		skb = dev_alloc_skb(hfa384x2host_16(usbin->rxfrm.desc.data_len) + hdrlen + WLAN_CRC_LEN + 2); /* a litlte extra */

		if ( ! skb ) {
			WLAN_LOG_DEBUG0(1, "alloc_skb failed.\n");
			goto done;
                }

		skb->dev = wlandev->netdev;
		skb->dev->last_rx = jiffies;

		/* theoretically align the IP header on a 32-bit word. */
		if ( hdrlen == WLAN_HDR_A3_LEN )
			skb_reserve(skb, 2);

		/* Copy the 802.11 hdr to the buffer */
		datap = skb_put(skb, WLAN_HDR_A3_LEN);
		memcpy(datap, w_hdr, WLAN_HDR_A3_LEN);

		/* Snag the A4 address if present */
		if (hdrlen == WLAN_HDR_A4_LEN) {
			datap = skb_put(skb, WLAN_ADDR_LEN);
			memcpy(datap, &usbin->rxfrm.desc.address4, WLAN_HDR_A3_LEN);
		}

		/* we can convert the data_len as we passed the original on */
		usbin->rxfrm.desc.data_len = hfa384x2host_16(usbin->rxfrm.desc.data_len);

		/* Copy the payload data to the buffer */
		if ( usbin->rxfrm.desc.data_len > 0 ) {
			datap = skb_put(skb, usbin->rxfrm.desc.data_len);
			memcpy(datap, &(usbin->rxfrm.data),  
				usbin->rxfrm.desc.data_len);
		}

		/* the prism2 series does not return the CRC */
		datap = skb_put(skb, WLAN_CRC_LEN);
		memset (datap, 0xff, WLAN_CRC_LEN);
		skb->mac.raw = skb->data;

		prism2sta_ev_rx(wlandev, skb);

		break;

	case 7:
        	if ( ! HFA384x_RXSTATUS_ISFCSERR(usbin->rxfrm.desc.status) ) {
                        /* Copy to wlansnif skb */
                        hfa384x_int_rxmonitor( wlandev, &usbin->rxfrm);
                } else {
                        WLAN_LOG_DEBUG0(3,"Received monitor frame: FCSerr set\n");
                }
                break;

	default:
		WLAN_LOG_WARNING("Received frame on unsupported port=%d\n",
			HFA384x_RXSTATUS_MACPORT_GET(usbin->rxfrm.desc.status) );
		goto done;
		break;
	}
	
done:
	DBFEXIT;
	return;
}

/*----------------------------------------------------------------
* hfa384x_int_rxmonitor
*
* Helper function for int_rx.  Handles monitor frames.
* Note that this function allocates space for the FCS and sets it
* to 0xffffffff.  The hfa384x doesn't give us the FCS value but the
* higher layers expect it.  0xffffffff is used as a flag to indicate
* the FCS is bogus.
*
* Arguments:
*	wlandev		wlan device structure
*	rxfrm		rx descriptor read from card in int_rx
*
* Returns: 
*	nothing
*
* Side effects:
*	Allocates an skb and passes it up via the PF_PACKET interface.
* Call context:
*	interrupt
----------------------------------------------------------------*/
static void hfa384x_int_rxmonitor( wlandevice_t *wlandev, hfa384x_usb_rxfrm_t *rxfrm)
{
	hfa384x_rx_frame_t              *rxdesc = &(rxfrm->desc);
	UINT				hdrlen = 0;
	UINT				datalen = 0;
	UINT				skblen = 0;
	p80211msg_lnxind_wlansniffrm_t	*msg;
	UINT8				*datap;
	UINT16				fc;
	struct sk_buff			*skb;
	prism2sta_priv_t	        *priv = wlandev->priv;
	hfa384x_t		        *hw = priv->hw;


	DBFENTER;
	/* Don't forget the status, time, and data_len fields are in host order */
	/* Figure out how big the frame is */
	fc = ieee2host16(rxdesc->frame_control);
	switch ( WLAN_GET_FC_FTYPE(fc) )
	{
	case WLAN_FTYPE_DATA:
		if ( WLAN_GET_FC_TODS(fc) && WLAN_GET_FC_FROMDS(fc) ) {
			hdrlen = WLAN_HDR_A4_LEN;
		} else {
			hdrlen = WLAN_HDR_A3_LEN;
		}
		datalen = hfa384x2host_16(rxdesc->data_len);
		break;
	case WLAN_FTYPE_MGMT:
		hdrlen = WLAN_HDR_A3_LEN;
		datalen = hfa384x2host_16(rxdesc->data_len);
		break;
	case WLAN_FTYPE_CTL:
		switch ( WLAN_GET_FC_FSTYPE(fc) )
		{
		case WLAN_FSTYPE_PSPOLL:
		case WLAN_FSTYPE_RTS:
		case WLAN_FSTYPE_CFEND:
		case WLAN_FSTYPE_CFENDCFACK:
			hdrlen = 16;
			break;
		case WLAN_FSTYPE_CTS:
		case WLAN_FSTYPE_ACK:
			hdrlen = 10;
			break;
		default:
			hdrlen = WLAN_HDR_A3_LEN;
			break;
		}
		datalen = 0;
		break;
	default:
		hdrlen = WLAN_HDR_A3_LEN;
		datalen = hfa384x2host_16(rxdesc->data_len);

		WLAN_LOG_DEBUG(1, "unknown frm: fc=0x%04x\n", fc);
		break;
	}

	/* Allocate an ind message+framesize skb */
	skblen = sizeof(p80211msg_lnxind_wlansniffrm_t) + 
		hdrlen + datalen + WLAN_CRC_LEN;
	
	/* sanity check the length */
	if ( skblen > 
		(sizeof(p80211msg_lnxind_wlansniffrm_t) + 
		WLAN_HDR_A4_LEN + WLAN_DATA_MAXLEN + WLAN_CRC_LEN) ) {
		WLAN_LOG_DEBUG(1, "overlen frm: len=%d\n", 
			skblen - sizeof(p80211msg_lnxind_wlansniffrm_t));
	}
			
	if ( (skb = dev_alloc_skb(skblen)) == NULL ) {
		WLAN_LOG_ERROR("alloc_skb failed trying to allocate %d bytes\n", skblen);
		return;
	}

	/* only prepend the prism header if in the right mode */
	if ((wlandev->netdev->type == ARPHRD_IEEE80211_PRISM) &&
	    (hw->sniffhdr == 0)) {
		datap = skb_put(skb, sizeof(p80211msg_lnxind_wlansniffrm_t));
		msg = (p80211msg_lnxind_wlansniffrm_t*) datap;
	  
		/* Initialize the message members */
		msg->msgcode = DIDmsg_lnxind_wlansniffrm;
		msg->msglen = sizeof(p80211msg_lnxind_wlansniffrm_t);
		strcpy(msg->devname, wlandev->name);
		
		msg->hosttime.did = DIDmsg_lnxind_wlansniffrm_hosttime;
		msg->hosttime.status = 0;
		msg->hosttime.len = 4;
		msg->hosttime.data = jiffies;
		
		msg->mactime.did = DIDmsg_lnxind_wlansniffrm_mactime;
		msg->mactime.status = 0;
		msg->mactime.len = 4;
		msg->mactime.data = rxdesc->time;
		
		msg->channel.did = DIDmsg_lnxind_wlansniffrm_channel;
		msg->channel.status = 0;
		msg->channel.len = 4;
		msg->channel.data = hw->sniff_channel;
		
		msg->rssi.did = DIDmsg_lnxind_wlansniffrm_rssi;
		msg->rssi.status = P80211ENUM_msgitem_status_no_value;
		msg->rssi.len = 4;
		msg->rssi.data = 0;
		
		msg->sq.did = DIDmsg_lnxind_wlansniffrm_sq;
		msg->sq.status = P80211ENUM_msgitem_status_no_value;
		msg->sq.len = 4;
		msg->sq.data = 0;
		
		msg->signal.did = DIDmsg_lnxind_wlansniffrm_signal;
		msg->signal.status = 0;
		msg->signal.len = 4;
		msg->signal.data = rxdesc->signal;
		
		msg->noise.did = DIDmsg_lnxind_wlansniffrm_noise;
		msg->noise.status = 0;
		msg->noise.len = 4;
		msg->noise.data = rxdesc->silence;
		
		msg->rate.did = DIDmsg_lnxind_wlansniffrm_rate;
		msg->rate.status = 0;
		msg->rate.len = 4;
		msg->rate.data = rxdesc->rate / 5; /* set to 802.11 units */
		
		msg->istx.did = DIDmsg_lnxind_wlansniffrm_istx;
		msg->istx.status = 0;
		msg->istx.len = 4;
		msg->istx.data = P80211ENUM_truth_false;
		
		msg->frmlen.did = DIDmsg_lnxind_wlansniffrm_frmlen;
		msg->frmlen.status = 0;
		msg->frmlen.len = 4;
		msg->frmlen.data = hdrlen + datalen + WLAN_CRC_LEN;
	} else if ((wlandev->netdev->type == ARPHRD_IEEE80211_PRISM) &&
		   (hw->sniffhdr != 0)) {
		p80211_caphdr_t		*caphdr;
		/* The NEW header format! */
		datap = skb_put(skb, sizeof(p80211_caphdr_t));
		caphdr = (p80211_caphdr_t*) datap;

		caphdr->version =	htonl(P80211CAPTURE_VERSION);
		caphdr->length =	htonl(sizeof(p80211_caphdr_t));
		caphdr->mactime =	__cpu_to_be64(rxdesc->time) * 1000;
		caphdr->hosttime =	__cpu_to_be64(jiffies);
		caphdr->phytype =	htonl(4); /* dss_dot11_b */
		caphdr->channel =	htonl(hw->sniff_channel);
		caphdr->datarate =	htonl(rxdesc->rate);
		caphdr->antenna =	htonl(0); /* unknown */
		caphdr->priority =	htonl(0); /* unknown */
		caphdr->ssi_type =	htonl(3); /* rssi_raw */
		caphdr->ssi_signal =	htonl(rxdesc->signal);
		caphdr->ssi_noise =	htonl(rxdesc->silence);
		caphdr->preamble =	htonl(0); /* unknown */
		caphdr->encoding =	htonl(1); /* cck */
	}

	/* Copy the 802.11 header to the skb (ctl frames may be less than a full header) */
	datap = skb_put(skb, hdrlen);
	memcpy( datap, &(rxdesc->frame_control), hdrlen);

	/* If any, copy the data from the card to the skb */
	if ( datalen > 0 )
	{
		datap = skb_put(skb, datalen);
		memcpy(datap, rxfrm->data, datalen);

		/* check for unencrypted stuff if WEP bit set. */
		if (*(datap - hdrlen + 1) & 0x40) // wep set
		  if ((*(datap) == 0xaa) && (*(datap+1) == 0xaa))
		    *(datap - hdrlen + 1) &= 0xbf; // clear wep; it's the 802.2 header!
	}

	if (hw->sniff_fcs) {
		/* Set the FCS */
		datap = skb_put(skb, WLAN_CRC_LEN);
		memset( datap, 0xff, WLAN_CRC_LEN);
	}

	/* set up various data fields */
	skb->dev = wlandev->netdev;
	
	skb->mac.raw = skb->data ;
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = htons(ETH_P_80211_RAW);  /* XXX ETH_P_802_2? */

	/* pass it back up */
	prism2sta_ev_rx(wlandev, skb);

	DBFEXIT;
	return;
}



/*----------------------------------------------------------------
* hfa384x_usbin_info
*
* At this point we have a successful received a Prism2 info frame.
*
* Arguments:
*	wlandev		wlan device
*	usbin		ptr to the usb transfer buffer
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void hfa384x_usbin_info(wlandevice_t *wlandev, hfa384x_usbin_t *usbin)
{
	DBFENTER;

	usbin->infofrm.info.framelen = hfa384x2host_16(usbin->infofrm.info.framelen);
	prism2sta_ev_info(wlandev, &usbin->infofrm.info);

	DBFEXIT;
	return;
}



/*----------------------------------------------------------------
* hfa384x_usbout_callback
*
* Callback for urb's on the BULKOUT endpoint.
*
* Arguments:
*	urb		ptr to the completed urb
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void hfa384x_usbout_callback(struct urb *urb)
{
	
	wlandevice_t		*wlandev = urb->context;
	prism2sta_priv_t	*priv = wlandev->priv;
	hfa384x_t		*hw = priv->hw;
	hfa384x_usbout_t	*usbout = urb->transfer_buffer;
	hfa384x_usbctlx_t	*ctlx;
	DBFENTER;

	WLAN_LOG_DEBUG(3,"urb->status=%d\n", urb->status);
#if 0
	void dbprint_urb(struct urb* urb);
#endif

	ctlx = hw->ctlxq.head;

	/* Handle a successful usbout packet */
	switch (hfa384x2host_16(usbout->type)) {
	case HFA384x_USB_TXFRM:
		hfa384x_usbout_tx(wlandev, usbout);
		break;

	case HFA384x_USB_CMDREQ:
	case HFA384x_USB_WRIDREQ:
	case HFA384x_USB_RRIDREQ:
	case HFA384x_USB_WMEMREQ:
	case HFA384x_USB_RMEMREQ:
	/* Validate that request matches head CTLX */
	if ( ctlx == NULL || 
	     ctlx->outbuf.type != (usbout->type) ) {
		/* else, type doesn't match */
		/* ignore it */
		WLAN_LOG_WARNING0(
			"Failed to match IN URB w/ head CTLX\n");
		hfa384x_usbctlxq_run(&hw->ctlxq);
		goto done;
	}

	WLAN_LOG_DEBUG0(4,"Matched usbout w/ ctlxq->head\n");
	
	if ( urb->status == 0 ) {
		/* Request portion of a CTLX is successful */
		switch ( ctlx->state ) {
		case HFA384x_USBCTLX_REQ_SUBMITTED:
			/* Success and correct state */
			/* Stop the reqtimer and set the new state */
			del_timer(&ctlx->reqtimer);
			ctlx->state = HFA384x_USBCTLX_REQ_COMPLETE;
			/* Allow machine to continue */
			break;

		case HFA384x_USBCTLX_RESP_RECEIVED:
			/* Success and correct state */
			/* stop the reqtimer and set the new state */
			del_timer(&ctlx->reqtimer);
			ctlx->state = HFA384x_USBCTLX_COMPLETE;

			/* Call the completion handler */
			hfa384x_usbctlx_complete(ctlx);
			break;

		case HFA384x_USBCTLX_REQ_COMPLETE:
		case HFA384x_USBCTLX_START:
		case HFA384x_USBCTLX_QUEUED:
		case HFA384x_USBCTLX_REQ_TIMEOUT:
		case HFA384x_USBCTLX_REQ_FAILED:
		case HFA384x_USBCTLX_RESP_TIMEOUT:
		case HFA384x_USBCTLX_REQSUBMIT_FAIL:
		case HFA384x_USBCTLX_COMPLETE:
			/* Any of these states signify error */
			/* This is bad and should _never_ happen */
			/* Spit out a log message */
			/* Assume the head ctlx is in progress and this */
			/*  received urb is spurious. Just ignore it. */
			WLAN_LOG_ERROR0(
				"called with matching head CTLX, "
				"not in valid state.\n");
			break;
		default:
			/* Things are _really_ broken */
			WLAN_LOG_ERROR0(
				"Wow, called with matching head CTLX, "
				"and it's in an unrecognized state.\n");
			break;
		}	
	} else {
		switch ( ctlx->state ) {
		case HFA384x_USBCTLX_REQ_SUBMITTED:
			/* Fail and correct state */
			/* Stop the reqtimer and resptimer */
			del_timer(&ctlx->reqtimer);
			del_timer(&ctlx->resptimer);

			/* Set state to REQ_FAILED */
			ctlx->state = HFA384x_USBCTLX_REQ_FAILED;

			/* fall through */
		case HFA384x_USBCTLX_REQ_TIMEOUT:
			/* Call the completion handler */
			hfa384x_usbctlx_complete(ctlx);
			break;

		case HFA384x_USBCTLX_RESP_RECEIVED:
		case HFA384x_USBCTLX_REQ_COMPLETE:
		case HFA384x_USBCTLX_START:
		case HFA384x_USBCTLX_QUEUED:
		case HFA384x_USBCTLX_REQ_FAILED:
		case HFA384x_USBCTLX_RESP_TIMEOUT:
		case HFA384x_USBCTLX_REQSUBMIT_FAIL:
		case HFA384x_USBCTLX_COMPLETE:
			/* Any of these states signify error */
			/* This is bad and should _never_ happen */
			/* Spit out a log message */
			/* Assume the head ctlx is in progress and this */
			/*  received urb is spurious. Just ignore it. */
			WLAN_LOG_ERROR0(
				"(2) called with matching head CTLX, "
				"not in valid state.\n");
			break;
		default:
			/* Things are _really_ broken */
			WLAN_LOG_ERROR0(
				"(2) Wow, called with matching head CTLX, "
				"and it's in an unrecognized state.\n");
			break;
		}	
	}
	break;

	default:
		WLAN_LOG_DEBUG(3,"Unrecognized USBOUT packet, type=%x\n", 
			usbout->type);
		break;
	}

done:
	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_usbctlx_reqtimerfn
*
* Timer response function for CTLX request timeouts.  If this 
* function is called, it means that the callback for the OUT
* URB containing a Prism2.x XXX_Request was never called.
*
* Arguments:
*	data		a ptr to the ctlx
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_usbctlx_reqtimerfn(unsigned long data)
{
	hfa384x_usbctlx_t	*ctlx = (hfa384x_usbctlx_t*)data;
	wlandevice_t		*wlandev = ctlx->outurb.context;
	prism2sta_priv_t	*priv = wlandev->priv;
	hfa384x_t		*hw = priv->hw;

	DBFENTER;

	if (hw->hwremoved)
		return;

	/* Make sure the head ctlx is the same as this one */
	if (hw->ctlxq.head != ctlx ) {
		WLAN_LOG_ERROR0(
			"called with CTLX that is not current head.\n");
		/* This is bad and should _never_ happen */
		goto done;
	}

	/* Stop the resptimer */
	del_timer(&ctlx->resptimer);

	/* Unlink the OUT URB */
	if ( ctlx->outurb.status == -EINPROGRESS ) {
		/* Set the state to REQ_TIMEOUT */
		ctlx->state = HFA384x_USBCTLX_REQ_TIMEOUT;

		/* This will invoke the usbout callback, */
		/* which will call ctlx_complete */
		usb_unlink_urb(&ctlx->outurb);
	} else {
		WLAN_LOG_ERROR0(
				"called with an outurb not in progress.\n");
		/* This is bad and should _never_ happen */
		goto done;
	}

done:
	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_usbctlx_resptimerfn
*
* Timer response function for CTLX response timeouts.  If this 
* function is called, it means that the callback for the IN
* URB containing a Prism2.x XXX_Response was never called.
*
* Arguments:
*	data		a ptr to the ctlx
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void
hfa384x_usbctlx_resptimerfn(unsigned long data)
{
	hfa384x_usbctlx_t	*ctlx = (hfa384x_usbctlx_t*)data;
	wlandevice_t		*wlandev = ctlx->outurb.context;
	prism2sta_priv_t	*priv = wlandev->priv;
	hfa384x_t		*hw = priv->hw;

	DBFENTER;
	/* Make sure the head ctlx is the same as this one */
	if (hw->ctlxq.head != ctlx ) {
		WLAN_LOG_ERROR0(
			"called with CTLX that is not current head.\n");
		/* This is bad and should _never_ happen */
		goto done;
	}

	/* Set the state to RESP_TIMEOUT */
	ctlx->state = HFA384x_USBCTLX_RESP_TIMEOUT;

	/* Call ctlx_complete */
	hfa384x_usbctlx_complete(ctlx);

done:
	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_usbctlx_submit_async
*
* Called from the doxxx functions to do an async submit of a
* CTLX.
*
* Arguments:
*	hw		ptr to the hw struct
*	ctlx		ctlx structure to enqueue		
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt or process
----------------------------------------------------------------*/
void 
hfa384x_usbctlx_submit_async(
	hfa384x_t		*hw, 
	hfa384x_usbctlx_t	*ctlx,
	ctlx_usercb_t		usercb,
	void			*usercb_data)
{
	DBFENTER;

	if (hw->hwremoved)
		return;

	/* fill usercb and data */
	ctlx->usercb = usercb;
	ctlx->usercb_data = usercb_data;

	/* set isasync */
	ctlx->is_async = 1;

	/* enqueue_run */
	hfa384x_usbctlxq_enqueue_run(&hw->ctlxq, ctlx);

	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_usbctlx_submit_wait
*
* Called from the doxxx functions to do a blocking submit of a
* CTLX.
*
* Arguments:
*	hw		ptr to the hw struct
*	ctlx		ctlx structure to enqueue		
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	process
----------------------------------------------------------------*/
void 
hfa384x_usbctlx_submit_wait(
	hfa384x_t		*hw, 
	hfa384x_usbctlx_t	*ctlx)
{
	DBFENTER;

	if (hw->hwremoved)
		return;

	ctlx->wanna_wakeup = 0;

	/* enqueue_run */
	hfa384x_usbctlxq_enqueue_run(&hw->ctlxq, ctlx);

	/* sleep on completion, look at out_callback and in_callback for more */
	/* Note the test, this is the worst kind of race potential, but 
	 * the commands seem to finish before we get to the sleep_on().
	 */
	switch(ctlx->state) { 
	case HFA384x_USBCTLX_COMPLETE:
	case HFA384x_USBCTLX_REQSUBMIT_FAIL:
	case HFA384x_USBCTLX_REQ_TIMEOUT:
	case HFA384x_USBCTLX_REQ_FAILED:
	case HFA384x_USBCTLX_RESP_TIMEOUT:
		WLAN_LOG_DEBUG0(3,"Already done, skipping sleep.\n");
		break;
	default:
		WLAN_LOG_DEBUG0(3,"Sleeping...\n");
		if (in_interrupt()) {
			while(!ctlx->wanna_wakeup)
				udelay(1000);
		} else {
			wait_event_interruptible(hw->cmdq, ctlx->wanna_wakeup);
		}
		break;
	}
	
	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_usbout_tx
*
* At this point we have finished a send of a frame.  Mark the URB
* as available and call ev_alloc to notify higher layers we're
* ready for more.
*
* Arguments:
*	wlandev		wlan device
*	usbout		ptr to the usb transfer buffer
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	interrupt
----------------------------------------------------------------*/
void hfa384x_usbout_tx(wlandevice_t *wlandev, hfa384x_usbout_t *usbout)
{
	DBFENTER;

	prism2sta_ev_alloc(wlandev);
	
	DBFEXIT;
	return;
}


/*----------------------------------------------------------------
* hfa384x_hwremoved
*
* Notification function for hardware removal.  This function is
* called very soon after it is known that the hardware has been
* removed.
*
* Arguments:
*	hw		device structure
*
* Returns: 
*	nothing
*
* Side effects:
*
* Call context:
*	Probably interrupt
----------------------------------------------------------------*/
void hfa384x_hwremoved(hfa384x_t *hw)
{
	hfa384x_usbctlx_t       *ctlx;
	unsigned long		flags;

	DBFENTER;

	/* At this point, the wlandev is already disabled, so all that's
	   left is to unlink all outstanding URBs. 
	   
	   Nobody else will be submitting new URBs at this time.  However this
	   might not be the case on a SMP box, as a request might be in the
	   works, so to speak.  More work remains to be done for that case.

	   We need to mark all outstanding URBs synchronous.
	*/

	spin_lock_irqsave(&hw->ctlxq.lock, flags);
	hw->hwremoved = 1;
	spin_unlock_irqrestore(&hw->ctlxq.lock, flags);

	ctlx = hw->ctlxq.head;
	while (ctlx != NULL) {
		hfa384x_usbctlx_t       *next;
		next = ctlx->next;
		ctlx->prev = NULL;
		
		if (! ctlx->is_async) {
			ctlx->wanna_wakeup = 1;
			wake_up_interruptible(&hw->cmdq);
		}
		
		hw->ctlxq.head = next;

		ctlx->outurb.transfer_flags &= ~USB_ASYNC_UNLINK;
		ctlx->inurb.transfer_flags &= ~USB_ASYNC_UNLINK;

		usb_unlink_urb(&(ctlx->outurb));
		usb_unlink_urb(&(ctlx->inurb));
		
		kfree(ctlx);
		ctlx = ctlx->next;
	}

	/* Unlink the tx/rx URBs */

	if (hw->rxurb_posted) {
		hw->rx_urb.transfer_flags &= ~USB_ASYNC_UNLINK;
		usb_unlink_urb(&(hw->rx_urb));
	}

	hw->tx_urb.transfer_flags &= ~USB_ASYNC_UNLINK;
	usb_unlink_urb(&(hw->tx_urb));
	hw->int_urb.transfer_flags &= ~USB_ASYNC_UNLINK;
	usb_unlink_urb(&(hw->int_urb)); 

	DBFEXIT;
}


/*----------------------------------------------------------------
* hfa384x_isgood_pdrcore
*
* Quick check of PDR codes.
*
* Arguments:
*	pdrcode		PDR code number (host order)
*
* Returns: 
*	zero		not good.
*	one		is good.
*
* Side effects:
*
* Call context:
----------------------------------------------------------------*/
int
hfa384x_isgood_pdrcode(UINT16 pdrcode)
{
	switch(pdrcode) {
	case HFA384x_PDR_END_OF_PDA:
	case HFA384x_PDR_PCB_PARTNUM:
	case HFA384x_PDR_PDAVER:
	case HFA384x_PDR_NIC_SERIAL:
	case HFA384x_PDR_MKK_MEASUREMENTS:
	case HFA384x_PDR_NIC_RAMSIZE:
	case HFA384x_PDR_MFISUPRANGE:
	case HFA384x_PDR_CFISUPRANGE:
	case HFA384x_PDR_NICID:
	case HFA384x_PDR_MAC_ADDRESS:
	case HFA384x_PDR_REGDOMAIN:
	case HFA384x_PDR_ALLOWED_CHANNEL:
	case HFA384x_PDR_DEFAULT_CHANNEL:
	case HFA384x_PDR_TEMPTYPE:
	case HFA384x_PDR_IFR_SETTING:
	case HFA384x_PDR_RFR_SETTING:
	case HFA384x_PDR_HFA3861_BASELINE:
	case HFA384x_PDR_HFA3861_SHADOW:
	case HFA384x_PDR_HFA3861_IFRF:
	case HFA384x_PDR_HFA3861_CHCALSP:
	case HFA384x_PDR_HFA3861_CHCALI:
	case HFA384x_PDR_3842_NIC_CONFIG:
	case HFA384x_PDR_USB_ID:
	case HFA384x_PDR_PCI_ID:
	case HFA384x_PDR_PCI_IFCONF:
	case HFA384x_PDR_PCI_PMCONF:
	case HFA384x_PDR_RFENRGY:
	case HFA384x_PDR_HFA3861_MANF_TESTSP:
	case HFA384x_PDR_HFA3861_MANF_TESTI:
		/* code is OK */
		return 1;
		break;
	default:
		if ( pdrcode < 0x1000 ) {
			/* code is OK, but we don't know exactly what it is */
			WLAN_LOG_DEBUG(3,
				"Encountered unknown PDR#=0x%04x, "
				"assuming it's ok.\n", 
				pdrcode);
			return 1;
		} else {
			/* bad code */
			WLAN_LOG_DEBUG(3,
				"Encountered unknown PDR#=0x%04x, "
				"(>=0x1000), assuming it's bad.\n",
				pdrcode);
			return 0;
		}
		break;
	}
	return 0; /* avoid compiler warnings */
}


