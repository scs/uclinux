/*
 * Copyright (C) 2006 Wolfgang Grandegger, <wg@grandegger.com>
 * Copyright (C) 2005 Marc Kleine-Budde, Pengutronix
 * Copyright (C) 2006 Andrey Volkov, Varma Electronics
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/delay.h>

#include <rtdm/rtdm_driver.h>

#include <rtdm/rtcan.h>
#include "rtcan_dev.h"
#include "rtcan_raw.h"
#include "rtcan_internal.h"

#define RTCAN_MAX_TSEG1  15
#define RTCAN_MAX_TSEG2  7

/* 
 * Calculate standard bit-time values for odd bitrates.
 * Most parts of this code is from Arnaud Westenberg <arnaud@wanadoo.nl>
 */
static int rtcan_calc_bit_time(struct rtcan_device *dev, 
			       can_baudrate_t rate,
			       struct can_bittime_std *bit_time)
{
    int best_error = 1000000000;
    int error;
    int best_tseg=0, best_brp=0, best_rate=0, brp=0;
    int tseg=0, tseg1=0, tseg2=0;
    int clock = dev->can_sys_clock;
    int sjw = 0;
    int sampl_pt = 90;
	
    /* some heuristic specials */
    if (rate > ((1000000 + 500000) / 2))
	sampl_pt = 75;
    
    if (rate < ((12500 + 10000) / 2))
	sampl_pt = 75;
    
    if (rate < ((100000 + 125000) / 2))
	sjw = 1;

    /* tseg even = round down, odd = round up */
    for (tseg = (0 + 0 + 2) * 2; 
	 tseg <= (RTCAN_MAX_TSEG2 + RTCAN_MAX_TSEG1 + 2) * 2 + 1; 
	 tseg++) {
	brp = clock / ((1 + tseg / 2) * rate) + tseg % 2;
	if ((brp == 0) || (brp > 64))
	    continue;
		
	error = rate - clock / (brp * (1 + tseg / 2));
	if (error < 0)
	    error = -error;
			
	if (error <= best_error) {
	    best_error = error;
	    best_tseg = tseg/2;
	    best_brp = brp - 1;
	    best_rate = clock / (brp * (1 + tseg / 2));
	}
    }
	
    if (best_error && (rate / best_error < 10)) {
	RTCAN_RTDM_DBG("%s: bitrate %d is not possible with %d Hz clock\n", 
		       dev->name, rate, clock);	
	return -EDOM;
    }
	
    tseg2 = best_tseg - (sampl_pt * (best_tseg + 1)) / 100;
	
    if (tseg2 < 0)
	tseg2 = 0;
		
    if (tseg2 > RTCAN_MAX_TSEG2)
	tseg2 = RTCAN_MAX_TSEG2;
		
    tseg1 = best_tseg - tseg2 - 2;
	
    if (tseg1 > RTCAN_MAX_TSEG1)  {
	tseg1 = RTCAN_MAX_TSEG1;
	tseg2 = best_tseg-tseg1-2;
    }

    bit_time->brp = best_brp + 1;
    bit_time->prop_seg = 0;
    bit_time->phase_seg1 = tseg1 + 1;
    bit_time->phase_seg2 = tseg2 + 1;
    bit_time->sjw = sjw + 1;
    bit_time->sam = 0;

    return 0;
}

static inline int rtcan_raw_ioctl_dev_get(struct rtcan_device *dev, 
					  int request, struct ifreq *ifr)
{
    struct can_bittime *bittime;
    can_baudrate_t *baudrate = NULL;
    can_state_t *state;
    can_ctrlmode_t *ctrlmode;
    rtdm_lockctx_t lock_ctx;
    int ret = 0;

    switch (request) {

    case SIOCGIFINDEX: {
	ifr->ifr_ifindex = dev->ifindex;
	break;
    }

    case SIOCGCANSTATE:
	state = (can_state_t *)&ifr->ifr_ifru;
	rtdm_lock_get_irqsave(&dev->device_lock, lock_ctx);
	if (dev->do_get_state)
	    dev->state = dev->do_get_state(dev);
	*state = dev->state;
	rtdm_lock_put_irqrestore(&dev->device_lock, lock_ctx);
	break;

    case SIOCGCANCTRLMODE:
	ctrlmode = (can_ctrlmode_t *)&ifr->ifr_ifru;
	*ctrlmode = dev->ctrl_mode;
	break;

    case SIOCGCANBAUDRATE:
	baudrate = (can_baudrate_t *)&ifr->ifr_ifru;
	*baudrate = dev->baudrate;
	break;

    case SIOCGCANCUSTOMBITTIME:
	bittime = (struct can_bittime *)&ifr->ifr_ifru;
	*bittime = dev->bit_time;
	break;
    }

    return ret;
}

static inline int rtcan_raw_ioctl_dev_set(struct rtcan_device *dev, 
					  int request, struct ifreq *ifr)
{
    rtdm_lockctx_t lock_ctx;
    can_ctrlmode_t *ctrl_mode;
    can_mode_t *mode;
    int ret = 0, started = 0;
    struct can_bittime bit_time, *bt;
    can_baudrate_t *baudrate = NULL;

    switch (request) {
    case SIOCSCANBAUDRATE:
	if (!dev->do_set_bit_time)
	    return 0;
	baudrate = (can_baudrate_t *)&ifr->ifr_ifru;
	if ((ret = rtcan_calc_bit_time(dev, *baudrate, &bit_time.std)))
	    break;
	bit_time.type = CAN_BITTIME_STD;
	break;
    }

    rtdm_lock_get_irqsave(&dev->device_lock, lock_ctx);

    if (dev->do_get_state)
	dev->state = dev->do_get_state(dev);
    
    switch (request) {
    case SIOCSCANCTRLMODE:
    case SIOCSCANBAUDRATE:
    case SIOCSCANCUSTOMBITTIME:
	if ((started = CAN_STATE_OPERATING(dev->state))) {
	    if ((ret = dev->do_set_mode(dev, CAN_MODE_STOP, &lock_ctx)))
		goto out;
	}
	break;
    }

    switch (request) {
    case SIOCSCANMODE:
	mode = (can_mode_t *)&ifr->ifr_ifru;
	if (dev->do_set_mode &&
	    !(*mode == CAN_MODE_START && CAN_STATE_OPERATING(dev->state)))
	    ret = dev->do_set_mode(dev, *mode, &lock_ctx);
	break;

    case SIOCSCANCTRLMODE:
	ctrl_mode = (can_ctrlmode_t *)&ifr->ifr_ifru;
	dev->ctrl_mode = *ctrl_mode;
	break;

    case SIOCSCANBAUDRATE:
	ret = dev->do_set_bit_time(dev, &bit_time, &lock_ctx);
	if (!ret) {
	    dev->baudrate = *baudrate;
	    dev->bit_time = bit_time;
	}
	break;

    case SIOCSCANCUSTOMBITTIME:
	bt = (struct can_bittime *)&ifr->ifr_ifru;
	ret = dev->do_set_bit_time(dev, bt, &lock_ctx);
	if (!ret) {
	    dev->bit_time = *bt;
	    if (bt->type == CAN_BITTIME_STD && bt->std.brp)
		dev->baudrate = (dev->can_sys_clock / 
				 (bt->std.brp * (1 + bt->std.prop_seg + 
						 bt->std.phase_seg1 + 
						 bt->std.phase_seg2)));
	    else
		dev->baudrate = CAN_BAUDRATE_UNKNOWN;
	}
	break;

    default:
	ret = -EOPNOTSUPP;
	break;
	
    }
    
 out:
    if (started)
	dev->do_set_mode(dev, CAN_MODE_START, &lock_ctx);
	
    rtdm_lock_put_irqrestore(&dev->device_lock, lock_ctx);	    

    return ret;
}

int rtcan_raw_ioctl_dev(struct rtdm_dev_context *context,
			rtdm_user_info_t *user_info, int request, void *arg)
{
    int ret = 0;
    struct ifreq *ifr;
    struct ifreq ifr_buf;
    struct rtcan_device *dev;

    switch (request) {

    case SIOCGIFINDEX:
    case SIOCGCANSTATE:
    case SIOCGCANBAUDRATE:
    case SIOCGCANCUSTOMBITTIME:

	if (user_info) {
	    if (!rtdm_rw_user_ok(user_info, arg, sizeof(struct ifreq)) ||
		rtdm_copy_from_user(user_info, &ifr_buf, arg,
				    sizeof(struct ifreq)))
		return -EFAULT;
	    
	    ifr = &ifr_buf;
	} else
	    ifr = (struct ifreq *)arg;
	
	if ((dev = rtcan_dev_get_by_name(ifr->ifr_name)) == NULL)
	    return -ENODEV;
	ret = rtcan_raw_ioctl_dev_get(dev, request, ifr);
	rtcan_dev_dereference(dev);
	
	if (user_info && !ret) {
	    /* Since we yet tested if user memory is rw safe,
	       we can copy to user space directly */
	    if (rtdm_copy_to_user(user_info, arg, ifr, 
				  sizeof(struct ifreq)))
		return -EFAULT;
	}
	break;
	
    case SIOCSCANMODE:
    case SIOCSCANCTRLMODE:
    case SIOCSCANBAUDRATE:
    case SIOCSCANCUSTOMBITTIME:

	if (user_info) {
	    /* Copy struct ifreq from userspace */
	    if (!rtdm_read_user_ok(user_info, arg,
				   sizeof(struct ifreq)) ||
		rtdm_copy_from_user(user_info, &ifr_buf, arg,
				    sizeof(struct ifreq)))
		return -EFAULT;

	    ifr = &ifr_buf;
	} else
	    ifr = (struct ifreq *)arg;

	/* Get interface index and data */
	if ((dev = rtcan_dev_get_by_name(ifr->ifr_name)) == NULL)
	    return -ENODEV;
	ret = rtcan_raw_ioctl_dev_set(dev, request, ifr);
	rtcan_dev_dereference(dev);
	break; 

    default:
	ret = -EOPNOTSUPP;
	break;

    }

    return ret;
}

#ifdef CONFIG_XENO_DRIVERS_CAN_BUS_ERR
void __rtcan_raw_enable_bus_err(struct rtcan_socket *sock)
{
    int i, begin, end;
    struct rtcan_device *dev;
    rtdm_lockctx_t lock_ctx;
    int ifindex = atomic_read(&sock->ifindex);

    if (ifindex) {
	begin = ifindex;
	end   = ifindex;
    } else {
	begin = 1;
	end = RTCAN_MAX_DEVICES;
    }

    for (i = begin; i <= end; i++) {
	if ((dev = rtcan_dev_get_by_index(i)) == NULL)
	    continue;

	if (dev->do_enable_bus_err) {
	    rtdm_lock_get_irqsave(&dev->device_lock, lock_ctx);
	    dev->do_enable_bus_err(dev);
	    rtdm_lock_put_irqrestore(&dev->device_lock, lock_ctx);
	}
	rtcan_dev_dereference(dev);
    }
}
#endif /* CONFIG_XENO_DRIVERS_CAN_BUS_ERR*/
