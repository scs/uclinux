/*
 * Copyright (C) 2006 Wolfgang Grandegger <wg@grandegger.com>
 *
 * Derived from RTnet project file stack/rtcan_module.c:
 *
 * Copyright (C) 2002      Ulrich Marx <marx@kammer.uni-hannover.de>
 *               2003-2006 Jan Kiszka <jan.kiszka@web.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <rtdm/rtcan.h>
#include <rtcan_version.h>
#include <rtcan_internal.h>
#include <rtcan_dev.h>
#include <rtcan_raw.h>

MODULE_LICENSE("GPL");


const char rtcan_rtdm_provider_name[] =
    "(C) 2006 RT-Socket-CAN Development Team";


#ifdef CONFIG_PROC_FS

struct proc_dir_entry *rtcan_proc_root;

static void rtcan_dev_get_ctrlmode_name(can_ctrlmode_t ctrlmode, 
					char* name, int max_len)
{
    *name = '\0';
    if (ctrlmode & CAN_CTRLMODE_LISTENONLY)
	strncat(name, "listen-only ", max_len);
    if (ctrlmode & CAN_CTRLMODE_LOOPBACK)
	strncat(name, "loopback ", max_len);
}

static char *rtcan_state_names[] = {
    "active", "warning", "passive" , "bus-off",
    "scanning", "stopped", "sleeping"
};

static void rtcan_dev_get_state_name(can_state_t state, 
				     char* name, int max_len)
{
    if (state >= CAN_STATE_ACTIVE && 
	state <= CAN_STATE_SLEEPING)
	strncpy(name, rtcan_state_names[state], max_len);
    else
	strncpy(name, "unknown", max_len);
}

static void rtcan_dev_get_baudrate_name(can_baudrate_t baudrate,
					char* name, int max_len)
{
    switch (baudrate) {
    case CAN_BAUDRATE_UNCONFIGURED:
	strncpy(name, "undefined", max_len);
	break;
    case CAN_BAUDRATE_UNKNOWN:
	strncpy(name, "unknown", max_len);
	break;
    default:
	snprintf(name, max_len, "%d", baudrate); 
	break;
    }
}

static void rtcan_dev_get_bittime_name(struct can_bittime *bit_time,
				       char* name, int max_len)
{
    switch (bit_time->type) {
    case CAN_BITTIME_STD:
	snprintf(name, max_len, 
		 "brp=%d prop_seg=%d phase_seg1=%d "
		 "phase_seg2=%d sjw=%d sam=%d",
		 bit_time->std.brp,
		 bit_time->std.prop_seg,
		 bit_time->std.phase_seg1,
		 bit_time->std.phase_seg2,
		 bit_time->std.sjw,
		 bit_time->std.sam);
	break;
    case CAN_BITTIME_BTR:
	snprintf(name, max_len, "btr0=0x%02x btr1=0x%02x", 
		 bit_time->btr.btr0, bit_time->btr.btr1); 
	break;
    default:
	strncpy(name, "unknown", max_len);
	break;
    }
}

static void rtcan_get_timeout_name(nanosecs_rel_t timeout,
				   char* name, int max_len)
{
    if (timeout == RTDM_TIMEOUT_INFINITE) 
	strncpy(name, "infinite", max_len);
    else
        sprintf(name, "%lld", (long long)timeout);
}

static int rtcan_read_proc_devices(char *buf, char **start, off_t offset,
                                   int count, int *eof, void *data)
{
    int i, ret;
    struct rtcan_device *dev;
    char state_name[20], baudrate_name[20];
    RTCAN_PROC_PRINT_VARS(80);

    if (down_interruptible(&rtcan_devices_nrt_lock))
        return -ERESTARTSYS;

    /* Name___________ _Baudrate State___ _TX_Counts _TX_Counts ____Errors
     * rtcan0             125000 stopped  1234567890 1234567890 1234567890   
     * rtcan1          undefined warning  1234567890 1234567890 1234567890
     * rtcan2          undefined scanning 1234567890 1234567890 1234567890
     */
    if (!RTCAN_PROC_PRINT("Name___________ _Baudrate State___ "
			  "TX_Counter RX_Counter ____Errors\n"))
        goto done;

    for (i = 1; i <= RTCAN_MAX_DEVICES; i++) {
        if ((dev = rtcan_dev_get_by_index(i)) != NULL) {
	    rtcan_dev_get_state_name(dev->state, state_name, 20);
	    rtcan_dev_get_baudrate_name(dev->baudrate, baudrate_name, 20);
	    ret = RTCAN_PROC_PRINT("%-15s %9s %-8s %10d %10d %10d\n",
				   dev->name, baudrate_name, state_name,
				   dev->tx_count, dev->rx_count, dev->err_count);
	    rtcan_dev_dereference(dev);
            if (!ret)
                break;
        }
    }

  done:
    up(&rtcan_devices_nrt_lock);
    RTCAN_PROC_PRINT_DONE;
}


static int rtcan_read_proc_sockets(char *buf, char **start, off_t offset,
                                   int count, int *eof, void *data)
{
    struct rtcan_socket *sock;
    struct rtdm_dev_context *context;
    struct rtcan_device *dev;
    char name[IFNAMSIZ] = "not-bound";
    char rx_timeout[20], tx_timeout[16];
    rtdm_lockctx_t lock_ctx;
    int ifindex;
    RTCAN_PROC_PRINT_VARS(120);

    if (down_interruptible(&rtcan_devices_nrt_lock))
        return -ERESTARTSYS;

    /* fd Name___________ Filter ErrMask RX_Timeout TX_Timeout RX_BufFull TX_Lo
     *  0 rtcan0               1 0x00010 1234567890 1234567890 1234567890 12345
     */
    if (!RTCAN_PROC_PRINT("fd Name___________ Filter ErrMask RX_Timeout_ns "
			  "TX_Timeout_ns RX_BufFull TX_Lo\n"))
	goto done;

    rtdm_lock_get_irqsave(&rtcan_recv_list_lock, lock_ctx);

    list_for_each_entry(sock, &rtcan_socket_list, socket_list) {
	context = rtcan_socket_context(sock);
	if (rtcan_sock_is_bound(sock)) {
	    ifindex = atomic_read(&sock->ifindex);
	    if (ifindex) {
		dev = rtcan_dev_get_by_index(ifindex);
		if (dev) {
		    strncpy(name, dev->name, IFNAMSIZ);
		    rtcan_dev_dereference(dev);
		}
	    } else
		sprintf(name, "%d", ifindex);
	}
	rtcan_get_timeout_name(sock->tx_timeout, tx_timeout, 20);
	rtcan_get_timeout_name(sock->rx_timeout, rx_timeout, 20);
	if (!RTCAN_PROC_PRINT("%2d %-15s %6d 0x%05x %13s %13s %10d %5d\n",
			      context->fd, name, sock->flistlen,
			      sock->err_mask, rx_timeout, tx_timeout,
			      sock->rx_buf_full,
			      rtcan_loopback_enabled(sock)))
	    break;
    }

    rtdm_lock_put_irqrestore(&rtcan_recv_list_lock, lock_ctx);

  done:
    up(&rtcan_devices_nrt_lock);
    RTCAN_PROC_PRINT_DONE;
}


static int rtcan_read_proc_info(char *buf, char **start, off_t offset,
				int count, int *eof, void *data)
{
    struct rtcan_device *dev = (struct rtcan_device *)data;
    char state_name[20], baudrate_name[20];
    char ctrlmode_name[80], bittime_name[80];
    RTCAN_PROC_PRINT_VARS(80);

    if (down_interruptible(&rtcan_devices_nrt_lock))
        return -ERESTARTSYS;

    rtcan_dev_get_state_name(dev->state, state_name, 20);
    rtcan_dev_get_ctrlmode_name(dev->ctrl_mode, ctrlmode_name, 80);
    rtcan_dev_get_baudrate_name(dev->baudrate, baudrate_name, 20);
    rtcan_dev_get_bittime_name(&dev->bit_time, bittime_name, 80);

    if (!RTCAN_PROC_PRINT("%s %s\n", "Device    ", dev->name) ||
	!RTCAN_PROC_PRINT("%s %s\n", "Controller", dev->ctrl_name) ||
	!RTCAN_PROC_PRINT("%s %s\n", "Board     ", dev->board_name) ||
	!RTCAN_PROC_PRINT("%s %d\n", "Clock-Hz  ", dev->can_sys_clock) ||
	!RTCAN_PROC_PRINT("%s %s\n", "Baudrate  ", baudrate_name) ||
	!RTCAN_PROC_PRINT("%s %s\n", "Bit-time  ", bittime_name) ||
	!RTCAN_PROC_PRINT("%s %s\n", "Ctrl-Mode ", ctrlmode_name) ||
	!RTCAN_PROC_PRINT("%s %s\n", "State     ", state_name) ||
	!RTCAN_PROC_PRINT("%s %d\n", "TX-Counter", dev->tx_count) ||
	!RTCAN_PROC_PRINT("%s %d\n", "RX-Counter", dev->rx_count) ||
	!RTCAN_PROC_PRINT("%s %d\n", "Errors    ", dev->err_count))
        goto done;

#ifdef RTCAN_USE_REFCOUNT
    if (!RTCAN_PROC_PRINT("%s %d\n", "Refcount  ", atomic_read(&dev->refcount)))
	goto done;
#endif

  done:
    up(&rtcan_devices_nrt_lock);
    RTCAN_PROC_PRINT_DONE;
}



static int rtcan_read_proc_filter(char *buf, char **start, off_t offset,
				  int count, int *eof, void *data)
{
    struct rtcan_device *dev = (struct rtcan_device *)data;
    struct rtcan_recv *recv_listener = dev->recv_list;
    struct rtdm_dev_context *context;
    rtdm_lockctx_t lock_ctx;
    RTCAN_PROC_PRINT_VARS(80);

    /*  fd __CAN_ID__ _CAN_Mask_ Inv MatchCount
     *   3 0x12345678 0x12345678  no 1234567890
     */

    if (!RTCAN_PROC_PRINT("fd __CAN_ID__ _CAN_Mask_ Inv MatchCount\n"))
        goto done;

    rtdm_lock_get_irqsave(&rtcan_recv_list_lock, lock_ctx);

    /* Loop over the reception list of the device */
    while (recv_listener != NULL) {
	context = rtcan_socket_context(recv_listener->sock);

	if (!RTCAN_PROC_PRINT("%2d 0x%08x 0x%08x %s %10d\n",
			      context->fd,
			      recv_listener->can_filter.can_id,
			      recv_listener->can_filter.can_mask &
			      ~CAN_INV_FILTER,
			      (recv_listener->can_filter.can_mask &
			       CAN_INV_FILTER) ? "yes" : " no",
			      recv_listener->match_count))
	    break;
	recv_listener = recv_listener->next;
    }

    rtdm_lock_put_irqrestore(&rtcan_recv_list_lock, lock_ctx);

  done:
    RTCAN_PROC_PRINT_DONE;
}



static int rtcan_read_proc_version(char *buf, char **start, off_t offset,
                                   int count, int *eof, void *data)
{
    RTCAN_PROC_PRINT_VARS(80);

    RTCAN_PROC_PRINT("RT-Socket-CAN %d.%d.%d - built on %s %s\n",
		     RTCAN_MAJOR_VER, RTCAN_MINOR_VER, RTCAN_BUGFIX_VER,
		     __DATE__, __TIME__);

    RTCAN_PROC_PRINT_DONE;
}


void rtcan_dev_remove_proc(struct rtcan_device* dev)
{
    if (!dev->proc_root)
	return;

    remove_proc_entry("info", dev->proc_root);
    remove_proc_entry("filters", dev->proc_root);
    remove_proc_entry(dev->name, rtcan_proc_root);

    dev->proc_root = NULL;
}

int rtcan_dev_create_proc(struct rtcan_device* dev)
{
    struct proc_dir_entry *proc_entry;

    if (!rtcan_proc_root)
	return -EINVAL;

    dev->proc_root = create_proc_entry(dev->name, S_IFDIR, rtcan_proc_root);
    if (!dev->proc_root)
        goto error1;

    proc_entry = create_proc_entry("info", S_IFREG | S_IRUGO | S_IWUSR,
                                   dev->proc_root);
    if (!proc_entry)
        goto error2;
    proc_entry->read_proc = rtcan_read_proc_info;
    proc_entry->data = dev;

    proc_entry = create_proc_entry("filters", S_IFREG | S_IRUGO | S_IWUSR,
                                   dev->proc_root);
    if (!proc_entry)
        goto error3;
    proc_entry->read_proc = rtcan_read_proc_filter;
    proc_entry->data = dev;

    return 0;

  error3:
    remove_proc_entry("info", dev->proc_root);
  error2:
    remove_proc_entry(dev->name, rtcan_proc_root);
  error1:
    printk("%s: unable to create /proc device entries\n", dev->name);
    return -1;
    
}


static int rtcan_proc_register(void)
{
    struct proc_dir_entry *proc_entry;

    rtcan_proc_root = create_proc_entry("rtcan", S_IFDIR, 0);
    if (!rtcan_proc_root)
        goto error1;

    proc_entry = create_proc_entry("devices", S_IFREG | S_IRUGO | S_IWUSR,
                                   rtcan_proc_root);
    if (!proc_entry)
        goto error2;
    proc_entry->read_proc = rtcan_read_proc_devices;

    proc_entry = create_proc_entry("version", S_IFREG | S_IRUGO | S_IWUSR,
                                   rtcan_proc_root);
    if (!proc_entry)
        goto error3;
    proc_entry->read_proc = rtcan_read_proc_version;

    proc_entry = create_proc_entry("sockets", S_IFREG | S_IRUGO | S_IWUSR,
                                   rtcan_proc_root);
    if (!proc_entry)
        goto error4;
    proc_entry->read_proc = rtcan_read_proc_sockets;

    return 0;

  error4:
    remove_proc_entry("version", rtcan_proc_root);

  error3:
    remove_proc_entry("devices", rtcan_proc_root);

  error2:
    remove_proc_entry("rtcan", 0);

  error1:
    printk("rtcan: unable to initialize /proc entries\n");
    return -1;
}



static void rtcan_proc_unregister(void)
{
    remove_proc_entry("devices", rtcan_proc_root);
    remove_proc_entry("version", rtcan_proc_root);
    remove_proc_entry("sockets", rtcan_proc_root);
    remove_proc_entry("rtcan", 0);
}
#endif  /* CONFIG_PROC_FS */



int __init rtcan_init(void)
{
    int err = 0;

	  
    printk("RT-Socket-CAN %d.%d.%d - %s\n", 
	   RTCAN_MAJOR_VER, RTCAN_MINOR_VER, RTCAN_BUGFIX_VER,
	   rtcan_rtdm_provider_name);

    if ((err = rtcan_raw_proto_register()) != 0)
        goto out;

#ifdef CONFIG_PROC_FS
    if ((err = rtcan_proc_register()) != 0)
        goto out;
#endif

 out:
    return err;
}


void __exit rtcan_exit(void)
{
    
    rtcan_raw_proto_unregister();	
#ifdef CONFIG_PROC_FS
    rtcan_proc_unregister();
#endif

    printk("rtcan: unloaded\n");
}


module_init(rtcan_init);
module_exit(rtcan_exit);
