/*      $Id: hw_atilibusb.c,v 5.2 2005/07/10 08:34:11 lirc Exp $      */

/****************************************************************************
 ** hw_atilibusb.c **********************************************************
 ****************************************************************************
 *  Userspace (libusb) driver for ATI/NVidia/X10 RF Remote.
 *
 *  Copyright (C) 2004 Michael Gold <mgold@scs.carleton.ca>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <usb.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "hardware.h"
#include "ir_remote.h"
#include "lircd.h"
#include "receive.h"

#define CODE_BYTES 5
#define USB_TIMEOUT (1000*60)

static int ati_init();
static int ati_deinit();
static char *ati_rec(struct ir_remote *remotes);
static void usb_read_loop(int fd);
static struct usb_device *find_usb_device(void);
static int find_device_endpoints(struct usb_device *dev);

struct hardware hw_atilibusb =
{
	NULL,                       /* default device */
	-1,                         /* fd */
	LIRC_CAN_REC_LIRCCODE,      /* features */
	0,                          /* send_mode */
	LIRC_MODE_LIRCCODE,         /* rec_mode */
	CODE_BYTES * CHAR_BIT,      /* code_length */
	ati_init,                   /* init_func */
	NULL,                       /* config_func */
	ati_deinit,                 /* deinit_func */
	NULL,                       /* send_func */
	ati_rec,                    /* rec_func */
	receive_decode,             /* decode_func */
	NULL,                       /* ioctl_func */
	NULL,                       /* readdata */
	"atilibusb"
};

typedef struct {
	u_int16_t vendor;
	u_int16_t product;
} usb_device_id;

/* table of compatible remotes -- from lirc_atiusb */
static usb_device_id usb_remote_id_table[] = {
	{ 0x0bc7, 0x0002 }, /* X10 USB Firecracker Interface */
	{ 0x0bc7, 0x0003 }, /* X10 VGA Video Sender */
	{ 0x0bc7, 0x0004 }, /* ATI Wireless Remote Receiver */
	{ 0x0bc7, 0x0005 }, /* NVIDIA Wireless Remote Receiver */
	{ 0x0bc7, 0x0006 }, /* ATI Wireless Remote Receiver */
	{ 0x0bc7, 0x0007 }, /* X10 USB Wireless Transceiver */
	{ 0x0bc7, 0x0008 }, /* X10 USB Wireless Transceiver */
	{ 0x0bc7, 0x0009 }, /* X10 USB Wireless Transceiver */
	{ 0x0bc7, 0x000A }, /* X10 USB Wireless Transceiver */
	{ 0x0bc7, 0x000B }, /* X10 USB Transceiver */
	{ 0x0bc7, 0x000C }, /* X10 USB Transceiver */
	{ 0x0bc7, 0x000D }, /* X10 USB Transceiver */
	{ 0x0bc7, 0x000E }, /* X10 USB Transceiver */
	{ 0x0bc7, 0x000F }, /* X10 USB Transceiver */
	{ 0, 0 } /* Terminating entry */
};

static struct usb_dev_handle *dev_handle = NULL;
struct usb_endpoint_descriptor *dev_ep_in = NULL, *dev_ep_out = NULL;
static pid_t child = -1;

/* init strings -- from lirc_atiusb */
static char init1[] = {0x80, 0x01, 0x00, 0x20, 0x14};
static char init2[] = {0x80, 0x01, 0x00, 0x20, 0x14, 0x20, 0x20, 0x20};

/****/

/* initialize driver -- returns 1 on success, 0 on error */
static int ati_init()
{
	struct usb_device *usb_dev;
	int pipe_fd[2] = { -1, -1 };
	
	LOGPRINTF(LOG_INFO, "initializing USB receiver");
	
	init_rec_buffer();
	
	/* A separate process will be forked to read data from the USB
	 * receiver and write it to a pipe. hw.fd is set to the readable
	 * end of this pipe. */
	if (pipe(pipe_fd) != 0)
	{
		logprintf(LOG_ERR, "couldn't open pipe: %s", strerror(errno));
		return 0;
	}
	hw.fd = pipe_fd[0];
	
	usb_dev = find_usb_device();
	if (usb_dev == NULL)
	{
		logprintf(LOG_ERR, "couldn't find a compatible USB device");
		return 0;
	}

	if (!find_device_endpoints(usb_dev))
	{
		logprintf(LOG_ERR, "couldn't find device endpoints");
		return 0;
	}
	
	dev_handle = usb_open(usb_dev);
	if (dev_handle == NULL)
	{
		logprintf(LOG_ERR, "couldn't open USB receiver: %s",
				strerror(errno));
		goto fail;
	}
	
	if (usb_claim_interface(dev_handle, 0) != 0)
	{
		logprintf(LOG_ERR, "couldn't claim USB interface: %s",
				strerror(errno));
		goto fail;
	}
	
	errno = 0;
	if ( (usb_interrupt_write(dev_handle, dev_ep_out->bEndpointAddress,
			init1, sizeof(init1), 100) != sizeof(init1))
	|| (usb_interrupt_write(dev_handle, dev_ep_out->bEndpointAddress,
			init2, sizeof(init2), 100) != sizeof(init2)) )
	{
		logprintf(LOG_ERR, "couldn't initialize USB receiver: %s",
				errno ? strerror(errno) : "short write");
		goto fail;
	}
	
	child = fork();
	if (child == -1)
	{
		logprintf(LOG_ERR, "couldn't fork child process: %s",
				strerror(errno));
		goto fail;
	}
	else if (child == 0)
	{
		usb_read_loop(pipe_fd[1]);
	}
	
	LOGPRINTF(LOG_INFO, "USB receiver initialized");
	return 1;

fail:
	if (dev_handle)
	{
		usb_close(dev_handle);
		dev_handle = NULL;
	}
	if (pipe_fd[0] >= 0) close(pipe_fd[0]);
	if (pipe_fd[1] >= 0) close(pipe_fd[1]);
	return 0;
}

/* deinitialize driver -- returns 1 on success, 0 on error */
static int ati_deinit()
{
	int err = 0;
	
	if (dev_handle)
	{
		if (usb_close(dev_handle) < 0) err = 1;
		dev_handle = NULL;
	}
	
	if (hw.fd >= 0)
	{
		if (close(hw.fd) < 0) err = 1;
		hw.fd = -1;
	}
	
	if (child > 1)
	{
		if ( (kill(child, SIGTERM) == -1)
				|| (waitpid(child, NULL, 0) == 0) ) err = 1;
	}
	
	return !err;
}

static char *ati_rec(struct ir_remote *remotes)
{
	if (!clear_rec_buffer()) return NULL;
	return decode_all(remotes);
}

/* returns 1 if the given device should be used, 0 otherwise */
static int is_device_ok(struct usb_device *dev)
{
	/* TODO: allow exact device to be specified */
	
	/* check if the device ID is in usb_remote_id_table */
	usb_device_id *dev_id;
	for (dev_id = usb_remote_id_table; dev_id->vendor; dev_id++)
	{
		if ( (dev->descriptor.idVendor == dev_id->vendor) &&
				(dev->descriptor.idProduct == dev_id->product) )
		{
			return 1;
		}
	}
	
	return 0;
}

/* find a compatible USB receiver and return a usb_device,
 * or NULL on failure. */
static struct usb_device *find_usb_device(void)
{
	struct usb_bus *usb_bus;
	struct usb_device *dev;
	
	usb_init();
	usb_find_busses();
	usb_find_devices();
	
	for (usb_bus = usb_busses; usb_bus; usb_bus = usb_bus->next)
	{
		for (dev = usb_bus->devices; dev; dev = dev->next)
		{
			if (is_device_ok(dev)) return dev;
		}
	}
	return NULL;  /* no suitable device found */
}

/* set dev_ep_in and dev_ep_out to the in/out endpoints of the given
 * device. returns 1 on success, 0 on failure. */
static int find_device_endpoints(struct usb_device *dev)
{
	struct usb_interface_descriptor *idesc;
	if (dev->descriptor.bNumConfigurations != 1) return 0;
	if (dev->config[0].bNumInterfaces != 1) return 0;
	if (dev->config[0].interface[0].num_altsetting != 1) return 0;
	
	idesc = &dev->config[0].interface[0].altsetting[0];
	if (idesc->bNumEndpoints != 2) return 0;
	
	dev_ep_in = &idesc->endpoint[0];
	if ((dev_ep_in->bEndpointAddress & USB_ENDPOINT_DIR_MASK)
			!= USB_ENDPOINT_IN) return 0;
	if ((dev_ep_in->bmAttributes & USB_ENDPOINT_TYPE_MASK)
			!= USB_ENDPOINT_TYPE_INTERRUPT) return 0;

	dev_ep_out = &idesc->endpoint[1];
	if ((dev_ep_out->bEndpointAddress & USB_ENDPOINT_DIR_MASK)
			!= USB_ENDPOINT_OUT) return 0;
	if ((dev_ep_out->bmAttributes & USB_ENDPOINT_TYPE_MASK)
			!= USB_ENDPOINT_TYPE_INTERRUPT) return 0;
	
	return 1;
}

/* this function is run in a forked process to read data from the USB
 * receiver and write it to the given fd. it calls exit() with result
 * code 0 on success, or 1 on failure. */
static void usb_read_loop(int fd)
{
	int inited = 0;
	int err = 0;
	
	alarm(0);
	signal(SIGTERM, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGHUP, SIG_IGN);
	signal(SIGALRM, SIG_IGN);
	
	for(;;)
	{
		char buf[CODE_BYTES];
		int bytes_r, bytes_w, pos;
		int channel;
		
		/* read from the USB device */
		bytes_r = usb_interrupt_read(dev_handle,
				dev_ep_in->bEndpointAddress,
				&buf[0], sizeof(buf), USB_TIMEOUT);
		if (bytes_r < 0)
		{
			if (errno == EAGAIN) continue;
			logprintf(LOG_ERR, "can't read from USB device: %s",
					strerror(errno));
			err = 1; goto done;
		}
		
		/* sometimes the remote sends one byte on startup; ignore it */
		if (!inited)
		{
			inited = 1;
			if (bytes_r == 1) continue;
		}
		
		/* TODO: accept codes only for a specific channel */
		channel = (buf[bytes_r - 1] >> 4) & 0x0F;
		
		/* pad the code with zeros (if shorter than CODE_BYTES) */
		memset(buf + bytes_r, 0, sizeof(buf) - bytes_r);
		/* erase the channel code -- TODO: make this optional */
		buf[bytes_r - 1] &= 0x0F;
		
		/* write to the pipe */
		bytes_r = sizeof(buf);
		for (pos = 0; pos < bytes_r; pos += bytes_w)
		{
			bytes_w = write(fd, buf + pos, bytes_r - pos);
			if (bytes_w < 0)
			{
				logprintf(LOG_ERR, "can't write to pipe: %s",
						strerror(errno));
				err = 1; goto done;
			}
		}
	}
	
done:
	if (!usb_close(dev_handle)) err = 1;
	exit(err);
}
