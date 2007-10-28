/****************************************************************************
 ** hw_hiddev.c *************************************************************
 ****************************************************************************
 *
 * receive keycodes input via /dev/usb/hiddev...
 * 
 * Copyright (C) 2002 Oliver Endriss <o.endriss@gmx.de>
 * Copyright (C) 2004 Chris Pascoe <c.pascoe@itee.uq.edu.au>
 * Copyright (C) 2005 William Uther <william.uther@nicta.com.au>
 * Copyright (C) 2007 Brice DUBOST <ml@braice.net>
 * Copyright (C) 2007 Benjamin Drung <benjamin.drung@gmail.com>
 * Copyright (C) 2007 Stephen Williams <stephen.gw@gmail.com>
 *
 * Distribute under GPL version 2 or later.
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>

#include <linux/types.h>
#include <linux/hiddev.h>

#include "hardware.h"
#include "ir_remote.h"
#include "lircd.h"
#include "receive.h"

#define TIMEOUT 20000

static int hiddev_init();
static int hiddev_deinit(void);
static int hiddev_decode(struct ir_remote *remote,
			   ir_code *prep, ir_code *codep, ir_code *postp,
			   int *repeat_flagp, lirc_t *remaining_gapp);
static char *hiddev_rec(struct ir_remote *remotes);
static int sb0540_init();
static char *sb0540_rec(struct ir_remote *remotes);
static char *macmini_rec(struct ir_remote *remotes);

struct hardware hw_dvico=
{
	"/dev/usb/hiddev0",     /* "device" */
	-1,			/* fd (device) */
	LIRC_CAN_REC_LIRCCODE,	/* features */
	0,			/* send_mode */
	LIRC_MODE_LIRCCODE,     /* rec_mode */
	64,			/* code_length */
	hiddev_init,		/* init_func */
	NULL,			/* config_func */
	hiddev_deinit,          /* deinit_func */
	NULL,			/* send_func */
	hiddev_rec,		/* rec_func */
	hiddev_decode,          /* decode_func */
	NULL,                   /* ioctl_func */
	NULL,			/* readdata */
	"dvico"
};

static int dvico_repeat_mask = 0x8000;

static int pre_code_length = 32;
static int main_code_length = 32;

static unsigned int pre_code;
static signed int main_code = 0;

static int repeat_flag = 0;

/* Remotec Mediamaster specific */
struct hardware hw_bw6130=
{
	"/dev/usb/hid/hiddev0", /* "device" */
	-1,			/* fd (device) */
	LIRC_CAN_REC_LIRCCODE,	/* features */
	0,			/* send_mode */
	LIRC_MODE_LIRCCODE,     /* rec_mode */
	64,			/* code_length */
	hiddev_init,		/* init_func */
	NULL,			/* config_func */
	hiddev_deinit,          /* deinit_func */
	NULL,			/* send_func */
	hiddev_rec,		/* rec_func */
	hiddev_decode,          /* decode_func */
	NULL,                   /* ioctl_func */
	NULL,			/* readdata */
	"bw6130"
};

struct hardware hw_asusdh=
{
	"/dev/usb/hiddev0",     /* "device" */
	-1,			/* fd (device) */
	LIRC_CAN_REC_LIRCCODE,	/* features */
	0,			/* send_mode */
	LIRC_MODE_LIRCCODE,     /* rec_mode */
	64,			/* code_length */
	hiddev_init,		/* init_func */
	NULL,			/* config_func */
	hiddev_deinit,          /* deinit_func */
	NULL,			/* send_func */
	hiddev_rec,		/* rec_func */
	hiddev_decode,          /* decode_func */
	NULL,                   /* ioctl_func */
	NULL,			/* readdata */
	"asusdh"		/* name */
};

/* Creative USB IR Receiver (SB0540) */
struct hardware hw_sb0540=
{
	"/dev/usb/hiddev0",     /* "device" */
	-1,			/* fd (device) */
	LIRC_CAN_REC_LIRCCODE,	/* features */
	0,			/* send_mode */
	LIRC_MODE_LIRCCODE,     /* rec_mode */
	32,			/* code_length */
	sb0540_init,		/* init_func */
	NULL,			/* config_func */
	hiddev_deinit,          /* deinit_func */
	NULL,			/* send_func */
	sb0540_rec,		/* rec_func */
	hiddev_decode,          /* decode_func */
	NULL,                   /* ioctl_func */
	NULL,			/* readdata */
	"sb0540"		/* name */
};

/* Apple Mac mini USB IR Receiver */
struct hardware hw_macmini=
{
	"/dev/usb/hiddev0",     /* "device" */
	-1,			/* fd (device) */
	LIRC_CAN_REC_LIRCCODE,	/* features */
	0,			/* send_mode */
	LIRC_MODE_LIRCCODE,     /* rec_mode */
	32,			/* code_length */
	hiddev_init,		/* init_func */
	NULL,			/* config_func */
	hiddev_deinit,          /* deinit_func */
	NULL,			/* send_func */
	macmini_rec,		/* rec_func */
	hiddev_decode,          /* decode_func */
	NULL,                   /* ioctl_func */
	NULL,			/* readdata */
	"macmini"		/* name */
};

static int old_main_code = 0;

const static int mousegrid[9][9]=
	{{0x00,0x15,0x15,0x16,0x16,0x16,0x16,0x17,0x17},
	 {0x05,0x0d,0x11,0x12,0x12,0x12,0x16,0x17,0x17},
	 {0x05,0x09,0x0e,0x12,0x12,0x12,0x13,0x13,0x13},
	 {0x06,0x0a,0x0a,0x0e,0x0e,0x12,0x13,0x13,0x13},
	 {0x06,0x0a,0x0a,0x0e,0x0e,0x0f,0x13,0x13,0x13},
	 {0x06,0x0a,0x0a,0x0a,0x0f,0x0f,0x0f,0x0f,0x13},
	 {0x06,0x06,0x0b,0x0b,0x0b,0x0f,0x0f,0x0f,0x0f},
	 {0x07,0x07,0x0b,0x0b,0x0b,0x0f,0x0f,0x0f,0x0f},
	 {0x07,0x07,0x0b,0x0b,0x0b,0x0b,0x0f,0x0f,0x0f}};


int hiddev_init()
{
	logprintf(LOG_INFO, "initializing '%s'", hw.device);
	
	if ((hw.fd = open(hw.device, O_RDONLY)) < 0) {
		logprintf(LOG_ERR, "unable to open '%s'", hw.device);
		return 0;
	}
	
	return 1;
}


int hiddev_deinit(void)
{
	if(hw.fd != -1)
	{
		logprintf(LOG_INFO, "closing '%s'", hw.device);
		close(hw.fd);
		hw.fd=-1;
	}
	return 1;
}


int hiddev_decode(struct ir_remote *remote,
			ir_code *prep, ir_code *codep, ir_code *postp,
			int *repeat_flagp, lirc_t *remaining_gapp)
{
	LOGPRINTF(1, "hiddev_decode");

	if(!map_code(remote,prep,codep,postp,
			 pre_code_length,pre_code,
			 main_code_length,main_code,
			 0,0))
	{
		return(0);
	}
	
	LOGPRINTF(1, "lirc code: 0x%X", *codep);

	*repeat_flagp = repeat_flag;
	*remaining_gapp = 0;
	
	return 1;
}


char *hiddev_rec(struct ir_remote *remotes)
{
	struct hiddev_event event;
	struct hiddev_event asus_events[8];
	int rd;
	/* Remotec Mediamaster specific */
	static int wheel_count = 0;
	static int x_movement = 0;
	int y_movement=0;
	int x_direction=0;
	int y_direction=0;
	int i;
	
	LOGPRINTF(1, "hiddev_rec");
	
	rd = read(hw.fd, &event, sizeof event);
	if (rd != sizeof event) {
		logprintf(LOG_ERR, "error reading '%s'", hw.device);
		logperror(LOG_ERR, NULL);
		hiddev_deinit();
		return 0;
	}

	LOGPRINTF(1, "hid 0x%X  value 0x%X", event.hid, event.value);

	pre_code = event.hid;
	main_code = event.value;

	/*
	 * This stuff is probably dvico specific.
	 * I don't have any other hid devices to test...
	 *
	 * See further for the Asus DH specific code
	 *
	 */
	if (event.hid == 0x10046) {
		repeat_flag = (main_code & dvico_repeat_mask);
		main_code = (main_code & ~dvico_repeat_mask);
		return decode_all(remotes);
#if 0
		/* the following code could be used to recreate the
		   real codes of the remote control (currently
		   verified for the MCE remote only) */
		ir_code pre, main;
		
		pre_code_length = 16;
		main_code_length = 16;
		
		pre = event.value&0xff;
		pre_code = reverse(~pre, 8)<<8 | reverse(pre, 8);
		
		repeat_flag = (event.value & dvico_repeat_mask);
		
		main = (event.value&0x7f00) >> 8;
		main_code = reverse(main, 8)<<8 | reverse(~main, 8);
		return decode_all(remotes);
#endif
	}
	/* Asus DH remote specific code */
	else if (event.hid == 0xFF000000)
	{
		LOGPRINTF(1, "This is an asus P5 DH remote, "
			  "we read the other events");
		asus_events[0]=event;
		for (i=1;i<8;i++)
		{
			if(!waitfordata(TIMEOUT))
			{
				logprintf(LOG_ERR,"timeout reading byte %d",i);
				return(NULL);
			}
			rd = read(hw.fd, &asus_events[i], sizeof event);
			if (rd != sizeof event) {
				logprintf(LOG_ERR, "error reading '%s'",
					  hw.device);
				return 0;
			}
		}
		for (i=0;i<8;i++)
		{
			LOGPRINTF(1, "Event number %d hid 0x%X  value 0x%X",
				  i, asus_events[i].hid,
				  asus_events[i].value);
		}
		pre_code = asus_events[1].hid;
		main_code = asus_events[1].value;
		if (main_code)
		{
			return decode_all(remotes);
		}
	}

	/* Remotec Mediamaster specific code */
	/* Y-Coordinate,
	   second event field after button code (wheel_count==2) */
	if (wheel_count == 2) {
		y_movement = event.value & 0x0000000F;
		y_direction = (event.value & 0x000000F0) >> 2;
		x_direction = (x_movement & 0x000000F0) >> 1;
		x_movement &= 0x0000000F;
		
		if(x_movement > 8 || y_movement > 8)
		{
			logprintf(LOG_ERR, "unexpected coordinates: %u,%u",
				  x_movement, y_movement);
			return NULL;
		}
		
		main_code=mousegrid[x_movement][y_movement];
		main_code |= x_direction;
		main_code |= y_direction;
		main_code |= 0x00000080; //just to make it unique

		wheel_count=0;
		pre_code=0xFFA10003; //so it gets recognized
		return decode_all(remotes);
	}
	/* X-Coordinate,
	   first event field after button code (wheel_count==1) */
	else if (wheel_count==1) {
		x_movement=event.value;
		
		wheel_count=2;	
		return NULL;
	}

	if ((event.hid == 0xFFA10003) &&
	    (event.value != 0xFFFFFFFF) &&
	    (event.value != 0xFFFFFFAA))
	{
		if (old_main_code == main_code) repeat_flag = 1;
		old_main_code = main_code;
		if (main_code==0x40) {  /* the mousedial has been touched */
			wheel_count=1;
			return 0;
		}
		return decode_all(remotes);
	}
	else if ((event.hid == 0xFFA10003) && (event.value == 0xFFFFFFAA)) {
		repeat_flag = 0;
		old_main_code = 0;
	}

	/* insert decoding logic for other hiddev remotes here */

	return 0;
}

/*
 * Creative USB IR Receiver specific code
 *
 * based on creative_rm1500_usb-0.1 from http://ecto.teftin.net/rm1500.html
 * which is written by Stan Sawa teftin(at)gmail.com
 *
 */

int sb0540_init()
{
	int rv = hiddev_init();

	if (rv == 1) {
		/* we want to get info on each report received from device */
		int flags = HIDDEV_FLAG_UREF | HIDDEV_FLAG_REPORT;
		if (ioctl(hw.fd, HIDIOCSFLAG, &flags)) {
			return 0;
		}
	}

	return rv;
}

char *sb0540_rec(struct ir_remote *remotes)
{
	/*
	 * at this point, each read from opened file/device should return
	 * hiddev_usage_ref structure
	 *
	 */

	ir_code code;
	ssize_t rd;
	struct hiddev_usage_ref uref;

	LOGPRINTF(1, "sb0540_rec");

	pre_code_length = 16;
	main_code_length = 16;
	pre_code = 0x8322;
	repeat_flag = 0;

	rd = read(hw.fd, &uref, sizeof(uref));
	if (rd < 0) {
		logprintf(LOG_ERR, "error reading '%s'", hw.device);
		logperror(LOG_ERR, NULL);
		hiddev_deinit();
		return 0;
	}

	if (uref.field_index == HID_FIELD_INDEX_NONE) {
		/*
		 * we get this when the new report has been send from
		 * device at this point we have the uref structure
		 * prefilled with correct report type and id
		 *
		 */

		/* this got guessed by getting the device report
		   descriptor (function devinfo in source) */
		uref.field_index = 0; /* which field of report */
		/* this got guessed by taking all values from device
		   and checking which ones are changing ;) */
		uref.usage_index = 3; /* which usage entry of field */

		/* fetch the usage code for given indexes */
		ioctl(hw.fd, HIDIOCGUCODE, &uref, sizeof(uref));
		/* fetch the value from report */
		ioctl(hw.fd, HIDIOCGUSAGE, &uref, sizeof(uref));
		/* now we have the key */

		code = reverse(uref.value, 8);
		main_code = (code << 8) + ((~code)&0xff);

		return decode_all(remotes);
	}
	/*
	 * we are not interested in any other events, as they are only
	 * giving info what changed in report and this not always
	 * works, is complicated, doesn't output anything sensible on
	 * repeated key and we already have all the info from real
	 * report
	 *
	 */

	return 0;
}

/*
 * Apple Mac mini USB IR Receiver specific code.
 *
 */

char *macmini_rec(struct ir_remote *remotes)
{
	struct hiddev_event ev[4];
	int rd;
	int i;

	LOGPRINTF(1, "macmini_rec");

	for (i=0;i<4;i++)
	{
		if(i>0 && !waitfordata(TIMEOUT))
		{
			logprintf(LOG_ERR,"timeout reading byte %d",i);
			return(NULL);
		}
		rd = read(hw.fd, &ev[i], sizeof(ev[i]));
		if (rd != sizeof(ev[i])) {
			logprintf(LOG_ERR, "error reading '%s'", hw.device);
			hiddev_deinit();
			return 0;
		}
	}

	/* Record the code */
	pre_code_length = 0;
	pre_code = 0;
	main_code = (ev[0].value << 24) + (ev[1].value << 16) +
	            (ev[2].value <<  8) + (ev[3].value <<  0);

	return decode_all(remotes);
}
