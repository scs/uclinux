/*
 * Wildcard S100U USB FXS Interface Zapata Telephony Driver
 *
 * Written by Mark Spencer <markster@linux-support.net>
 *            Matthew Fredrickson <creslin@linux-support.net>
 *
 * Copyright (C) 2001, Linux Support Services, Inc.
 *
 * All rights reserved.
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

/* Save power at the expense of not always being able to transmit on hook.  If
   this is set, we only transit on hook for some time after a ring 
   (POWERSAVE_TIMEOUT) */

#define PROSLIC_POWERSAVE
#define POWERSAVE_TIME 4000

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/usb.h>
#include <linux/errno.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,19)
#define USB2420
#endif

#ifdef STANDALONE_ZAPATA

#include "zaptel.h"
#else
#include <linux/zaptel.h>
#endif /* STANDALONE_ZAPATA */

#include "wcfxsusb.h"
#include "proslic.h"


#ifdef DEBUG_WILDCARD
#define DPRINTK(x) printk x
#else
#define DPRINTK(x)
#endif

// Function prototypes
static int readProSlicDirectReg(struct usb_device *dev, unsigned char address, unsigned char* data);
static int initializeIndirectRegisters(struct usb_device *dev);
static int verifyIndirectRegisters(struct usb_device *dev);
static int writeProSlicDirectReg(struct usb_device *dev, unsigned char address, unsigned char data);
static int writeProSlicInDirectReg(struct usb_device *dev, unsigned char address, unsigned short data);
static int readProSlicInDirectReg(struct usb_device *dev, unsigned char address, unsigned short *data);
static int writeProSlicInDirectReg(struct usb_device *dev, unsigned char address, unsigned short data);

static alpha  indirect_regs[] =
{
{0,"DTMF_ROW_0_PEAK",0x55C2},
{1,"DTMF_ROW_1_PEAK",0x51E6},
{2,"DTMF_ROW2_PEAK",0x4B85},
{3,"DTMF_ROW3_PEAK",0x4937},
{4,"DTMF_COL1_PEAK",0x3333},
{5,"DTMF_FWD_TWIST",0x0202},
{6,"DTMF_RVS_TWIST",0x0202},
{7,"DTMF_ROW_RATIO_TRES",0x0198},
{8,"DTMF_COL_RATIO_TRES",0x0198},
{9,"DTMF_ROW_2ND_ARM",0x0611},
{10,"DTMF_COL_2ND_ARM",0x0202},
{11,"DTMF_PWR_MIN_TRES",0x00E5},
{12,"DTMF_OT_LIM_TRES",0x0A1C},
{13,"OSC1_COEF",0x6D40},
{14,"OSC1X",0x0470},
{15,"OSC1Y",0x0000},
{16,"OSC2_COEF",0x4A80},
{17,"OSC2X",0x0830},
{18,"OSC2Y",0x0000},
{19,"RING_V_OFF",0x0000},
{20,"RING_OSC",0x7EF0},
{21,"RING_X",0x0160},
{22,"RING_Y",0x0000},
{23,"PULSE_ENVEL",0x2000},
{24,"PULSE_X",0x2000},
{25,"PULSE_Y",0x0000},
//{26,"RECV_DIGITAL_GAIN",0x4000},	// playback volume set lower
{26,"RECV_DIGITAL_GAIN",0x2000},	// playback volume set lower
{27,"XMIT_DIGITAL_GAIN",0xc000 /* was 0x4000 */ },
{28,"LOOP_CLOSE_TRES",0x1000},
{29,"RING_TRIP_TRES",0x3600},
{30,"COMMON_MIN_TRES",0x1000},
{31,"COMMON_MAX_TRES",0x0200},
{32,"PWR_ALARM_Q1Q2",0x0550},
{33,"PWR_ALARM_Q3Q4",0x2600},
{34,"PWR_ALARM_Q5Q6",0x1B80},
{35,"LOOP_CLOSURE_FILTER",0x8000},
{36,"RING_TRIP_FILTER",0x0320},
{37,"TERM_LP_POLE_Q1Q2",0x0100},
{38,"TERM_LP_POLE_Q3Q4",0x0100},
{39,"TERM_LP_POLE_Q5Q6",0x0010},
{40,"CM_BIAS_RINGING",0x0C00},
{41,"DCDC_MIN_V",0x0C00},
{42,"DCDC_XTRA",0x1000},
};

#define WCUSB_SPORT0				0x26
#define WCUSB_SPORT1				0x27
#define WCUSB_SPORT2				0x28
#define WCUSB_SPORT_CTRL		0x29

#define WC_AUX0	0x1
#define WC_AUX1 0x2
#define WC_AUX2 0x4
#define WC_AUX3 0x8

#define CONTROL_TIMEOUT_MS		(500)		/* msec */
#define CONTROL_TIMEOUT_JIFFIES ((CONTROL_TIMEOUT_MS * HZ) / 1000)

#define REQUEST_NORMAL 4

#define FLAG_RUNNING	(1 << 0)

static int debug = 0;

struct stinky_urb {
#ifdef USB2420
	struct urb urb;
	struct iso_packet_descriptor isoframe[1];
#else
	urb_t urb;
	iso_packet_descriptor_t isoframe[1];
#endif

};

typedef enum {
	STREAM_NORMAL,
	STREAM_DTMF,
} stream_t;

typedef enum {
	STATE_WCREAD_WRITEREG,
	STATE_WCREAD_READRES,
	STATE_WCWRITE_WRITEREG,
	STATE_WCWRITE_WRITERES,
} control_state_t;

typedef enum {
	WC_KEYPAD,
	WC_PROSLIC,
} dev_type_t;

typedef enum {
	STATE_FOR_LOOP_1_OUT,
	STATE_FOR_LOOP_2_IN,
	STATE_FOR_LOOP_PROC_DATA,
	STATE_FOR_LOOP_CLEAR_DIGIT,
} keypad_state_t;

struct wc_keypad_data {
	/* Keypad state monitoring variables */
	keypad_state_t state;
#ifdef USB2420
	struct urb urb;
#else
	urb_t urb;
#endif
	int running;
	char data;
	char data12;
	char tmp;
	int scanned_event;
	int i;
	int count;
	/* DTMF tone generation stuff for zaptel */
	struct zt_tone_state ts;
	struct zt_tone *tone;
};

#define WC_IO_READ	(1 << 0)
#define WC_IO_WRITE	(1 << 1)

#define IO_READY(x)	(((x) & (WC_IO_READ | WC_IO_WRITE)) == \
			      (WC_IO_READ | WC_IO_WRITE))

struct wc_usb_pvt {
	struct usb_device *dev;
	dev_type_t devclass;
	unsigned int readpipe;
	unsigned int writepipe;
	int usecount;
	int dead;
	int hardwareflags;
	struct zt_span span;
	struct zt_chan chan;
	struct stinky_urb dataread[2];
	struct stinky_urb datawrite[2];
	int iostate;	/* Whether reads/writes are complete */
#ifdef USB2420
	struct urb *pendingurb;	/* Pending URB for transmission */
	struct urb 		control;
	struct usb_ctrlrequest	dr;
#else

	urb_t *pendingurb;	/* Pending URB for transmission */
	urb_t 		control;
	devrequest	dr;
#endif
	control_state_t controlstate;
	int urbcount;
	int flags;
	int timer;
	int lowpowertimer;
	int idletxhookstate;
	int hookstate;
	__u8 newtxhook;
	__u8 txhook;
	int pos;
	unsigned char auxstatus;
	unsigned char wcregindex;
	unsigned char wcregbuf[4];
	unsigned char wcregval;
	short readchunk[ZT_MAX_CHUNKSIZE * 2];
	short writechunk[ZT_MAX_CHUNKSIZE * 2];
	stream_t sample;
	void *pvt_data;
};

struct wc_usb_desc {
	char *name;
	int flags;
};

#define FLAG_FLIP_RELAYS	(1 << 0)

static struct wc_usb_desc wcusb = { "Wildcard S100U USB FXS Interface" };
static struct wc_usb_desc wcusb2 = { "Wildcard S110U USB FXS Interface", FLAG_FLIP_RELAYS };
static struct wc_usb_desc wc_usb_phone = { "Wildcard Phone Test driver" };
static struct wc_usb_pvt *ifaces[WC_MAX_IFACES];



static void wcusb_check_keypad(struct wc_usb_pvt *p);
static int set_aux_ctrl(struct wc_usb_pvt *p, char auxpins, int on);



static int Wcusb_WriteWcRegs(struct usb_device *dev, unsigned char index, 
					  unsigned char *data, int len)
{
	unsigned int pipe = usb_sndctrlpipe(dev, 0);
	int requesttype;
	int res;

	requesttype = USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE;

	res = usb_control_msg(dev, pipe, REQUEST_NORMAL, requesttype, 
							0, index, data, len, CONTROL_TIMEOUT_JIFFIES);
	if (res == -ETIMEDOUT) {
		printk("wcusb: timeout on vendor write\n");
		return -1;
	} else if (res < 0) {
		printk("wcusb: Error executing control: status=%d\n", le32_to_cpu(res));
		return -1;
	}
	return 0;
}					  

static int Wcusb_ReadWcRegs(struct usb_device *dev, unsigned char index, 
					  unsigned char *data, int len)
{
	unsigned int pipe = usb_rcvctrlpipe(dev, 0);
	int requesttype;
	int res;

	requesttype = USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE;

	res = usb_control_msg(dev, pipe, REQUEST_NORMAL, requesttype, 
							0, index, data, len, CONTROL_TIMEOUT_JIFFIES);
	if (res == -ETIMEDOUT) {
		printk("wcusb: timeout on vendor write\n");
		return -1;
	} else if (res < 0) {
		printk("wcusb: Error executing control: status=%d\n", le32_to_cpu(res));
		return -1;
	} else {
		DPRINTK(("wcusb: Executed read, result = %d (data = %04x)\n", le32_to_cpu(res), (int) *data));
	}
	return 0;
}					  

#ifdef USB2420
static int wcusb_async_read(struct wc_usb_pvt *p, unsigned char index, unsigned char *data, int len, int state, void (*complete)(struct urb *urb));
static int wcusb_async_write(struct wc_usb_pvt *p, unsigned char index, unsigned char *data, int len, int state, void (*complete)(struct urb *urb));
static void wcusb_async_control(struct urb *urb);
#else
static int wcusb_async_read(struct wc_usb_pvt *p, unsigned char index, unsigned char *data, int len, int state, void (*complete)(urb_t *urb));
static int wcusb_async_write(struct wc_usb_pvt *p, unsigned char index, unsigned char *data, int len, int state, void (*complete)(urb_t *urb));
static void wcusb_async_control(urb_t *urb);
#endif

static void proslic_read_direct_async(struct wc_usb_pvt *p, unsigned char address)
{
	p->wcregindex = address;
	p->wcregbuf[0] = address | 0x80;
	p->wcregbuf[1] = 0;
	p->wcregbuf[2] = 0;
	p->wcregbuf[3] = 0x67;
	wcusb_async_write(p, WCUSB_SPORT0, p->wcregbuf, 4, STATE_WCREAD_WRITEREG, wcusb_async_control);
}

static void proslic_write_direct_async(struct wc_usb_pvt *p, unsigned char address, unsigned char val)
{
	p->wcregindex = address;
	p->wcregbuf[0] = address & 0x7f;
	p->wcregbuf[1] = val;
	p->wcregbuf[2] = 0;
	p->wcregbuf[3] = 0x27;
	wcusb_async_write(p, WCUSB_SPORT0, p->wcregbuf, 4, STATE_WCWRITE_WRITERES, wcusb_async_control);
}

#ifdef USB2420
static void wcusb_async_control(struct urb *urb)
#else
static void wcusb_async_control(urb_t *urb)
#endif
{
	struct wc_usb_pvt *p = urb->context;
	p->urbcount--;
	if (urb->status) {
		printk("Error in transfer...\n");
		p->timer = 50;
		return;
	}
	if (!(p->flags & FLAG_RUNNING)) {
		return;
	}
	switch (p->controlstate) {
	case STATE_WCREAD_WRITEREG:
		/* We've written the register to sport0, now read form sport 1 */
		wcusb_async_read(p, WCUSB_SPORT1, &p->wcregval, 1, STATE_WCREAD_READRES, wcusb_async_control);
		return;
	case STATE_WCREAD_READRES:
		switch(p->wcregindex) {
		case 68:
			if (!p->hookstate && (p->wcregval & 1)) {
				p->hookstate = 1;
				if (debug)
					printk("Going off hook...\n");
				zt_hooksig(&p->chan, ZT_RXSIG_OFFHOOK);
			} else if (p->hookstate && !(p->wcregval & 1)) {
				p->hookstate = 0;
				if (debug)
					printk("Going on hook...\n");
				zt_hooksig(&p->chan, ZT_RXSIG_ONHOOK);
			}
			/* Set outgoing hook state if necessary */
			if (p->txhook != p->newtxhook) {
				if (debug)
					printk("Really setting hook state to %d\n", p->newtxhook);
				p->txhook = p->newtxhook;
				proslic_write_direct_async(p, 64, p->newtxhook);
			} else
				p->timer = 50;
			break;
		case 64:
			if (debug)
				printk("Read hook state as %02x\n", p->wcregval);
			p->timer = 50;
			break;
		default:
			printk("dunno what to do with read/regindex %d\n", p->wcregindex);
			p->wcregindex = 0;
		}
		return;
	case STATE_WCWRITE_WRITERES:
		switch(p->wcregindex) {
		case 64:
			if (debug) {
				printk("Hook transition complete to %d\n", ((char *)(urb->transfer_buffer))[1]);
#ifdef BOOST_RINGER
			}
			if (p->txhook == 4) {
				/* Ringing -- boost battery to 96V */
				proslic_write_direct_async(p, 74, 0x3f);
			} else {
				/* Leave battery at default 75V */
				proslic_write_direct_async(p, 74, 0x32);
			}
			break;
		case 74:
			if (debug) {
				printk("Battery set to -%dV\n", ((char *)(urb->transfer_buffer))[1] * 3 / 2);
#endif
				proslic_read_direct_async(p, 64);
			} else
				p->timer = 50;
			break;
		default:
			printk("dunno what to do with write/regindex %d\n", p->wcregindex);
			p->wcregindex = 0;
		}
		return;
	default:
		printk("async control in unknown state %d\n", p->controlstate);
	}
}

#ifdef USB2420
static void keypad_check_done(struct urb *urb)
#else
static void keypad_check_done(urb_t *urb)
#endif
{
	struct wc_usb_pvt *p = urb->context;
	struct wc_keypad_data *d = p->pvt_data;
	static char aux_pattern[] = {0x1e, 0x1d, 0x17, 0xf};
	char digit = 'z';

	p->urbcount--;
	if (!d->running) {
		printk("Stopping stream (check_done)\n");
		return;
	}

	if (urb->status) {
		printk("status %d\n", urb->status);
	}

	if (debug) printk("i is %d\n", d->i);
	switch (d->state) {
loop_start:
		case STATE_FOR_LOOP_1_OUT:
			if (debug) printk("data12 is %x\n", d->data12);
			if(d->i < sizeof(aux_pattern) / sizeof(char)) {
				d->tmp = aux_pattern[d->i] | (d->data12 & 0xe0);
				d->state = STATE_FOR_LOOP_2_IN;
				if (debug) printk("tmp is %x\n", d->tmp);
				wcusb_async_write(p, 0x12, &d->tmp, 1, 0, keypad_check_done);
				return;
			} else {
				goto func_end;
			}
		case STATE_FOR_LOOP_2_IN:
			d->state = STATE_FOR_LOOP_PROC_DATA;
			wcusb_async_read(p, 0xc0, &d->data, 1, 0, keypad_check_done);
			return;
		case STATE_FOR_LOOP_PROC_DATA:
			d->state = STATE_FOR_LOOP_CLEAR_DIGIT;
			if(debug) printk("data is %x\n", d->data);
			if ((d->data & 0x1f) != 0x1f) {
				if(d->data == 0xe && aux_pattern[d->i] == 0x1e) { digit = '1';}
				else if(d->data == 0xd && aux_pattern[d->i] == 0x1e) { digit = '2';}
				else if(d->data == 0xb && aux_pattern[d->i] == 0x1e) { digit = '3';}
				else if(d->data == 0x7 && aux_pattern[d->i] == 0x1e) {
					p->hookstate = 0; /* On||Off */ 
					zt_hooksig(&p->chan, ZT_RXSIG_ONHOOK);
				}

				else if(d->data == 0xe && aux_pattern[d->i] == 0x1d) { digit = '4';}
				else if(d->data == 0xd && aux_pattern[d->i] == 0x1d) { digit = '5';}
				else if(d->data == 0xb && aux_pattern[d->i] == 0x1d) { digit = '6';}
				else if(d->data == 0x7 && aux_pattern[d->i] == 0x1d) {
					p->hookstate = 1;/* Dial */
					zt_hooksig(&p->chan, ZT_RXSIG_OFFHOOK);
				}

				else if(d->data == 0xe && aux_pattern[d->i] == 0x17) { digit = '7';}
				else if(d->data == 0xd && aux_pattern[d->i] == 0x17) { digit = '8';}
				else if(d->data == 0xb && aux_pattern[d->i] == 0x17) { digit = '9';}
				else if(d->data == 0x7 && aux_pattern[d->i] == 0x17) d->scanned_event = 15; /* ReDial */
	
				else if(d->data == 0xe && aux_pattern[d->i] == 0xf) { digit = '*';}/* '*' */
				else if(d->data == 0xd && aux_pattern[d->i] == 0xf) { digit = '0';}
				else if(d->data == 0xb && aux_pattern[d->i] == 0xf) { digit = '#';} /* '#' */
				else if(d->data == 0x7 && aux_pattern[d->i] == 0xf) d->scanned_event = 16; /* Volume? */
				else {
					(d->i)++;
					if (debug) printk("Scanned event %d; data = %x\n", d->scanned_event, d->data);
					goto loop_start;
				}
			} else {
				if(debug) printk("Hit new if\n");
				goto func_end;
			}
			if (debug) printk("wcusb: got digit %d\n", d->scanned_event);
			if (digit != 'z') {
				d->tone = zt_dtmf_tone(digit, 0);
				if (!d->tone) {
					printk("wcusb: Didn't get a tone structure\n");
					goto func_end;
				}
				zt_init_tone_state(&d->ts, d->tone);
				p->sample = STREAM_DTMF;
			}
			d->count = 0;
		case STATE_FOR_LOOP_CLEAR_DIGIT:
			if (((d->data & 0xf) != 0xf) && d->count < 200) {
				wcusb_async_read(p, 0xc0, &d->data, 1, 0, keypad_check_done);
				return;
			}
			(d->i)++;
			p->sample = STREAM_NORMAL;
			goto loop_start;
	}
func_end:
	p->timer = 100;
	return;
}

static void wcusb_check_interrupt(struct wc_usb_pvt *p)
{
	/* Start checking for interrupts */
	if (p->devclass == WC_KEYPAD) {
		wcusb_check_keypad(p);
	} else {
		proslic_read_direct_async(p, 68);
	}
	return;
}

#ifdef USB2420
static int wcusb_async_read(struct wc_usb_pvt *p, unsigned char index, unsigned char *data, int len, int state, void (*complyyete)(struct urb *urb))
#else
static int wcusb_async_read(struct wc_usb_pvt *p, unsigned char index, unsigned char *data, int len, int state, void (*complete)(urb_t *urb))
#endif
{
	__u16 size = len;
	__u16 ind = index;
#ifdef USB2420
	struct urb *urb = &p->control;
	memset(urb, 0, sizeof(struct urb));

	p->dr.bRequestType = USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE;
	p->dr.bRequest = REQUEST_NORMAL;
	p->dr.wValue = 0;
	p->dr.wIndex = cpu_to_le16(ind);
	p->dr.wLength = cpu_to_le16(size);
#else
	urb_t *urb = &p->control;
	memset(urb, 0, sizeof(urb_t));

	p->dr.requesttype = USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE;
	p->dr.request = REQUEST_NORMAL;
	p->dr.value = 0;
	p->dr.index = cpu_to_le16(ind);
	p->dr.length = cpu_to_le16(size);
#endif

	FILL_CONTROL_URB(urb, p->dev, usb_rcvctrlpipe(p->dev, 0), (unsigned char *)&p->dr, data, len, complete, p);
	if (usb_submit_urb(urb)) {
		printk("wcusb_async_read: control URB died\n");
		return -1;
	}
	p->controlstate = state;
	p->urbcount++;
	return 0;
}

#ifdef USB2420
static int wcusb_async_write(struct wc_usb_pvt *p, unsigned char index, unsigned char *data, int len, int state, void (*complete)(struct urb *urb))
#else
static int wcusb_async_write(struct wc_usb_pvt *p, unsigned char index, unsigned char *data, int len, int state, void (*complete)(urb_t *urb))
#endif
{
	__u16 size = len;
	__u16 ind = index;
#ifdef USB2420
	struct urb *urb = &p->control;
	memset(urb, 0, sizeof(struct urb));

	p->dr.bRequestType = USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE;
	p->dr.bRequest = REQUEST_NORMAL;
	p->dr.wValue = 0;
	p->dr.wIndex = cpu_to_le16(ind);
	p->dr.wLength = cpu_to_le16(size);
#else
	urb_t *urb = &p->control;
	memset(urb, 0, sizeof(urb_t));

	p->dr.requesttype = USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE;
	p->dr.request = REQUEST_NORMAL;
	p->dr.value = 0;
	p->dr.index = cpu_to_le16(ind);
	p->dr.length = cpu_to_le16(size);
#endif

	FILL_CONTROL_URB(urb, p->dev, usb_sndctrlpipe(p->dev, 0), (unsigned char *)&p->dr, data, len, complete, p);
	if (usb_submit_urb(urb)) {
		printk("wcusb_async_write: control URB died\n");
		p->timer = 50;
		return -1;
	}
	p->controlstate = state;
	p->urbcount++;
	return 0;
}

/*
**	Write register to Wc560
*/
static int wcoutp(struct usb_device *dev, unsigned char address, unsigned char data)
{
	if (!Wcusb_WriteWcRegs(dev, address, &data, 1))
		return 0;

	return -1;
}

/*
**	read register from Wc560
*/
static int wcinp(struct usb_device *dev, unsigned char address, unsigned char* data )
{
	if (!Wcusb_ReadWcRegs(dev, address, data, 1))
		return 0;

	return -1;
}

static int waitForProSlicIndirectRegAccess(struct usb_device *dev)
{
    unsigned char count, data;
    count = 0;
    while (count++ < 3)
	 {
		data = 0;
		readProSlicDirectReg(dev, I_STATUS, &data);

		if (!data)
			return 0;

	 }

    if(count > 2) printk(" ##### Loop error #####\n");

	return -1;
}

static int writeProSlicInDirectReg(struct usb_device *dev, unsigned char address, unsigned short data)
{
	
   if(!waitForProSlicIndirectRegAccess(dev))
	{
		if (!writeProSlicDirectReg(dev, IDA_LO,(unsigned char)(data & 0xFF)))
		{
			if(!writeProSlicDirectReg(dev, IDA_HI,(unsigned char)((data & 0xFF00)>>8)))
			{
				if(!writeProSlicDirectReg(dev, IAA,address))
					return 0;
			}
		}
	}

	return -1;
}

/*
**	Read register from ProSlic
*/
int readProSlicDirectReg(struct usb_device *dev, unsigned char address, unsigned char* dataRead)
{
	unsigned char data[4];

	data[0] = address | 0x80;
	data[1] = 0;
	data[2] = 0;
	data[3] = 0x67;

	// write to WC register 0x26
	Wcusb_WriteWcRegs(dev, WCUSB_SPORT0, data, 4);
	Wcusb_ReadWcRegs(dev, WCUSB_SPORT1, data, 1);
	*dataRead = data[0];

	return 0;
}

/*
**	Write register to ProSlic
*/
int writeProSlicDirectReg(struct usb_device *dev, unsigned char address, unsigned char RegValue)
{
	unsigned char data[4];

	data[0] = address & 0x7f;
	data[1] = RegValue;
	data[2] = 0;
	data[3] = 0x27;

	// write to WC register 0x26
	return Wcusb_WriteWcRegs(dev, WCUSB_SPORT0, data, 4);
}

static int readProSlicInDirectReg(struct usb_device *dev, unsigned char address, unsigned short *data)
{ 
    if (!waitForProSlicIndirectRegAccess(dev))
	 {
		if (!writeProSlicDirectReg(dev,IAA,address))
		{
			if(!waitForProSlicIndirectRegAccess(dev))
			{
				unsigned char data1, data2;

				if (!readProSlicDirectReg(dev,IDA_LO, &data1) && !readProSlicDirectReg (dev, IDA_HI, &data2))
				{
					*data = data1 | (data2 << 8);
					return 0;
				} else 
					printk("Failed to read direct reg\n");
			} else
				printk("Failed to wait inside\n");
		} else
			printk("failed write direct IAA\n");
	 } else
	 	printk("failed to wait\n");

    return -1;
}

static int initializeIndirectRegisters(struct usb_device *dev)
{
	unsigned char i;

	for (i=0; i<43; i++)
	{
		if(writeProSlicInDirectReg(dev, i,indirect_regs[i].initial))
			return -1;
	}

	return 0;
}

static int verifyIndirectRegisters(struct usb_device *dev)
{ 
	int passed = 1;
	unsigned short i,j, initial;

	for (i=0; i<43; i++) 
	{
		if(readProSlicInDirectReg(dev, (unsigned char) i, &j)) {
			printk("Failed to read indirect register %d\n", i);
			return -1;
		}
		initial= indirect_regs[i].initial;

		if ( j != initial )
		{
			 printk("!!!!!!! %s  iREG %X = %X  should be %X\n",
				indirect_regs[i].name,i,j,initial );
			 passed = 0;
		}	
	}

    if (passed) {
		if (debug)
			printk("Init Indirect Registers completed successfully.\n");
    } else {
		printk(" !!!!! Init Indirect Registers UNSUCCESSFULLY.\n");
    }

	return 0;
}

static int calibrateAndActivateProSlic(struct usb_device *dev)
{ 
	unsigned char x;

	if(writeProSlicDirectReg(dev, 92, 0xc8))
		 return -1;

	if(writeProSlicDirectReg(dev, 97, 0))
		 return -1;

	if(writeProSlicDirectReg(dev, 93, 0x19))
		 return -1;

	if(writeProSlicDirectReg(dev, 14, 0))
		 return -1;

	if(writeProSlicDirectReg(dev, 93, 0x99))
		 return -1;

	if(!readProSlicDirectReg (dev, 93, &x))
	{
		if (debug)
			printk("DC Cal x=%x\n",x);

		if (!writeProSlicDirectReg(dev, 97, 0))
		{
		   if(!writeProSlicDirectReg(dev, CALIBR1, CALIBRATE_LINE))
			{
				unsigned char data;

				 if(!readProSlicDirectReg(dev, CALIBR1, &data))
						 return writeProSlicDirectReg(dev, LINE_STATE,ACTIVATE_LINE);
			}
		}
	}

	return -1;
}

static int InitProSlic(struct usb_device *dev)
{
    if (writeProSlicDirectReg(dev, 67, 0x0e)) 
		/* Disable Auto Power Alarm Detect and other "features" */
		 return -1;
    if (initializeIndirectRegisters(dev)) {
		printk(KERN_INFO "Indirect Registers failed to initialize.\n");
		 return -1;
	}
    if (verifyIndirectRegisters(dev)) {
		printk(KERN_INFO "Indirect Registers failed verification.\n");
		 return -1;
	}
    if (calibrateAndActivateProSlic(dev)) {
		printk(KERN_INFO "ProSlic Died on Activation.\n");
		 return -1;
	}
    if (writeProSlicInDirectReg(dev, 97, 0x0)) { // Stanley: for the bad recording fix
		 printk(KERN_INFO "ProSlic IndirectReg Died.\n");
		 return -1;
	}
    if (writeProSlicDirectReg(dev, 1, 0x2a)) { // U-Law GCI 8-bit interface
		 printk(KERN_INFO "ProSlic DirectReg Died.\n");
		 return -1;
	}
    if (writeProSlicDirectReg(dev, 2, 0))    // Tx Start count low byte  0
		 return -1;
    if (writeProSlicDirectReg(dev, 3, 0))    // Tx Start count high byte 0
		 return -1;
    if (writeProSlicDirectReg(dev, 4, 0))    // Rx Start count low byte  0
		 return -1;
    if (writeProSlicDirectReg(dev, 5, 0))    // Rx Start count high byte 0
		 return -1;
    if (writeProSlicDirectReg(dev, 8, 0x0))    // disable loopback
		 return -1;
    if (writeProSlicDirectReg(dev, 18, 0xff))     // clear all interrupt
		 return -1;
    if (writeProSlicDirectReg(dev, 19, 0xff)) 
		 return -1;
    if (writeProSlicDirectReg(dev, 20, 0xff)) 
		 return -1;
    if (writeProSlicDirectReg(dev, 21, 0x00)) 	// enable interrupt
		 return -1;
    if (writeProSlicDirectReg(dev, 22, 0x02)) 	// Loop detection interrupt
		 return -1;
    if (writeProSlicDirectReg(dev, 23, 0x01)) 	// DTMF detection interrupt
		 return -1;
    if (writeProSlicDirectReg(dev, 72, 0x20))
	    	return -1;
#ifdef BOOST_RINGER
	/* Beef up Ringing voltage to 89V */
	if (writeProSlicInDirectReg(dev, 23, 0x1d1))
			return -1;
#endif
	return 0;
}

static int InitHardware(struct wc_usb_pvt *p)
{
	struct usb_device *dev = p->dev;

	switch (p->devclass) {
		case WC_PROSLIC:
		if (wcoutp(dev, 0x12, 0x00))	// AUX6 as output, set to low
			return -1;

    		if (wcoutp(dev, 0x13, 0x40))	// AUX6 is output
      			return -1;

    		if (wcoutp(dev, 0, 0x50))	// extrst, AUX2 is suspend
      			return -1;

    		if (wcoutp(dev, 0x29, 0x20))	// enable SerialUP AUX pin definition
      			return -1;

    		if(wcoutp(dev, 0, 0x51))	// no extrst, AUX2 is suspend
      			return -1;
	/* Make sure there is no gain */
    		if (wcoutp(dev, 0x22, 0x00))
			return -1;
    		if (wcoutp(dev, 0x23, 0xf2))
        		return -1;
    		if (wcoutp(dev, 0x24, 0x00))
			return -1;
    		if (wcoutp(dev, 0x25, 0xc9))
			return -1;
    // Now initial Proslic
		if(InitProSlic(dev)) {
			printk("Failed to initialize proslic\n");
			return -1;
		}
		case WC_KEYPAD:
		set_aux_ctrl(p, WC_AUX0, 1);
		set_aux_ctrl(p, WC_AUX1, 1);
		set_aux_ctrl(p, WC_AUX2, 1);
		set_aux_ctrl(p, WC_AUX3, 1);
	}

	if (debug)
		printk("Setting up correct altsettings\n");

	/* Setup correct settings (8000 Hz, signed linear) */
	if (usb_set_interface(dev, 2, 1)) 
		printk("Unable to setup USB interface 2 to altsetting 1\n");
	if (usb_set_interface(dev, 3, 1))
		printk("Unable to setup USB interface 3 to altsetting 1\n");

    DPRINTK("<<< Exit InitHardware\n");
    return 0; 
}

static struct usb_device_id wc_dev_ids[] = {
	  /* This needs to be a USB audio device, and it needs to be made by us and have the right device ID */
	{ match_flags: (USB_DEVICE_ID_MATCH_INT_CLASS | USB_DEVICE_ID_MATCH_INT_SUBCLASS | USB_DEVICE_ID_MATCH_DEVICE),
	  bInterfaceClass: USB_CLASS_AUDIO,
	  bInterfaceSubClass: 1,
	  idVendor: 0x06e6,			
	  idProduct: 0x831c,		/* Product ID / Chip configuration (you can't change this) */
	  driver_info: (unsigned long)&wcusb,
	},
	{ match_flags: (USB_DEVICE_ID_MATCH_INT_CLASS | USB_DEVICE_ID_MATCH_INT_SUBCLASS | USB_DEVICE_ID_MATCH_DEVICE),
	  bInterfaceClass: USB_CLASS_AUDIO,
	  bInterfaceSubClass: 1,
	  idVendor: 0x06e6,			/*  */
	  idProduct: 0x831e,		/* Product ID / Chip configuration (you can't change this) */
	  driver_info: (unsigned long)&wcusb2,
	},
	{ match_flags: (USB_DEVICE_ID_MATCH_INT_CLASS | USB_DEVICE_ID_MATCH_INT_SUBCLASS | USB_DEVICE_ID_MATCH_DEVICE),
	  bInterfaceClass: USB_CLASS_AUDIO,
	  bInterfaceSubClass: 1,
	  idVendor: 0x06e6,			/*  */
	  idProduct: 0xb210,
	  driver_info: (unsigned long)&wc_usb_phone,
	},
	{ }	/* Terminating Entry */
};

// Don't call from an interrupt context
static int set_aux_ctrl(struct wc_usb_pvt *p, char uauxpins, int on)
{
	char udata12 = 0;
	char udata13 = 0;

	wcinp(p->dev, 0x12, &udata12);
	wcinp(p->dev, 0x13, &udata13);

	wcoutp(p->dev, 0x12, on ? (uauxpins | udata12) : (~uauxpins & udata12));
	wcoutp(p->dev, 0x13, uauxpins | udata13);

	return 0;
}
	
static void wcusb_check_keypad(struct wc_usb_pvt *p)
{
	struct wc_keypad_data *d = p->pvt_data;

	if (!d->running) {
		printk("Stopping keypad stream\n");
		return;
	}
	if (debug) printk("Launched a packet\n");
	d->state = STATE_FOR_LOOP_1_OUT;
	d->data = -1;
	d->data12 = -1;
	d->scanned_event = -1;
	d->i = 0;
	wcusb_async_read(p, 0x12, &d->data12, 1, 0, keypad_check_done);
	return;
}

static char wc_dtmf(struct wc_usb_pvt *p)
{
	struct wc_keypad_data *d = p->pvt_data;
	short linsample = 0;

	if (!d) {
		printk("NULL pointer, go away\n");
		return 0;
	}

	linsample = zt_tone_nextsample(&d->ts, d->tone);


	return ZT_LIN2MU(linsample);
}

static void wcusb_do_io(struct wc_usb_pvt *p, struct urb *out, struct urb *in)
{
	/* This function performs glues together the USB side
	   with the zaptel side, always doing things in receive/transmit
	   order */

	int x;
	short *ochunk = out->transfer_buffer;
	short *ichunk = in->transfer_buffer;

	/* Perform input preparations */
	switch (p->sample) {
		case STREAM_NORMAL:
			for (x = 0; x < ZT_CHUNKSIZE; x++) {
				p->chan.readchunk[x] = ZT_LIN2MU(le16_to_cpu(ichunk[x]));
			}

			break;
		case STREAM_DTMF:
			for (x = 0; x < ZT_CHUNKSIZE; x++) {
				p->chan.readchunk[x] = wc_dtmf(p);
			}
			break;
	}

	/* Work with Zaptel now */
	/* XXX Might be able to optimize this some XXX */
	zt_ec_chunk(&p->chan, p->chan.readchunk, p->chan.writechunk);
	zt_receive(&p->span);
	zt_transmit(&p->span);

	/* Fill in transmission info  */
	for (x = 0; x < ZT_CHUNKSIZE; x++) {
		ochunk[x] = ZT_MULAW(cpu_to_le16(p->chan.writechunk[x]));
	}

	/* Transmit the pending outgoing urb */
	if (usb_submit_urb(out)) {
		printk("wcusb: 'write' urb failed\n");
	} else {
		p->urbcount++;
	}

	/* Readsubmit read URB */
	if (usb_submit_urb(in)) {
		printk("wcusb: 'read' urb failed\n");
	} else
		p->urbcount++;
	/* Clear I/O state */
	p->iostate = 0;
}

static void wcusb_read_complete(struct urb *q)
{
	struct wc_usb_pvt *p = q->context;

	/* Decrement number of outstanding URB's */
	p->urbcount--;

	if (!p->flags & FLAG_RUNNING) {
		/* Stop sending URBs since we're not running anymore */
		return;
	}


	/* Prepare for retransmission */
	q->dev = p->dev;

	if (p->iostate & WC_IO_READ) {
		static int notify=0;
		if (!notify)
			printk("Already ready to read?\n");
		notify++;
	}

	/* Note that our read is now complete */
	p->iostate |= WC_IO_READ;

	if (IO_READY(p->iostate)) {
		/* Transmit side is complete, lets go */
		wcusb_do_io(p, p->pendingurb, q);
	} else {
		/* Let the transmission side know we're
		   ready to go again */
		p->pendingurb = q;
	}

	if (p->timer && !--p->timer) {
		if (p->devclass == WC_KEYPAD) {
			if(debug) printk("Checking keypad\n");
			wcusb_check_keypad(p);
		} else {
			wcusb_check_interrupt(p);
		}
	}

#ifdef PROSLIC_POWERSAVE
	if (p->devclass != WC_KEYPAD) {
		if (p->lowpowertimer && !--p->lowpowertimer) {
			/* Switch back into low power mode */
			p->idletxhookstate = 1;
			if (p->txhook == 2)
				p->newtxhook = p->idletxhookstate;
		}
	}
#endif	
	return;
}

static void wcusb_write_complete(struct urb *q)
{
	struct wc_usb_pvt *p = q->context;

	/* Decrement counter */
	p->urbcount--;
	if (!p->flags & FLAG_RUNNING) {
		/* Stop sending URBs since we're not running anymore */
		return;
	}

	if (p->iostate & WC_IO_WRITE) {
		static int notify=0;
		if (!notify)
			printk("Already ready to write?\n");
		notify++;
	}

	/* Prepare for retransmission */
	p->iostate |= WC_IO_WRITE;
	q->dev = p->dev;
	
	if (IO_READY(p->iostate)) {
		/* Receive is already done, lets go */
		wcusb_do_io(p, q, p->pendingurb);
	} else {
		/* Let the receive side know we're
		   ready to go again */
		p->pendingurb = q;
	}

}

static int StopTransmit(struct wc_usb_pvt *p)
{
	p->flags &= ~FLAG_RUNNING;

	if (p->devclass == WC_KEYPAD) {
		struct wc_keypad_data *d = p->pvt_data;
		d->running = 0;
	}
	while(p->urbcount) {
		schedule_timeout(1);
	}
	printk("ending transmit\n");
	return 0;
}

static int flip_relays(struct wc_usb_pvt *p, int onoff)
{
    unsigned char ctl;
    unsigned char data;
    /* Read data */
    if (wcinp(p->dev, 0x12, &data))
	return -1;
    /* Read control */
    if (wcinp(p->dev, 0x13, &ctl))
	return -1;
    /* Setup values properly -- Pins AUX3 & AUX4 control the relays */
    ctl |= 0x18;
    if (onoff) {
	data |= 0x18;
    } else {
	data &= 0xe7;
    }
    if (wcoutp(p->dev, 0x12, data))
	return -1;
    if (wcoutp(p->dev, 0x13, ctl))
	return -1;
    return 0;
}

static int InitPrivate(struct wc_usb_pvt *p)
{
	int x;
	unsigned int readpipe;
	unsigned int writepipe;
	/* Endpoint 6 is the wave-in device */
	readpipe = usb_rcvisocpipe(p->dev, 0x06);

	/* Endpoint 7 is the wave-out device */
	writepipe = usb_sndisocpipe(p->dev, 0x07);


	for (x=0;x<2;x++) {
		p->dataread[x].urb.dev = p->dev;
		p->dataread[x].urb.pipe = readpipe;
		p->dataread[x].urb.transfer_flags = USB_ISO_ASAP;
		p->dataread[x].urb.number_of_packets = 1;
		p->dataread[x].urb.context = p;
		p->dataread[x].urb.complete = wcusb_read_complete;
		p->dataread[x].urb.iso_frame_desc[0].length = ZT_CHUNKSIZE * 2;
		p->dataread[x].urb.iso_frame_desc[0].offset = 0;
		p->dataread[x].urb.transfer_buffer = p->readchunk + ZT_CHUNKSIZE * x;
		p->dataread[x].urb.transfer_buffer_length = ZT_CHUNKSIZE * 2;

		p->datawrite[x].urb.dev = p->dev;
		p->datawrite[x].urb.pipe = writepipe;
		p->datawrite[x].urb.transfer_flags = USB_ISO_ASAP;
		p->datawrite[x].urb.number_of_packets = 1;
		p->datawrite[x].urb.context = p;
		p->datawrite[x].urb.complete = wcusb_write_complete;
		p->datawrite[x].urb.iso_frame_desc[0].length = ZT_CHUNKSIZE * 2;
		p->datawrite[x].urb.iso_frame_desc[0].offset = 0;
		p->datawrite[x].urb.transfer_buffer = p->writechunk + ZT_CHUNKSIZE * x;
		p->datawrite[x].urb.transfer_buffer_length = ZT_CHUNKSIZE * 2;

	}


	return 0;
}

static int InitTransfer(struct wc_usb_pvt *p)
{

	int x;
	p->urbcount = 4;
	p->flags |= FLAG_RUNNING;

	for (x=0;x<2;x++) {
		if (usb_submit_urb(&p->dataread[x].urb)) {
			printk(KERN_ERR "wcusb: Read submit failed\n");
			return -1;
		}
		if (usb_submit_urb(&p->datawrite[x].urb)) {
			printk(KERN_ERR "wcusb: Write submit failed\n");
			return -1;
		}
	}
	/* Start checking for interrupts */
	wcusb_check_interrupt(p);
	return 0;
}

static int wc_usb_hooksig(struct zt_chan *chan, zt_txsig_t txsig)
{
	struct wc_usb_pvt *p = chan->pvt;

	switch (p->devclass) {
		case WC_PROSLIC:
#ifdef PROSLIC_POWERSAVE
			if (p->txhook == 4) {
				/* Switching out of ring...  Be sure we idle at 2, not 1 at least
				    for a bit so we can transmit caller*ID */
				p->idletxhookstate = 2;
				p->lowpowertimer = POWERSAVE_TIME;
			}
#endif	
	
			p->txhook = -1;
			switch(txsig) {
				case ZT_TXSIG_ONHOOK:
					switch(chan->sig) {
						case ZT_SIG_FXOKS:
						case ZT_SIG_FXOLS:
							p->newtxhook = p->idletxhookstate;
							break;
						case ZT_SIG_FXOGS:
							p->newtxhook = 3;
							break;
					}
				break;
				case ZT_TXSIG_OFFHOOK:
					p->newtxhook = p->idletxhookstate;
					break;
				case ZT_TXSIG_START:
					p->newtxhook = 4;
					break;
				case ZT_TXSIG_KEWL:
					p->newtxhook = 0;
					break;
			}
		case WC_KEYPAD:
			switch (txsig) {
				case ZT_TXSIG_ONHOOK:
					break;
				case ZT_TXSIG_OFFHOOK:
					break;
				case ZT_TXSIG_START:
					break;
				case ZT_TXSIG_KEWL:
					break;
			}
			break;
	}
	return 0;
}

static int wc_usb_open(struct zt_chan *chan)
{
	struct wc_usb_pvt *p = chan->pvt;
	if (p->dead)
		return -1;
	switch (p->devclass) {
		case WC_KEYPAD:
			p->hookstate = 0;
			zt_hooksig(&p->chan, ZT_RXSIG_ONHOOK);
			break;
		default:
			break;
	}
#ifndef LINUX26
	MOD_INC_USE_COUNT;
#endif
	p->usecount++;
	return 0;
}

static int wc_usb_close(struct zt_chan *chan)
{
	struct wc_usb_pvt *p = chan->pvt;
	p->usecount--;
	if (!p->usecount && p->dead) {
		/* Someone unplugged us while we were running, so now
		   that the program exited, we can release our resources */
		zt_unregister(&p->span);
		ifaces[p->pos] = NULL;
		if (p->pvt_data)
			kfree(p->pvt_data);
		kfree(p);
	}
#ifndef LINUX26
	MOD_DEC_USE_COUNT;
#endif
	return 0;
}

static int init_device_pvt(struct wc_usb_pvt *p)
{
	struct usb_device *dev = p->dev;

	if (dev->descriptor.idProduct == 0xb210) {
		struct wc_keypad_data *d = kmalloc(sizeof(struct wc_keypad_data), GFP_KERNEL);
		printk("wcusb: Found a WC Keyed Phone\n");
		p->devclass = WC_KEYPAD;
		if (!d) {
			printk("wcusb: kmalloc failed in init_device_pvt\n");
			return -1;
		}
		memset(d, 0, sizeof(struct wc_keypad_data));
		p->pvt_data = d;
		d->count = 0;
		d->running = 1;
		d->tone = NULL;
		return 0;
	} else {
		p->pvt_data = NULL;
		p->devclass = WC_PROSLIC;
	}
	return 0;
}
	
static void *wc_usb_probe(struct usb_device *dev, unsigned int ifnum, const struct usb_device_id *id)
{
	struct usb_config_descriptor *config = dev->actconfig;
	struct wc_usb_pvt *p=NULL;
	struct wc_usb_desc *d = (struct wc_usb_desc *)id->driver_info;
#if 0
	char auxcon = 0;
#endif
	int x;
	for (x=0;x<WC_MAX_IFACES;x++)
		if (!ifaces[x]) break;
	if (x >= WC_MAX_IFACES) {
		printk("Too many interfaces\n");
		goto fail;
	}

	p = kmalloc(sizeof(struct wc_usb_pvt), GFP_KERNEL);

	if (!p)
		goto fail;

	memset(p, 0, sizeof(struct wc_usb_pvt));
	p->hardwareflags = d->flags;
	sprintf(p->span.name, "WCUSB/%d", x);
	sprintf(p->span.desc,"%s %d", d->name, x);
	sprintf(p->chan.name, "WCUSB/%d/%d", x, 0);
#if 0	/* Make them choose with zaptel.conf */
	p->chan.sig = ZT_SIG_FXOKS;					/* Assume FXOKS signalling for starters */
#endif
	p->chan.sigcap = ZT_SIG_FXOKS | ZT_SIG_FXOLS | ZT_SIG_FXOGS;	/* We're capabable of both FXOKS and FXOLS */
	p->chan.chanpos = 1;
	p->span.deflaw = ZT_LAW_MULAW;
	p->span.chans = &p->chan;
	p->span.channels = 1;
	p->span.hooksig = wc_usb_hooksig;
	p->span.open = wc_usb_open;
	p->span.close = wc_usb_close;
	p->dev = dev;
	p->pos = x;
	p->span.flags = ZT_FLAG_RBS;
	init_waitqueue_head(&p->span.maintq);
	p->span.pvt = p;
	p->chan.pvt = p;
#ifdef PROSLIC_POWERSAVE
	/* By default we can't send on hook */
	p->idletxhookstate = 1;
#else
	/* By default we can always send on hook */
	p->idletxhookstate = 2;	
#endif	
	ifaces[x] = p;
	p->sample = STREAM_NORMAL;

	if (init_device_pvt(p)) {
		printk(KERN_ERR "wcusb: init_device_pvt failed\n");
		goto fail;
	}
	
	if (usb_set_configuration(dev, dev->config[0].bConfigurationValue) < 0) {
		printk(KERN_ERR "wcusb: set_configuration failed (ConfigValue 0x%x)\n", config->bConfigurationValue);
		goto fail;
	}
	if (InitHardware(p)) {
		printk(KERN_ERR "wcusb: Hardware initialization failed\n");
		goto fail;
	}

	if (InitPrivate(p)) {
		printk(KERN_ERR "wcusb: Unable to initialize private data structure\n");
		goto fail;
	}
	if (p->hardwareflags & FLAG_FLIP_RELAYS) {
		flip_relays(p, 1);
	}

	if (zt_register(&p->span, 0)) {
		printk("Unable to register span %s\n", p->span.name);
		goto fail;
	}

	if (InitTransfer(p)) {
		printk(KERN_ERR "wcusb: Unable to begin data flow\n");
		goto fail;
	}
	printk("wcusb: Found a %s\n", d->name);
#if 0
	wcinp(p->dev, 0x13, &auxcon);
	printk("Register 0x13 is set to %x\n",auxcon);
#endif
	
	return p;
fail:
	if (x < WC_MAX_IFACES)
		ifaces[x] = NULL;
	if (p) {
		if (p->pvt_data) {
			kfree(p->pvt_data);
		}
		kfree(p);
	}
	return NULL;
}

static void wc_usb_disconnect(struct usb_device *dev, void *ptr)
{
	/* Doesn't handle removal if we're in use right */
	struct wc_usb_pvt *p = ptr;
	if (ptr) {
		StopTransmit(p);
		if (!p->usecount) {
			zt_unregister(&p->span);
			ifaces[p->pos] = NULL;
			if (p->pvt_data)
				kfree(p->pvt_data);
			kfree(ptr);
		} else {
			/* Generate alarm and note that we're dead */
			p->span.alarms = ZT_ALARM_RED;
			zt_alarm_notify(&p->span);
			p->dead = 1;
		}
	}
	printk("wcusb: Removed a Wildcard device\n");
	return;
}

static struct usb_driver wc_usb_driver =
{
	name: "wcusb",
	probe: wc_usb_probe,
	disconnect: wc_usb_disconnect,
	fops: NULL,
	minor: 0,
	id_table: wc_dev_ids,
};

static int __init wc_init (void) 
{
	int res;
	res = usb_register(&wc_usb_driver);
	if (res)
		return res;
	printk("Wildcard USB FXS Interface driver registered\n");
	return 0;
}	  

static void __exit wc_cleanup(void)
{
	usb_deregister(&wc_usb_driver);
}

MODULE_AUTHOR("Mark Spencer <markster@linux-support.net>");
MODULE_DESCRIPTION("Wildcard USB FXS Interface driver");
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif
MODULE_PARM(debug, "i");

MODULE_DEVICE_TABLE(usb, wc_dev_ids);

module_init(wc_init);
module_exit(wc_cleanup);

