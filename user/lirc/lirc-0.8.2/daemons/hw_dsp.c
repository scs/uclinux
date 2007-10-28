/*      $Id: hw_dsp.c,v 5.4 2005/07/10 08:34:11 lirc Exp $      */

/****************************************************************************
 ** hw_dsp.c ****************************************************************
 ****************************************************************************
 *
 * routines for diode in microphone input
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 * Copyright (C) 2001, 2002 Pavel Machek <pavel@ucw.cz>
 *
 * Distribute under GPL version 2 or later.
 *
 * This is hardware for "simplest ir receiver". Simplest ir receiver
 * consists of BPW34 receiving diode connected to your microphone
 * port. (Find a way where it generates loudest noise when you press
 * transmit ir near it).
 *
 * BPW34 is not good selection (range is about meter, I can get better
 * results with other diode), but at least its tested. If you know
 * better hw to use, let me know.
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/soundcard.h>

#include "hardware.h"
#include "ir_remote.h"
#include "lircd.h"
#include "receive.h"
#include "transmit.h"
#include "hw_default.h"

extern struct ir_remote *repeat_remote;

/*
  decoding stuff
*/

static int myfd = -1;

#define BUFSIZE 20
#define SAMPLE 47999


lirc_t dsp_readdata(lirc_t timeout)
{
	lirc_t data;
	static int lastlength, laststate;
	int i;
	signed short buf[BUFSIZE];
	double energy = 0.0;
	int state;

	while(1) {
		if (read(myfd, buf, BUFSIZE*2)!=BUFSIZE*2)
		{
			logperror(LOG_ERR,"could not read in simple...");
		}
	
		for (i=0; i<BUFSIZE-1; i++) {
			energy += ((double) buf[i]-buf[i+1])*
				((double) buf[i]-buf[i+1]);
		}
		energy /= BUFSIZE;
		energy /= 2E4;

		state = (energy > 2.0);
		if (state == laststate) {
			lastlength += ((1000000 / SAMPLE) * BUFSIZE);
		} else {
			data = lastlength | (laststate ? PULSE_BIT : 0);
			lastlength = ((1000000 / SAMPLE) * BUFSIZE);
			laststate = state;
			LOGPRINTF(1,"Pulse came %8x,  %8d...",
				  data, data & ~PULSE_BIT);
			return data;
		}

		timeout -= BUFSIZE*1000000 / SAMPLE;
		if (timeout <= 0)
			return 0;
	}
	return 0;
}

/*
  interface functions
*/

int dsp_init()
{
        int speed = SAMPLE, fmt = AFMT_S16_LE;
	
	logprintf(LOG_INFO,"Initializing %s...",hw.device);
	init_rec_buffer();
	if((hw.fd=open(hw.device,O_RDONLY))<0)
	{
		logprintf(LOG_ERR,"could not open %s",hw.device);
		logperror(LOG_ERR,"dsp_init()");
		return(0);
	}

        if (ioctl(hw.fd, SNDCTL_DSP_SPEED, &speed)<0)
	{
		logprintf(LOG_ERR,"could not ioctl(SPEED) on %s",hw.device);
		logperror(LOG_ERR,"dsp_init()");
		return(0);
	}
	if (speed != SAMPLE)
	{
		logprintf(LOG_ERR,"wrong speed handshaked on %s",hw.device);
		logperror(LOG_ERR,"dsp_init()");
		return(0);
	}
        if (ioctl(hw.fd, SNDCTL_DSP_SETFMT, &fmt)<0)
	{
		logprintf(LOG_ERR,"could not ioctl(SETFMT) on %s",hw.device);
		logperror(LOG_ERR,"dsp_init()");
		return(0);
	}
	if (fmt != AFMT_S16_LE)
	{
		logprintf(LOG_ERR,"wrong format handshaked on %s",hw.device);
		logperror(LOG_ERR,"dsp_init()");
		return(0);
	}
	myfd = hw.fd;
	/* select on soundcard does not work */
	hw.fd = open("/dev/zero", O_RDONLY);
	return(1);
}

int dsp_deinit(void)
{
	close(hw.fd);
	close(myfd);
	return(1);
}

char *dsp_rec(struct ir_remote *remotes)
{
	if(!clear_rec_buffer()) return(NULL);
	return(decode_all(remotes));
}

int dsp_decode(struct ir_remote *remote,
		   ir_code *prep,ir_code *codep,ir_code *postp,
		   int *repeat_flagp,lirc_t *remaining_gapp)
{
	return(receive_decode(remote,prep,codep,postp,
			      repeat_flagp,remaining_gapp));
}


struct hardware hw_dsp=
{
	"/dev/dsp",	    /* simple device */
	-1,                 /* fd */
	LIRC_CAN_REC_MODE2, /* features */
	0,                  /* send_mode */
	LIRC_MODE_MODE2,    /* rec_mode */
	0,                  /* code_length */
	dsp_init,           /* init_func */
	NULL,               /* config_func */
	dsp_deinit,         /* deinit_func */
	NULL,               /* send_func */
	dsp_rec,            /* rec_func */
	dsp_decode,         /* decode_func */
	NULL,               /* ioctl_func */
	dsp_readdata,
	"dsp"
};
