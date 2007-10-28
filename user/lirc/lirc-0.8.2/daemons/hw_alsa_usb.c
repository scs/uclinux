/*      $Id: hw_alsa_usb.c,v 5.2 2005/07/10 08:34:11 lirc Exp $   */

/****************************************************************************
 ** hw_alsa_usb.c ***********************************************************
 ****************************************************************************
 *
 * routines for Sound Blaster USB audio devices accessed via ALSA hwdep
 *
 * Copyright (c) 2005 Clemens Ladisch <clemens@ladisch.de>
 *
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <alsa/asoundlib.h>

#include "lircd.h"
#include "hardware.h"

static int init(void);
static int deinit(void);
static int decode(struct ir_remote *remote,
		  ir_code *prep, ir_code *codep, ir_code *postp,
		  int *repeat_flagp, lirc_t *remaining_gapp);
static char *rec(struct ir_remote *remotes);

static ir_code code, last_code;
static snd_hwdep_t *hwdep;
static struct timeval last_time;
static int repeat_flag;

struct hardware hw_alsa_usb = {
	"",			/* default device */
	-1,			/* fd */
	LIRC_CAN_REC_CODE,	/* features */
	0,			/* send_mode */
	LIRC_MODE_CODE,		/* rec_mode */
	8,			/* code_length */
	init,			/* init_func */
	NULL,			/* config_func */
	deinit,			/* deinit_func */
	NULL,			/* send_func */
	rec,			/* rec_func */
	decode,			/* decode_func */
	NULL,                   /* ioctl_func */
	NULL,			/* readdata */
	"alsa_usb"
};

static const char *search_device(void)
{
	int card, err;
	snd_hwdep_info_t *info;

	snd_hwdep_info_alloca(&info);
	card = -1;
	while (snd_card_next(&card) >= 0 && card >= 0) {
		char ctl_name[20];
		snd_ctl_t *ctl;
		int device;

		sprintf(ctl_name, "hw:CARD=%d", card);
		err = snd_ctl_open(&ctl, ctl_name, SND_CTL_NONBLOCK);
		if (err < 0)
			continue;
		device = -1;
		while (snd_ctl_hwdep_next_device(ctl, &device) >= 0 && device >= 0) {
			snd_hwdep_info_set_device(info, device);
			err = snd_ctl_hwdep_info(ctl, info);
			if (err >= 0 &&
			    snd_hwdep_info_get_iface(info) == SND_HWDEP_IFACE_SB_RC) {
				static char name[36];

				sprintf(name, "hw:CARD=%d,DEV=%d", card, device);
				snd_ctl_close(ctl);
				return name;
			}
		}
		snd_ctl_close(ctl);
	}
	return NULL;
}

static int init(void)
{
	const char *device;
	snd_hwdep_info_t *info;
	struct pollfd pollfd;
	int err;

	device = hw.device;
	if (!device || !*device) {
		device = search_device();
		if (!device) {
			logprintf(LOG_ERR, "device not found");
			return 0;
		}
	}
	err = snd_hwdep_open(&hwdep, device, SND_HWDEP_OPEN_READ);
	if (err < 0) {
		logprintf(LOG_ERR, "cannot open %s: %s",
			  device, snd_strerror(err));
		return 0;
	}
	snd_hwdep_info_alloca(&info);
	err = snd_hwdep_info(hwdep, info);
	if (err < 0) {
		snd_hwdep_close(hwdep);
		logprintf(LOG_ERR, "cannot get hwdep info: %s",
			  snd_strerror(err));
		return 0;
	}
	if (snd_hwdep_info_get_iface(info) != SND_HWDEP_IFACE_SB_RC) {
		snd_hwdep_close(hwdep);
		logprintf(LOG_ERR, "%s is not a Sound Blaster remote control device",
			  device);
		return 0;
	}
	err = snd_hwdep_poll_descriptors(hwdep, &pollfd, 1);
	if (err < 0) {
		snd_hwdep_close(hwdep);
		logprintf(LOG_ERR, "cannot get file descriptor: %s",
			  snd_strerror(err));
		return 0;
	}
	if (err != 1) {
		snd_hwdep_close(hwdep);
		logprintf(LOG_ERR, "invalid number of file descriptors (%d): %s",
			  err, snd_strerror(err));
		return 0;
	}
	hw.fd = pollfd.fd;
	return 1;
}

static int deinit(void)
{
	snd_hwdep_close(hwdep);
	hw.fd = -1;
	return 1;
}

static char *rec(struct ir_remote *remotes)
{
	unsigned char rc_code;
	ssize_t size;
	struct timeval current;

	size = snd_hwdep_read(hwdep, &rc_code, 1);
	if (size < 1)
		return NULL;
	gettimeofday(&current, NULL);
	last_code = code;
	code = (ir_code)rc_code;
	/* delay for repeating buttons is up to 320 ms */
	repeat_flag = code == last_code &&
		current.tv_sec - last_time.tv_sec <= 2 &&
		time_elapsed(&last_time, &current) <= 350000;
	last_time = current;
	LOGPRINTF(1, "code: %llx", (unsigned long long) code);
	LOGPRINTF(1, "repeat_flag: %d", repeat_flag);
	return decode_all(remotes);
}

static int decode(struct ir_remote *remote,
		  ir_code *prep, ir_code *codep, ir_code *postp,
		  int *repeat_flagp, lirc_t *remaining_gapp)
{
	if(!map_code(remote,prep,codep,postp,0,0,8,code,0,0))
	{
		return(0);
	}
	*repeat_flagp = repeat_flag;
	*remaining_gapp = 0;
	return 1;
}
