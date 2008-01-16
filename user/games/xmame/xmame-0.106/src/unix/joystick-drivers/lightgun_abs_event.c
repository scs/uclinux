/*
 * Linux ABS event driven (/dev/input/event*) lightgun support.
 *
 * Copyright (C) 2003  Ben Collins <bcollins@debian.org>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifdef USE_LIGHTGUN_ABS_EVENT

#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <poll.h>

#include "xmame.h"
#include "devices.h"

#include <linux/input.h>

#include "lightgun_abs_event.h"

enum { LG_X_AXIS, LG_Y_AXIS, LG_MAX_AXIS };

#define test_bit(bit, array)	(array[bit/8] & (1<<(bit%8)))

#ifdef LIGHTGUN_DEFINE_INPUT_ABSINFO
struct input_absinfo {
	int abs;
	int minimum;
	int maximum;
	int fuzz;
	int flat;
};
#endif

struct lg_dev {
	char *device;
	int last[LG_MAX_AXIS];
	int min[LG_MAX_AXIS];
	int range[LG_MAX_AXIS];
	int fd;
};

static struct lg_dev lg_devices[GUN_MAX];

/* Options */
struct rc_option lightgun_abs_event_opts[] = {
	{ "evabs-lightgun1",		"evabslg1",	rc_string,
	  &lg_devices[0].device,	NULL,	1,	0,	NULL,
	  "Device name for lightgun of player 1" },

	{ "evabs-lightgun2",		"evabslg2",	rc_string,
	  &lg_devices[1].device,	NULL,	1,	0,	NULL,
	  "Device name for lightgun of player 2" },

	{ "evabs-lightgun3",		"evabslg3",	rc_string,
	  &lg_devices[2].device,	NULL,	1,	0,	NULL,
	  "Device name for lightgun of player 3" },

	{ "evabs-lightgun4",		"evabslg4",	rc_string,
	  &lg_devices[3].device,	NULL,	1,	0,	NULL,
	  "Device name for lightgun of player 4" },

	{ NULL, NULL, rc_end, NULL, NULL, 0, 0, NULL, NULL }
};

void lightgun_event_abs_init(void)
{
	int i;

	for (i = 0; i < GUN_MAX; i++) {
		char name[256] = "Unknown";
		uint8_t abs_bitmask[ABS_MAX/8 + 1];
		struct input_absinfo abs_features;

		if (!lg_devices[i].device)
			continue;

		if ((lg_devices[i].fd = open(lg_devices[i].device, O_RDONLY)) < 0) {
			fprintf(stderr_file, "Lightgun%d: %s[open]: %s",
				i + 1, lg_devices[i].device, strerror(errno));
			continue;
		}

		if (ioctl(lg_devices[i].fd, EVIOCGNAME(sizeof(name)), name) < 0) {
			fprintf(stderr_file, "Lightgun%d: %s[ioctl/EVIOCGNAME]: %s\n",
				i + 1, lg_devices[i].device, strerror(errno));
			lg_devices[i].device = NULL;
			continue;
		}

		memset(abs_bitmask, 0, sizeof(abs_bitmask));
		if (ioctl(lg_devices[i].fd, EVIOCGBIT(EV_ABS, sizeof(abs_bitmask)), abs_bitmask) < 0) {
			fprintf(stderr_file, "Lightgun%d: %s[ioctl/EVIOCGNAME]: %s\n",
				i + 1, lg_devices[i].device, strerror(errno));
			lg_devices[i].device = NULL;
			continue;
		}

		/* Make sure we have an X and Y axis. Not much good
		 * without it. */
		if (!test_bit(ABS_X, abs_bitmask) || !test_bit(ABS_Y, abs_bitmask)) {
			fprintf(stderr_file, "Lightgun%d: %s: Does not contain both X and Y axis, "
				"ignoring\n", i + 1, lg_devices[i].device);
			lg_devices[i].device = NULL;
			continue;
		}

		if (ioctl(lg_devices[i].fd, EVIOCGABS(ABS_X), &abs_features)) {
			fprintf(stderr_file, "Lightgun%d: %s[ioctl/EVIOCGABS(ABX_X)]: %s\n",
				i + 1, lg_devices[i].device, strerror(errno));
			lg_devices[i].device = NULL;
			continue;
		}

		lg_devices[i].min[LG_X_AXIS] = abs_features.minimum;
		lg_devices[i].range[LG_X_AXIS] = abs_features.maximum - abs_features.minimum;

		if (ioctl(lg_devices[i].fd, EVIOCGABS(ABS_Y), &abs_features)) {
			fprintf(stderr_file, "Lightgun%d: %s[ioctl/EVIOCGABS(ABX_Y)]: %s\n",
				i + 1, lg_devices[i].device, strerror(errno));
			lg_devices[i].device = NULL;
			continue;
		}

		lg_devices[i].min[LG_Y_AXIS] = abs_features.minimum;
		lg_devices[i].range[LG_Y_AXIS] = abs_features.maximum - abs_features.minimum;

		fprintf(stderr_file, "Lightgun%d: %s\n", i + 1, name);
		fprintf(stderr_file, "           X axis:  min[%d]  range[%d]\n",
			lg_devices[i].min[LG_X_AXIS], lg_devices[i].range[LG_X_AXIS]);
		fprintf(stderr_file, "           Y axis:  min[%d]  range[%d]\n",
			lg_devices[i].min[LG_Y_AXIS], lg_devices[i].range[LG_Y_AXIS]);
	}
}

void lightgun_event_abs_poll(void)
{
	int i, fds, rd;
	struct pollfd pfd[GUN_MAX];

	for (i = fds = 0; i < GUN_MAX; i++) {
		if (!lg_devices[i].device)
			continue;

		pfd[fds].events = POLLIN;
		pfd[fds].fd = lg_devices[i].fd;
		pfd[fds].revents = 0;

		fds++;
	}

	if (!fds)
		return;

	rd = poll(pfd, fds, 0);

	for (i = 0; i < GUN_MAX; i++) {
		int p, t;
		size_t rd;
		struct input_event events[16];

		if (!lg_devices[i].device)
			continue;

		for (p = 0; p < fds; p++)
			if (pfd[p].fd == lg_devices[i].fd)
				break;

		if (pfd[p].revents & (POLLNVAL | POLLERR)) {
			fprintf(stderr_file, "Lightgun%d: %s[poll]: Error, ignoring device\n",
				i + 1, lg_devices[i].device);
			lg_devices[i].device = NULL;
			close(lg_devices[i].fd);
			continue;
		}

		if (!(pfd[p].revents & POLLIN))
			continue;

		rd = read(lg_devices[i].fd, events, sizeof(events));

		for (t = 0; t < (rd / sizeof(*events)); t++) {
			struct input_event *ev = &events[t];

			/* XXX The BTN_MIDDLE and BTN_SIDE are specific to
			 * ACT LABS lightguns. May not be the same for
			 * other guns. */

			if (ev->type == EV_ABS && ev->code == ABS_X) {
				lg_devices[i].last[LG_X_AXIS] = ev->value;
			} else if (ev->type == EV_ABS && ev->code == ABS_Y) {
				lg_devices[i].last[LG_Y_AXIS] = ev->value;
			} else if (ev->type == EV_KEY && (ev->code == BTN_MIDDLE
						|| ev->code == BTN_MOUSE
						|| ev->code == BTN_6)) {
				sysdep_display_mouse_data[i].buttons[0] = ev->value;
			} else if (ev->type == EV_KEY && (ev->code == BTN_SIDE 
						|| ev->code == BTN_RIGHT
						|| ev->code == BTN_7)) {
				lg_devices[i].last[LG_X_AXIS] =
					lg_devices[i].min[LG_X_AXIS];
				lg_devices[i].last[LG_Y_AXIS] =
					lg_devices[i].min[LG_Y_AXIS];
                                sysdep_display_mouse_data[i].buttons[0] = ev->value;
			}
		}
	}

	return;
}

int lightgun_event_abs_read(int joynum, int joyindex, int *val)
{
	if (joynum > GUN_MAX || !lg_devices[joynum].device
			|| joyindex >= LG_MAX_AXIS)
		return 0;

	/* Map onto the range ANALOG_VALUE_MIN..ANALOG_VALUE_MAX. */
	if (joyindex == 0)
		*val = (INT64)(lg_devices[joynum].last[LG_X_AXIS] - (lg_devices[joynum].min[LG_X_AXIS] + lg_devices[joynum].range[LG_X_AXIS] / 2)) * (INT64)(ANALOG_VALUE_MAX - ANALOG_VALUE_MIN) / (INT64)lg_devices[joynum].range[LG_X_AXIS];
	else
		*val = (INT64)(lg_devices[joynum].last[LG_Y_AXIS] - (lg_devices[joynum].min[LG_Y_AXIS] + lg_devices[joynum].range[LG_Y_AXIS] / 2)) * (INT64)(ANALOG_VALUE_MAX - ANALOG_VALUE_MIN) / (INT64)lg_devices[joynum].range[LG_Y_AXIS];

	if (*val < ANALOG_VALUE_MIN)
		*val = ANALOG_VALUE_MIN;
	else if (*val > ANALOG_VALUE_MAX)
		*val = ANALOG_VALUE_MAX;

	return 1;
}

#endif /* USE_LIGHTGUN_ABS_EVENT */
