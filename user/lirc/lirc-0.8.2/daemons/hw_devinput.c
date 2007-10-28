/****************************************************************************
 ** hw_devinput.c ***********************************************************
 ****************************************************************************
 *
 * receive keycodes input via /dev/input/...
 * 
 * Copyright (C) 2002 Oliver Endriss <o.endriss@gmx.de>
 *
 * Distribute under GPL version 2 or later.
 *
 */

/*
  TODO:

  - use more than 32 bits (?)
  
  CB
  
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <fnmatch.h>

#include <linux/input.h>

#ifndef EV_SYN
/* previous name */
#define EV_SYN EV_RST
#endif

#include "hardware.h"
#include "ir_remote.h"
#include "lircd.h"
#include "receive.h"


static int devinput_init();
static int devinput_deinit(void);
static int devinput_decode(struct ir_remote *remote,
			   ir_code *prep, ir_code *codep, ir_code *postp,
			   int *repeat_flagp, lirc_t *remaining_gapp);
static char *devinput_rec(struct ir_remote *remotes);

enum locate_type {
	locate_by_name,
	locate_by_phys,
};

struct hardware hw_devinput=
{
	"/dev/input/event0",	/* "device" */
	-1,			/* fd (device) */
	LIRC_CAN_REC_LIRCCODE,	/* features */
	0,			/* send_mode */
	LIRC_MODE_LIRCCODE,	/* rec_mode */
	32,			/* code_length */
	devinput_init,		/* init_func */
	NULL,			/* config_func */
	devinput_deinit,	/* deinit_func */
	NULL,			/* send_func */
	devinput_rec,		/* rec_func */
	devinput_decode,	/* decode_func */
	NULL,                   /* ioctl_func */
	NULL,			/* readdata */
	"dev/input"
};

static ir_code code;
static int repeat_flag=0;

#if 0
/* using fnmatch */
static int do_match (const char *text, const char *wild)
{
	while (*wild)
	{
		if (*wild == '*')
		{
			const char *next = text;
			wild++;
			while(*next)
			{
				if(do_match (next, wild))
				{
					return 1;
				}
				next++;
			}
			return *wild ? 0:1;
		}
		else if (*wild == '?')
		{
			wild++;
			if (!*text++) return 0;
		}
		else if (*wild == '\\')
		{
			if (!wild[1])
			{
				return 0;
			}
			if (wild[1] != *text++)
			{
				return 0;
			}
			wild += 2;
		}
		else if (*wild++ != *text++)
		{
			return 0;
		}
	}
	return *text ? 0:1;
}
#endif

static int locate_dev (const char *pattern, enum locate_type type)
{
	static char devname[FILENAME_MAX];
	char ioname[255];
	DIR *dir;
	struct dirent *obj;
	int request;

	dir = opendir ("/dev/input");
	if (!dir)
	{
		return 1;
	}

	devname[0] = 0;
	switch (type)
	{
		case locate_by_name:
			request = EVIOCGNAME (sizeof (ioname));
			break;
#ifdef EVIOCGPHYS			
		case locate_by_phys:
			request = EVIOCGPHYS (sizeof (ioname));
			break;
#endif
		default:
			closedir (dir);
			return 1;
	}

	while ((obj = readdir (dir)))
	{
		int fd;
		if (obj->d_name[0] == '.' &&
		    (obj->d_name[1] == 0 ||
		     (obj->d_name[1] == '.' && obj->d_name[2] == 0)))
		{
			continue; /* skip "." and ".." */
		}
		sprintf (devname, "/dev/input/%s", obj->d_name);
		fd = open (devname, O_RDONLY);
		if (!fd)
		{
			continue;
		}
		if (ioctl (fd, request, ioname) >= 0)
		{
			int ret;
			close (fd);
			
			ioname[sizeof(ioname)-1] = 0;
			//ret = !do_match (ioname, pattern);
			ret = fnmatch(pattern, ioname, 0);
			if (ret == 0)
			{
				hw.device = devname;
				closedir (dir);
				return 0;
			}
		}
		close (fd);
	}

	closedir (dir);
	return 1;
}

int devinput_init()
{
	logprintf(LOG_INFO, "initializing '%s'", hw.device);

	if (!strncmp (hw.device, "name=", 5)) {
		if (locate_dev (hw.device + 5, locate_by_name)) {
			logprintf(LOG_ERR, "unable to find '%s'", hw.device);
			return 0;
		}
	}
	else if (!strncmp (hw.device, "phys=", 5)) {
		if (locate_dev (hw.device + 5, locate_by_phys)) {
			logprintf(LOG_ERR, "unable to find '%s'", hw.device);
			return 0;
		}
	}
	
	if ((hw.fd = open(hw.device, O_RDONLY)) < 0) {
		logprintf(LOG_ERR, "unable to open '%s'", hw.device);
		return 0;
	}
	
#ifdef EVIOCGRAB
	if (ioctl(hw.fd, EVIOCGRAB, 1) == -1)
	{
		logprintf(LOG_WARNING, "can't get exclusive access to events "
			  "comming from `%s' interface",
			  hw.device);
	}
#endif
			
	return 1;
}


int devinput_deinit(void)
{
	logprintf(LOG_INFO, "closing '%s'", hw.device);
	close(hw.fd);
	hw.fd=-1;
	return 1;
}


int devinput_decode(struct ir_remote *remote,
		    ir_code *prep, ir_code *codep, ir_code *postp,
		    int *repeat_flagp, lirc_t *remaining_gapp)
{
	LOGPRINTF(1, "devinput_decode");

        if(!map_code(remote,prep,codep,postp,
                     0,0,hw_devinput.code_length,code,0,0))
        {
                return(0);
        }
	
	*repeat_flagp = repeat_flag;
	*remaining_gapp = 0;
	
	return 1;
}


char *devinput_rec(struct ir_remote *remotes)
{
	struct input_event event;
	int rd;


	LOGPRINTF(1, "devinput_rec");
	
	rd = read(hw.fd, &event, sizeof event);
	if (rd != sizeof event) {
		logprintf(LOG_ERR, "error reading '%s'", hw.device);
		if(rd <= 0 && errno != EINTR) raise(SIGTERM);
		return 0;
	}

	LOGPRINTF(1, "time %ld.%06ld  type %d  code %d  value %d",
		  event.time.tv_sec, event.time.tv_usec,
		  event.type, event.code, event.value);
	
	code = event.value ? 0x80000000 : 0;
	code |= ((event.type & 0x7fff) << 16);
	code |= event.code;

	repeat_flag = (event.value == 2) ? 1:0;

	LOGPRINTF(1, "code %.8llx", code);

	/* ignore EV_SYN */
	if(event.type == EV_SYN) return NULL;

	return decode_all(remotes);
}
