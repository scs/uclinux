/*      $Id: release.c,v 1.1 2007/05/06 11:54:02 lirc Exp $      */

/****************************************************************************
 ** release.c ***************************************************************
 ****************************************************************************
 *
 * release.c - automatic release event generation
 * 
 * Copyright (C) 2007 Christoph Bartelmus (lirc@bartelmus.de)
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>

#include "release.h"
#include "lircd.h"

static struct timeval release_time;
static struct ir_remote *release_remote;
static struct ir_ncode *release_ncode;
static ir_code release_code;
static lirc_t release_gap;

static struct ir_remote *release_remote2;
static struct ir_ncode *release_ncode2;
static ir_code release_code2;
static const char *release_suffix = NULL;
static char message[PACKET_SIZE+1];

void register_input(void)
{
	struct timeval gap;
	
	if(release_suffix == NULL) return;
	
	if(release_remote == NULL) return;
	
	timerclear(&gap);
	gap.tv_usec = 2*release_gap;
	
	gettimeofday(&release_time,NULL);
	timeradd(&release_time, &gap, &release_time);
}

void register_button_press(struct ir_remote *remote, struct ir_ncode *ncode,
			   ir_code code, int reps)
{
	if(release_suffix == NULL) return;
	
	if(reps == 0 && release_remote != NULL)
	{
		release_remote2 = release_remote;
		release_ncode2 = release_ncode;
		release_code2 = release_code;
	}
	
	release_remote = remote;
	release_ncode = ncode;
	release_code = code;
	release_gap = remote->remaining_gap;
	
	register_input();
}

void set_release_suffix(const char *s)
{
	release_suffix = s;
}

void get_release_time(struct timeval *tv)
{
	*tv = release_time;
}

const char *check_release_event(void)
{
	int len = 0;
	
	if(release_remote2 != NULL)
	{
		len = write_message(message, PACKET_SIZE+1,
				    release_remote2->name,
				    release_ncode2->name, release_suffix,
				    release_code2, 0);
		release_remote2 = NULL;
		release_ncode2 = NULL;
		release_code2 = 0;
		
		if(len>=PACKET_SIZE+1)
		{
			logprintf(LOG_ERR,"message buffer overflow");
			return(NULL);
		}

		logprintf(LOG_INFO, "check");
		return message;
	}
	return NULL;
}

const char *trigger_release_event(void)
{
	int len = 0;
	
	if(release_remote != NULL)
	{
		len = write_message(message, PACKET_SIZE+1,
				    release_remote->name, release_ncode->name,
				    release_suffix, release_code, 0);
		timerclear(&release_time);
		release_remote = NULL;
		release_ncode = NULL;
		release_code = 0;
		
		if(len>=PACKET_SIZE+1)
		{
			logprintf(LOG_ERR,"message buffer overflow");
			return(NULL);
		}
		logprintf(LOG_INFO, "trigger");
		return message;
	}
	return NULL;
}

const char *release_map_remotes(struct ir_remote *old, struct ir_remote *new)
{
	struct ir_remote *remote;
	struct ir_ncode *ncode;
	
	if(release_remote2 != NULL)
	{
		/* should not happen */
		logprintf(LOG_ERR, "release_remote2 still in use");
		release_remote2 = NULL;
	}
	if(release_remote && is_in_remotes(old, release_remote))
	{
		if((remote = get_ir_remote(new, release_remote->name)) &&
		   (ncode = get_ir_code(remote, release_ncode->name)))
		{
			release_remote = remote;
			release_ncode = ncode;
		}
		else
		{
			return trigger_release_event();
		}
	}
	return NULL;
}
