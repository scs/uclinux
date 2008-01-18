/*****************************************************************************/

/*
 *	flatfs.c -- simple flat FLASH file-system.
 *
 *	Copyright (C) 1999, Greg Ungerer (gerg@snapgear.com).
 *	Copyright (C) 2001-2002, SnapGear (www.snapgear.com)
 */

/*****************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <syslog.h>

#include <config/autoconf.h>
#include "flatfs.h"
#include "dev.h"
#include "ops.h"
#include "flatfs1.h"
#include "flatfs3.h"

/*****************************************************************************/

/*
 * Return the version number of flatfs we have. Return 1 or 2, otherwise
 * an error code that is less than zero.
 */

int flat_version(void)
{
	unsigned int magic;

	magic = flat1_gethdr();
	if (magic == FLATFS_MAGIC)
		return 1;
	else if (magic == FLATFS_MAGIC_V2)
		return 2;

#ifdef CONFIG_USER_FLATFSD_COMPRESSED
	magic = flat3_gethdr();
	if (magic == FLATFS_MAGIC_V3)
		return 3;
#endif

	syslog(LOG_ERR, "invalid header magic version");
	return ERROR_CODE();
}

/*****************************************************************************/

/*
 * Check the consistency of the flatfs in flash.
 */

int flat_check(void)
{
	int rc;

	if (chdir(DSTDIR) < 0)
		return ERROR_CODE();

	if ((rc = flat_open(FILEFS, "r")) < 0)
		return rc;

	switch (rc = flat_version()) {
	case 1:
	case 2:
		rc = flat1_checkfs();
		break;
#ifdef CONFIG_USER_FLATFSD_COMPRESSED
	case 3:
		rc = flat3_checkfs();
		break;
#endif
	default:
		/* Unknown revision? */
		break;
	}

	flat_close(0, 0);
	return rc;
}

/*****************************************************************************/

/*
 * Read the contents of a flat file-system and dump them out as regular files.
 * At this level we just figure out what version flatfs it is and call off
 * the the right place to handle it.
 */

int flat_restorefs(void)
{
	int rc;

	if (chdir(DSTDIR) < 0) {
		return ERROR_CODE();
	}

	if ((rc = flat_open(FILEFS, "r")) < 0) {
		return ERROR_CODE();
	}

	switch (numversion = flat_version()) {
	case 1:
	case 2:
		rc = flat1_restorefs(numversion, 1);
		break;
#ifdef CONFIG_USER_FLATFSD_COMPRESSED
	case 3:
		rc = flat3_restorefs(numversion, 1);
		break;
#endif
	default:
		/* Unknown revision? */
		break;
	}

	flat_close(0, 0);
	return rc;
}

/*****************************************************************************/

/*
 *	Write out the contents of the local directory to flat file-system.
 *	The writing process is not quite as easy as read. Use the usual
 *	write system call so that FLASH programming is done properly.
 */

int flat_savefs(int version)
{
	unsigned int total;
	time_t start_time, flt_write_time;
	int log_level, rc = 0;

	flat_sum = 0;
	start_time = time(NULL);

	if (chdir(SRCDIR) < 0)
		return ERROR_CODE();

#ifndef HAS_RTC
	{
		/* Create a special config file to store the current time. */
		FILE *hfile;

		if ((hfile = fopen(FLATFSD_CONFIG, "w")) == NULL)
			return ERROR_CODE();
		fprintf(hfile, "time %ld\n", time(NULL));
		/* Ignore errors! */
		fflush(hfile);
		fclose(hfile);
	}
#endif

	rc = flat_open(FILEFS, "w");
	if (rc < 0)
		goto cleanup;

#if 1
	/* Check to see if the config will fit before we erase */
	switch (version) {
#ifdef CONFIG_USER_FLATFSD_COMPRESSED
	case 3:
		rc = flat3_savefs(0, &total);
		break;
#endif
	case 1:
	case 2:
	default:
		rc = flat1_savefs(0, &total);
		break;
	}
	if ((rc < 0) || (total > flat_length())) { 
		syslog(LOG_ERR, "config will not fit in flash");
		goto cleanup;
	}
#endif

	switch (version) {
#ifdef CONFIG_USER_FLATFSD_COMPRESSED
	case 3:
		rc = flat3_savefs(1, &total);
		break;
#endif
	case 1:
	case 2:
	default:
		rc = flat1_savefs(1, &total);
		break;
	}
	if (rc < 0)
		goto cleanup;

	unlink(FLATFSD_CONFIG);
	rc = flat_close(0, total);

	flt_write_time = time(NULL) - start_time;

	log_level = LOG_ALERT;
	if (flt_write_time <= 20)
		log_level = LOG_DEBUG;
	else if ((flt_write_time > 20) && (flt_write_time <= 40))
		log_level = LOG_NOTICE;
	else if ((flt_write_time > 40) && (flt_write_time <= 100))
		log_level = LOG_ERR;
	else
		log_level = LOG_ALERT;
	syslog(log_level, "Wrote %d bytes to flash in %ld seconds",
		total, flt_write_time);

	return rc;

cleanup:
	unlink(FLATFSD_CONFIG);
	flat_close(1, 0);
	return rc;
}

/*****************************************************************************/
