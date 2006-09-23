/*
 * File:         arch/blackfin/mach-common/bf5xx_rtc.c
 * Based on:
 * Author:       unknown
 *
 * Created:      ?
 * Description:  real time clock support
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2004-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
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
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <asm/blackfin.h>
#include <asm/bf5xx_rtc.h>

#define MIN_TO_SECS(_x_) (60 * _x_)
#define HRS_TO_SECS(_x_) (60 * 60 * _x_)
#define DAYS_TO_SECS(_x_) (24 * 60 * 60 * _x_)

#define NUM_SECS_IN_DAY (24 * 3600)
#define NUM_SECS_IN_HOUR (3600)
#define NUM_SECS_IN_MIN (60)

/* Shift values for RTC_STAT register */
#define DAY_BITS_OFF    17
#define HOUR_BITS_OFF   12
#define MIN_BITS_OFF    6
#define SEC_BITS_OFF    0

static void wait_for_complete(void);

/* Initialize the RTC. Enable pre-scaler to scale RTC clock to 1Hz. */
int rtc_init(void)
{
	bfin_write_RTC_PREN(0x1);
	wait_for_complete();
	return 0;
}

/* Set the time. time_in_secs is the number of seconds since Jan 1970 */
int rtc_set(time_t time_in_secs)
{
	unsigned long n_days_1970 = 0;
	unsigned long n_secs_rem = 0;
	unsigned long n_hrs = 0;
	unsigned long n_mins = 0;
	unsigned long n_secs = 0;

	/* Compute no. of days since 1970 */
	n_days_1970 = (unsigned long)(time_in_secs / (NUM_SECS_IN_DAY));

	/* From the remining secs, compute the hrs(0-23), mins(0-59)
	 * and secs(0-59)
	 */
	n_secs_rem = (unsigned long)(time_in_secs % (NUM_SECS_IN_DAY));
	n_hrs = n_secs_rem / (NUM_SECS_IN_HOUR);
	n_secs_rem = n_secs_rem % (NUM_SECS_IN_HOUR);
	n_mins = n_secs_rem / (NUM_SECS_IN_MIN);
	n_secs = n_secs_rem % (NUM_SECS_IN_MIN);

	/* Store the new time in the RTC_STAT register */
	bfin_write_RTC_STAT(
	    ((n_days_1970 << DAY_BITS_OFF) | (n_hrs << HOUR_BITS_OFF) |
	     (n_mins << MIN_BITS_OFF) | (n_secs << SEC_BITS_OFF)));

	wait_for_complete();
	return 0;
}

/* Read the time from the RTC_STAT.
 * time_in_seconds is seconds since Jan 1970
 */
int rtc_get(time_t * time_in_seconds)
{
	unsigned long cur_rtc_stat = 0;
	int tm_sec = 0, tm_min = 0, tm_hour = 0, tm_day = 0;

	if (time_in_seconds == NULL) {
		return -1;
	}

	/* Read the RTC_STAT register */
	cur_rtc_stat = bfin_read_RTC_STAT();

	/* Get the secs (0-59), mins (0-59), hrs (0-23) and the days
	 * since Jan 1970
	 */
	tm_sec = (cur_rtc_stat >> SEC_BITS_OFF) & 0x3f;
	tm_min = (cur_rtc_stat >> MIN_BITS_OFF) & 0x3f;
	tm_hour = (cur_rtc_stat >> HOUR_BITS_OFF) & 0x1f;
	tm_day = (cur_rtc_stat >> DAY_BITS_OFF) & 0x7fff;

	/* Calculate the total number of seconds since Jan 1970 */
	*(time_in_seconds) = (tm_sec) +
	    MIN_TO_SECS(tm_min) + HRS_TO_SECS(tm_hour) + DAYS_TO_SECS(tm_day);

	/* a time_t greater than "7FFF FFFF" would be treated as negative
	 * manywhere,so we just reset it.
	 * This will happen in following situations:
	 *   1. No battery for RTC. The random time value will be reset to 0.
	 *   2. On a system with battery, user sets time value to be greater
	 *   than 7FFF FFFF.
	 *   3. Many many years passed after user sets it!
	 */
	if ((unsigned long)(*(time_in_seconds)) >= 0x7FFFFFFF) {
		bfin_write_RTC_STAT(0);
		*(time_in_seconds) = 0;
		wait_for_complete();
	}

	return 0;
}

/* Wait for the previous write to a RTC register to complete */
static void wait_for_complete(void)
{
	while (!(bfin_read_RTC_ISTAT() & 0x8000)) {
		/*printk(""); */
	}
	bfin_write_RTC_ISTAT(0x8000);
}
